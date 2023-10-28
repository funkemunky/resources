use anyhow::{anyhow, bail, Context, Result};
use async_std::{stream::StreamExt, sync::Arc};
use nparse::KVStrToJson;
use nvml_wrapper::{enums::device::UsedGpuMemory, error::NvmlError, Device, Nvml};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    time::SystemTime,
};

static PAGESIZE: Lazy<usize> = Lazy::new(sysconf::pagesize);

static UID_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"Uid:\s*(\d+)").unwrap());

static NVML: Lazy<Result<Nvml, NvmlError>> = Lazy::new(Nvml::init);

static NVML_DEVICES: Lazy<Vec<Device>> = Lazy::new(|| {
    if let Ok(nvml) = NVML.as_ref() {
        let device_count = nvml.device_count().unwrap_or(0);
        let mut return_vec = Vec::new();
        for i in 0..device_count {
            if let Ok(device) = nvml.device_by_index(i) {
                return_vec.push(device);
            }
        }
        return_vec
    } else {
        Vec::new()
    }
});

#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, Serialize, Deserialize, Copy)]
pub enum Containerization {
    #[default]
    None,
    Flatpak,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize, Copy)]
pub struct GpuUsageStats {
    pub gfx: u64,
    pub gfx_timestamp: u64,
    pub mem: u64,
    pub enc: u64,
    pub enc_timestamp: u64,
    pub dec: u64,
    pub dec_timestamp: u64,
    pub nvidia: bool,
}

/// Data that could be transferred using `resources-processes`, separated from
/// `Process` mainly due to `Icon` not being able to derive `Serialize` and
/// `Deserialize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct ProcessData {
    pub pid: i32,
    pub uid: u32,
    proc_path: PathBuf,
    pub comm: String,
    pub commandline: String,
    pub cpu_time: u64,
    pub cpu_time_timestamp: u64,
    pub memory_usage: usize,
    pub cgroup: Option<String>,
    pub containerization: Containerization,
    pub read_bytes: Option<u64>,
    pub read_bytes_timestamp: Option<u64>,
    pub write_bytes: Option<u64>,
    pub write_bytes_timestamp: Option<u64>,
    pub gpu_usage_stats: BTreeMap<String, GpuUsageStats>,
}

impl ProcessData {
    fn sanitize_cgroup<S: AsRef<str>>(cgroup: S) -> Option<String> {
        let cgroups_v2_line = cgroup.as_ref().split('\n').find(|s| s.starts_with("0::"))?;
        if cgroups_v2_line.ends_with(".scope") {
            let cgroups_segments: Vec<&str> = cgroups_v2_line.split('-').collect();
            if cgroups_segments.len() > 1 {
                cgroups_segments
                    .get(cgroups_segments.len() - 2)
                    .map(|s| unescape::unescape(s).unwrap_or_else(|| (*s).to_string()))
            } else {
                None
            }
        } else if cgroups_v2_line.ends_with(".service") {
            let cgroups_segments: Vec<&str> = cgroups_v2_line.split('/').collect();
            if let Some(last) = cgroups_segments.last() {
                last[0..last.len() - 8]
                    .split('@')
                    .next()
                    .map(|s| unescape::unescape(s).unwrap_or_else(|| s.to_string()))
                    .map(|s| {
                        if s.contains("dbus-:") {
                            s.split('-').last().unwrap_or(&s).to_string()
                        } else {
                            s
                        }
                    })
            } else {
                None
            }
        } else {
            None
        }
    }

    async fn get_uid(proc_path: &PathBuf) -> Result<u32> {
        let status = async_std::fs::read_to_string(proc_path.join("status")).await?;
        if let Some(captures) = UID_REGEX.captures(&status) {
            let first_num_str = captures.get(1).context("no uid found")?;
            first_num_str
                .as_str()
                .parse::<u32>()
                .context("couldn't parse uid in /status")
        } else {
            Ok(0)
        }
    }

    pub async fn try_from_path(proc_path: PathBuf) -> Result<Self> {
        // Stat
        let shared_proc_path = Arc::new(proc_path.clone());
        let stat = async_std::task::spawn(async move {
            async_std::fs::read_to_string(shared_proc_path.join("stat")).await
        });

        // Statm
        let shared_proc_path = Arc::new(proc_path.clone());
        let statm = async_std::task::spawn(async move {
            async_std::fs::read_to_string(shared_proc_path.join("statm")).await
        });

        // Comm
        let shared_proc_path = Arc::new(proc_path.clone());
        let comm = async_std::task::spawn(async move {
            async_std::fs::read_to_string(shared_proc_path.join("comm")).await
        });

        // Cmdline
        let shared_proc_path = Arc::new(proc_path.clone());
        let commandline = async_std::task::spawn(async move {
            async_std::fs::read_to_string(shared_proc_path.join("cmdline")).await
        });

        // Cgroup
        let shared_proc_path = Arc::new(proc_path.clone());
        let cgroup = async_std::task::spawn(async move {
            async_std::fs::read_to_string(shared_proc_path.join("cgroup")).await
        });

        // IO
        let shared_proc_path = Arc::new(proc_path.clone());
        let io = async_std::task::spawn(async move {
            async_std::fs::read_to_string(shared_proc_path.join("io")).await
        });

        let stat = stat.await?;
        let statm = statm.await?;
        let comm = comm.await?;
        let commandline = commandline.await?;
        let cgroup = cgroup.await?;

        let pid = proc_path
            .file_name()
            .ok_or_else(|| anyhow!(""))?
            .to_str()
            .ok_or_else(|| anyhow!(""))?
            .parse()?;

        let uid = Self::get_uid(&proc_path).await?;

        let stat = stat
            .split(' ')
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();

        let statm = statm
            .split(' ')
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();

        let comm = comm.replace('\n', "");

        let cpu_time = stat[13].parse::<u64>()? + stat[14].parse::<u64>()?;

        let cpu_time_timestamp = Self::unix_as_millis();

        let memory_usage = (statm[1].parse::<usize>()? - statm[2].parse::<usize>()?) * *PAGESIZE;

        let cgroup = Self::sanitize_cgroup(cgroup);

        let containerization = match &proc_path.join("root").join(".flatpak-info").exists() {
            true => Containerization::Flatpak,
            false => Containerization::None,
        };

        let (mut read_bytes, mut read_bytes_timestamp, mut write_bytes, mut write_bytes_timestamp) =
            (None, None, None, None);

        if let Ok(io) = io.await {
            let io = io.kv_str_to_json().ok();

            read_bytes = io.as_ref().and_then(|kv| {
                kv.as_object().and_then(|obj| {
                    obj.get("read_bytes")
                        .and_then(|val| val.as_str().and_then(|s| s.parse().ok()))
                })
            });

            read_bytes_timestamp = if read_bytes.is_some() {
                Some(Self::unix_as_millis())
            } else {
                None
            };

            write_bytes = io.and_then(|kv| {
                kv.as_object().and_then(|obj| {
                    obj.get("write_bytes")
                        .and_then(|val| val.as_str().and_then(|s| s.parse().ok()))
                })
            });

            write_bytes_timestamp = if write_bytes.is_some() {
                Some(Self::unix_as_millis())
            } else {
                None
            };
        }

        let gpu_usage_stats = Self::gpu_usage_stats(&proc_path, pid).await;

        Ok(Self {
            pid,
            uid,
            comm,
            commandline,
            cpu_time,
            cpu_time_timestamp,
            memory_usage,
            cgroup,
            proc_path,
            containerization,
            read_bytes,
            read_bytes_timestamp,
            write_bytes,
            write_bytes_timestamp,
            gpu_usage_stats,
        })
    }

    fn unix_as_millis() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    async fn gpu_usage_stats(proc_path: &PathBuf, pid: i32) -> BTreeMap<String, GpuUsageStats> {
        let nvidia_stats = Self::nvidia_gpu_usage_stats(pid).unwrap_or_default();
        let mut other_stats = Self::other_gpu_usage_stats(proc_path)
            .await
            .unwrap_or_default();
        other_stats.extend(nvidia_stats.into_iter());
        other_stats
    }

    async fn other_gpu_usage_stats(proc_path: &PathBuf) -> Result<BTreeMap<String, GpuUsageStats>> {
        let fdinfo_path = proc_path.join("fdinfo");
        let mut dir = async_std::fs::read_dir(fdinfo_path).await?;

        let mut client_ids = HashSet::new();
        let mut return_map = BTreeMap::new();

        while let Some(entry) = dir.next().await {
            if let Ok(entry) = entry {
                let file_path = entry.path();

                if file_path.is_file().await {
                    let stats = Self::read_fdinfo(&file_path).await;
                    if let Ok(stats) = stats {
                        if client_ids.contains(&stats.2) {
                            continue;
                        }
                        client_ids.insert(stats.2);
                        return_map.insert(stats.0, stats.1);
                    }
                }
            }
        }

        Ok(return_map)
    }

    async fn read_fdinfo(
        fdinfo_path: &async_std::path::PathBuf,
    ) -> Result<(String, GpuUsageStats, i64)> {
        let kv = async_std::fs::read_to_string(fdinfo_path)
            .await?
            .kv_str_to_json()
            .map_err(|_| anyhow!("couldn't parse to kv"))?;
        let object = kv.as_object().context("couldn't get kv as object")?;

        if let (Some(pci_slot), Some(client_id)) = (
            object.get("drm-pdev").and_then(|obj| obj.as_str()),
            object.get("drm-client-id").and_then(|obj| obj.as_i64()),
        ) {
            let gfx = object
                .get("drm-engine-gfx")
                .and_then(|gfx| gfx.as_str())
                .and_then(|gfx| gfx[0..(gfx.len() - 3)].parse::<u64>().ok())
                .unwrap_or(0);
            let enc = object
                .get("drm-engine-enc")
                .and_then(|gfx| gfx.as_str())
                .and_then(|gfx| gfx[0..(gfx.len() - 3)].parse::<u64>().ok())
                .unwrap_or(0);
            let dec = object
                .get("drm-engine-dec")
                .and_then(|gfx| gfx.as_str())
                .and_then(|gfx| gfx[0..(gfx.len() - 3)].parse::<u64>().ok())
                .unwrap_or(0);
            let vram = object
                .get("drm-engine-vram")
                .and_then(|gfx| gfx.as_str())
                .and_then(|gfx| gfx[0..(gfx.len() - 4)].parse::<u64>().ok())
                .map(|bytes| bytes * 1024)
                .unwrap_or(0);
            let gtt = object
                .get("drm-engine-gtt")
                .and_then(|gfx| gfx.as_str())
                .and_then(|gfx| gfx[0..(gfx.len() - 4)].parse::<u64>().ok())
                .map(|bytes| bytes * 1024)
                .unwrap_or(0);
            let stats = GpuUsageStats {
                gfx,
                gfx_timestamp: Self::unix_as_millis(),
                mem: vram.saturating_add(gtt),
                enc,
                enc_timestamp: Self::unix_as_millis(),
                dec,
                dec_timestamp: Self::unix_as_millis(),
                nvidia: false,
            };
            return Ok((pci_slot.to_string(), stats, client_id));
        }

        bail!("unable to find gpu information in this fdinfo");
    }

    fn nvidia_gpu_usage_stats(pid: i32) -> Result<BTreeMap<String, GpuUsageStats>> {
        let mut return_map = BTreeMap::new();

        for gpu in NVML_DEVICES.iter() {
            if let Ok(stats) = Self::read_nvidia_gpu_stats(pid, gpu) {
                return_map.insert(stats.0, stats.1);
            }
        }

        Ok(return_map)
    }

    fn read_nvidia_gpu_stats(pid: i32, gpu: &Device) -> Result<(String, GpuUsageStats)> {
        let pci_slot = gpu
            .pci_info()
            .map(|pci_info| pci_info.bus_id)?
            .to_lowercase();

        let usage_stats = gpu.process_utilization_stats(None)?;
        let mut comp_gfx_stats = gpu.running_graphics_processes()?;
        comp_gfx_stats.extend(gpu.running_compute_processes()?);

        let this_process_stats = usage_stats.iter().find(|process| process.pid == pid as u32);
        let this_process_mem_stats = comp_gfx_stats
            .iter()
            .find(|process| process.pid == pid as u32)
            .map(|stats| match stats.used_gpu_memory {
                UsedGpuMemory::Unavailable => 0,
                UsedGpuMemory::Used(bytes) => bytes,
            });

        if let Some(process_stats) = this_process_stats {
            let gpu_stats = GpuUsageStats {
                gfx: process_stats.sm_util as u64,
                gfx_timestamp: Self::unix_as_millis(),
                mem: this_process_mem_stats.unwrap_or(0),
                enc: process_stats.enc_util as u64,
                enc_timestamp: Self::unix_as_millis(),
                dec: process_stats.dec_util as u64,
                dec_timestamp: Self::unix_as_millis(),
                nvidia: true,
            };
            Ok((pci_slot[4..pci_slot.len()].to_owned(), gpu_stats))
        } else {
            bail!("no stats found")
        }
    }
}
