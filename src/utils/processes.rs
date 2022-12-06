use anyhow::{anyhow, bail, Context, Result};
use config::LIBEXECDIR;
use glob::glob;
use log::debug;
use nix::{sys::signal, unistd::Pid};
use once_cell::sync::OnceCell;
use std::{collections::HashMap, path::PathBuf, process::Command, time::SystemTime};

use gtk::{
    gio::{AppInfo, Icon, ThemedIcon},
    prelude::AppInfoExt,
};

use crate::config;

static PAGESIZE: OnceCell<usize> = OnceCell::new();

#[derive(Debug, Clone, Default, Hash, PartialEq, Eq)]
pub enum Containerization {
    #[default]
    None,
    Flatpak,
}

/// Represents a process that can be found within procfs.
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq)]
pub struct Process {
    pid: usize,
    uid: usize,
    proc_path: PathBuf,
    commandline: String,
    cpu_time: u64,
    cpu_time_timestamp: u64,
    cpu_time_before: u64,
    cpu_time_before_timestamp: u64,
    mem_usage: usize,
    cgroup: Option<String>,
    alive: bool,
    containerization: Containerization,
}

/// Represents an application installed on the system. It doesn't
/// have to be running (i.e. have alive processes).
#[derive(Debug, Clone)]
pub struct App {
    processes: HashMap<usize, Process>,
    app_info: AppInfo,
}

/// Convenience struct for displaying running applications and
/// displaying a "System Processes" item.
#[derive(Debug, Clone)]
pub struct SimpleItem {
    pub id: Option<String>,
    pub display_name: String,
    pub icon: Icon,
    pub description: Option<String>,
    pub executable: Option<PathBuf>,
    pub memory_usage: usize,
    pub cpu_time_ratio: Option<f32>,
    pub processes_amount: usize,
    pub containerization: Containerization,
}

#[derive(Debug, Clone, Default)]
pub struct Apps {
    apps: HashMap<String, App>,
    system_processes: Vec<Process>,
    known_proc_paths: Vec<PathBuf>,
}

// TODO: use Into<PathBuf> instead of PathBuf
impl TryFrom<PathBuf> for Process {
    fn try_from(value: PathBuf) -> Result<Self> {
        let stat: Vec<String> = std::fs::read_to_string(value.join("stat"))?
            .split(' ')
            .map(std::string::ToString::to_string)
            .collect();
        let statm: Vec<String> = std::fs::read_to_string(value.join("statm"))?
            .split(' ')
            .map(std::string::ToString::to_string)
            .collect();
        let containerization = match &value.join("root").join(".flatpak-info").exists() {
            true => Containerization::Flatpak,
            false => Containerization::None,
        };
        Ok(Process {
            pid: value
                .file_name()
                .ok_or_else(|| anyhow!(""))?
                .to_str()
                .ok_or_else(|| anyhow!(""))?
                .parse()?,
            uid: std::fs::read_to_string(value.join("loginuid"))?.parse()?,
            commandline: std::fs::read_to_string(value.join("cmdline"))?,
            cpu_time: stat[13].parse::<u64>()? + stat[14].parse::<u64>()?,
            cpu_time_timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_millis() as u64,
            cpu_time_before: 0,
            cpu_time_before_timestamp: 0,
            mem_usage: (statm[1].parse::<usize>()? - statm[2].parse::<usize>()?)
                * PAGESIZE.get_or_init(sysconf::pagesize),
            cgroup: Self::sanitize_cgroup(std::fs::read_to_string(value.join("cgroup"))?),
            proc_path: value,
            alive: true,
            containerization,
        })
    }

    type Error = anyhow::Error;
}

impl Process {
    /// Returns a `Vec` containing all currently running processes.
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are problems traversing and
    /// parsing procfs
    pub fn all() -> Result<Vec<Self>> {
        let mut return_vec = Vec::new();
        for entry in glob("/proc/[0-9]*/").context("unable to glob")?.flatten() {
            return_vec.push(Self::try_from(entry));
        }
        Ok(return_vec.into_iter().flatten().collect())
    }

    fn refresh_result(&mut self) -> Result<()> {
        let stat: Vec<String> = std::fs::read_to_string(self.proc_path.join("stat"))?
            .split(' ')
            .map(std::string::ToString::to_string)
            .collect();
        let statm: Vec<String> = std::fs::read_to_string(self.proc_path.join("statm"))?
            .split(' ')
            .map(std::string::ToString::to_string)
            .collect();
        self.cpu_time_before = self.cpu_time;
        self.cpu_time_before_timestamp = self.cpu_time_timestamp;
        self.cpu_time = stat[13].parse::<u64>()? + stat[14].parse::<u64>()?;
        self.cpu_time_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_millis() as u64;
        self.mem_usage = (statm[1].parse::<usize>()? - statm[2].parse::<usize>()?)
            * PAGESIZE.get_or_init(sysconf::pagesize);
        Ok(())
    }

    pub fn refresh(&mut self) -> bool {
        self.alive = self.proc_path.exists() && self.refresh_result().is_ok();
        self.alive
    }

    fn sanitize_cgroup<S: AsRef<str>>(cgroup: S) -> Option<String> {
        let cgroups_v2_line = cgroup
            .as_ref()
            .split('\n')
            .filter(|s| s.starts_with("0::"))
            .next()?;
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

    /// Terminates the processes
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are problems terminating the process
    /// that running it with superuser permissions can't solve
    pub fn term(&self) -> Result<()> {
        debug!("sending SIGTERM to pid {}", self.pid);
        let result = signal::kill(
            Pid::from_raw(self.pid as i32),
            Some(signal::Signal::SIGTERM),
        );
        if let Err(err) = result {
            return match err {
                nix::errno::Errno::EPERM => self.pkexec_term(),
                _ => bail!("unable to term {}", self.pid),
            };
        }
        Ok(())
    }

    fn pkexec_term(&self) -> Result<()> {
        debug!(
            "using pkexec to send SIGTERM with root privileges to pid {}",
            self.pid
        );
        let path = format!("{}/resources-kill", LIBEXECDIR);
        Command::new("pkexec")
            .args([
                "--disable-internal-agent",
                &path,
                "TERM",
                self.pid.to_string().as_str(),
            ])
            .spawn()
            .map(|_| ())
            .with_context(|| format!("failure calling {} on {} (with pkexec)", &path, self.pid))
    }

    /// Kills the process
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are problems killing the process
    /// that running it with superuser permissions can't solve
    pub fn kill(&self) -> Result<()> {
        debug!("sending SIGKILL to pid {}", self.pid);
        let result = signal::kill(
            Pid::from_raw(self.pid as i32),
            Some(signal::Signal::SIGKILL),
        );
        if let Err(err) = result {
            return match err {
                nix::errno::Errno::EPERM => self.pkexec_kill(),
                _ => bail!("unable to kill {}", self.pid),
            };
        }
        Ok(())
    }

    fn pkexec_kill(&self) -> Result<()> {
        debug!(
            "using pkexec to send SIGKILL with root privileges to pid {}",
            self.pid
        );
        let path = format!("{}/resources-kill", LIBEXECDIR);
        Command::new("pkexec")
            .args([
                "--disable-internal-agent",
                &path,
                "KILL",
                self.pid.to_string().as_str(),
            ])
            .spawn()
            .map(|_| ())
            .with_context(|| format!("failure calling {} on {} (with pkexec)", &path, self.pid))
    }

    /// Stops the process
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are problems stopping the process
    /// that running it with superuser permissions can't solve
    pub fn stop(&self) -> Result<()> {
        debug!("sending SIGSTOP to pid {}", self.pid);
        let result = signal::kill(
            Pid::from_raw(self.pid as i32),
            Some(signal::Signal::SIGSTOP),
        );
        if let Err(err) = result {
            return match err {
                nix::errno::Errno::EPERM => self.pkexec_stop(),
                _ => bail!("unable to stop {}", self.pid),
            };
        }
        Ok(())
    }

    fn pkexec_stop(&self) -> Result<()> {
        debug!(
            "using pkexec to send SIGSTOP with root privileges to pid {}",
            self.pid
        );
        let path = format!("{LIBEXECDIR}/resources-kill");
        Command::new("pkexec")
            .args([
                "--disable-internal-agent",
                &path,
                "STOP",
                self.pid.to_string().as_str(),
            ])
            .spawn()
            .map(|_| ())
            .with_context(|| format!("failure calling {} on {} (with pkexec)", &path, self.pid))
    }

    /// Continues the processes
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are problems continuing the process
    /// that running it with superuser permissions can't solve
    pub fn cont(&self) -> Result<()> {
        debug!("sending SIGCONT to pid {}", self.pid);
        let result = signal::kill(
            Pid::from_raw(self.pid as i32),
            Some(signal::Signal::SIGCONT),
        );
        if let Err(err) = result {
            return match err {
                nix::errno::Errno::EPERM => self.pkexec_cont(),
                _ => bail!("unable to cont {}", self.pid),
            };
        }
        Ok(())
    }

    fn pkexec_cont(&self) -> Result<()> {
        debug!(
            "using pkexec to send SIGCONT with root privileges to pid {}",
            self.pid
        );
        let path = format!("{LIBEXECDIR}/resources-kill");
        Command::new("pkexec")
            .args([
                "--disable-internal-agent",
                &path,
                "CONT",
                self.pid.to_string().as_str(),
            ])
            .spawn()
            .map(|_| ())
            .with_context(|| format!("failure calling {} on {} (with pkexec)", &path, self.pid))
    }
}

impl App {
    #[must_use]
    pub fn commandline(&self) -> Option<PathBuf> {
        self.app_info.commandline()
    }

    #[must_use]
    pub fn description(&self) -> Option<String> {
        self.app_info.description().map(|x| x.to_string())
    }

    #[must_use]
    pub fn display_name(&self) -> String {
        self.app_info.display_name().to_string()
    }

    #[must_use]
    pub fn executable(&self) -> PathBuf {
        self.app_info.executable()
    }

    #[must_use]
    pub fn icon(&self) -> Icon {
        if let Some(id) = self.id() && id == "org.gnome.Shell" {
            return ThemedIcon::new("shell").into();
        }
        self.app_info
            .icon()
            .unwrap_or_else(|| ThemedIcon::new("generic-process").into())
    }

    #[must_use]
    pub fn id(&self) -> Option<String> {
        self.app_info
            .id()
            .map(|id| Apps::sanitize_appid(id.to_string()))
    }

    #[must_use]
    pub fn name(&self) -> String {
        self.app_info.name().to_string()
    }

    pub fn refresh(&mut self) -> Vec<PathBuf> {
        self.processes
            .drain_filter(|_, process| !process.refresh())
            .map(|(_, process)| process.proc_path)
            .collect()
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        !self.processes.is_empty()
    }

    #[must_use]
    pub fn memory_usage(&self) -> usize {
        self.processes
            .values()
            .map(|process| process.mem_usage)
            .sum()
    }

    #[must_use]
    pub fn cpu_time(&self) -> u64 {
        self.processes
            .values()
            .map(|process| process.cpu_time)
            .sum()
    }

    #[must_use]
    pub fn cpu_time_timestamp(&self) -> u64 {
        self.processes
            .values()
            .map(|process| process.cpu_time_timestamp)
            .sum::<u64>()
            .checked_div(self.processes.len() as u64) // the timestamps of the last cpu time check should be pretty much equal but to be sure, take the average of all of them
            .unwrap_or(0)
    }

    #[must_use]
    pub fn cpu_time_before(&self) -> u64 {
        self.processes
            .values()
            .map(|process| process.cpu_time_before)
            .sum()
    }

    #[must_use]
    pub fn cpu_time_before_timestamp(&self) -> u64 {
        self.processes
            .values()
            .map(|process| process.cpu_time_before_timestamp)
            .sum::<u64>()
            .checked_div(self.processes.len() as u64)
            .unwrap_or(0)
    }

    #[must_use]
    pub fn term(&self) -> Vec<Result<()>> {
        debug!("sending SIGTERM to processes of {}", self.display_name());
        self.processes.values().map(Process::term).collect()
    }

    #[must_use]
    pub fn kill(&self) -> Vec<Result<()>> {
        debug!("sending SIGKILL to processes of {}", self.display_name());
        self.processes.values().map(Process::kill).collect()
    }

    #[must_use]
    pub fn stop(&self) -> Vec<Result<()>> {
        debug!("sending SIGSTOP to processes of {}", self.display_name());
        self.processes.values().map(Process::stop).collect()
    }

    #[must_use]
    pub fn cont(&self) -> Vec<Result<()>> {
        debug!("sending SIGCONT to processes of {}", self.display_name());
        self.processes.values().map(Process::cont).collect()
    }
}

impl Apps {
    /// Creates a new `Apps` object, this operation is quite expensive
    /// so try to do it only one time during the lifetime of the program.
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are problems getting the list of
    /// running processes.
    pub fn new() -> Result<Self> {
        let app_infos = gtk::gio::AppInfo::all();
        let mut app_map = HashMap::new();
        let mut processes = Process::all()?;
        let mut known_proc_paths = Vec::new();
        for app_info in app_infos {
            if let Some(id) = app_info
                .id()
                .map(|gstring| Self::sanitize_appid(gstring.to_string()))
            {
                app_map.insert(
                    id.clone(),
                    App {
                        processes: HashMap::new(),
                        app_info,
                    },
                );
            }
        }
        processes
            .iter()
            .for_each(|process| known_proc_paths.push(process.proc_path.clone()));
        // split the processes `Vec` into two `Vec`s:
        // one, where the process' cgroup can be found as an ID
        // of the installed graphical applications (meaning that the
        // process belongs to a graphical application) and one where
        // this is not possible. the latter are our system processes
        let non_system_processes: Vec<Process> = processes
            .drain_filter(|process| {
                process
                    .cgroup
                    .as_deref()
                    .map_or(true, |cgroup| !cgroup.starts_with("xdg-desktop-portal")) // throw out the portals
                    && app_map.contains_key(process.cgroup.as_deref().unwrap_or_default())
            })
            .collect();
        for process in non_system_processes {
            app_map
                .get_mut(process.cgroup.as_deref().unwrap_or_default())
                .and_then(|app| app.processes.insert(process.pid, process));
        }
        Ok(Apps {
            apps: app_map,
            system_processes: processes,
            known_proc_paths,
        })
    }

    fn sanitize_appid<S: Into<String>>(a: S) -> String {
        let mut appid: String = a.into();
        if appid.ends_with(".desktop") {
            appid = appid[0..appid.len() - 8].to_string();
        }
        appid
    }

    pub fn get_app<S: AsRef<str>>(&self, id: S) -> Option<&App> {
        self.apps.get(id.as_ref())
    }

    #[must_use]
    pub fn system_processes(&self) -> &Vec<Process> {
        &self.system_processes
    }

    /// Returns a `Vec` of running graphical applications. For more
    /// info, refer to `SimpleItem`.
    #[must_use]
    pub fn simple(&self) -> Vec<SimpleItem> {
        let mut return_vec = self
            .apps
            .iter()
            .filter(|(_, app)| app.is_running())
            .map(|(_, app)| {
                let containerization = if app
                    .processes
                    .values()
                    .filter(|process| {
                        !process.commandline.starts_with("bwrap") && !process.commandline.is_empty()
                    })
                    .all(|process| process.containerization == Containerization::Flatpak)
                {
                    Containerization::Flatpak
                } else {
                    Containerization::None
                };

                SimpleItem {
                    id: app.id(),
                    display_name: app.display_name(),
                    icon: app.icon(),
                    description: app.description(),
                    executable: Some(app.executable()),
                    memory_usage: app.memory_usage(),
                    cpu_time_ratio: if app.cpu_time_before() == 0 {
                        None
                    } else {
                        Some(
                            ((app.cpu_time() - app.cpu_time_before()) as f32
                                / (app.cpu_time_timestamp() - app.cpu_time_before_timestamp())
                                    as f32)
                                .clamp(0.0, 1.0),
                        )
                    },
                    processes_amount: app.processes.len(),
                    containerization,
                }
            })
            .collect::<Vec<SimpleItem>>();
        let system_cpu_time: u64 = self
            .system_processes
            .iter()
            .map(|process| process.cpu_time)
            .sum();
        let system_cpu_time_timestamp = self
            .system_processes
            .iter()
            .map(|process| process.cpu_time_timestamp)
            .sum::<u64>()
            .checked_div(self.system_processes.len() as u64)
            .unwrap_or(0);
        let system_cpu_time_before: u64 = self
            .system_processes
            .iter()
            .map(|process| process.cpu_time_before)
            .sum();
        let system_cpu_time_before_timestamp = self
            .system_processes
            .iter()
            .map(|process| process.cpu_time_before_timestamp)
            .sum::<u64>()
            .checked_div(self.system_processes.len() as u64)
            .unwrap_or(0);
        let system_cpu_ratio = if system_cpu_time_before == 0 {
            None
        } else {
            Some(
                ((system_cpu_time - system_cpu_time_before) as f32
                    / (system_cpu_time_timestamp - system_cpu_time_before_timestamp) as f32)
                    .clamp(0.0, 1.0),
            )
        };
        return_vec.push(SimpleItem {
            id: None,
            display_name: gettextrs::gettext("System Processes"),
            icon: ThemedIcon::new("system-processes").into(),
            description: None,
            executable: None,
            memory_usage: self
                .system_processes
                .iter()
                .map(|process| process.mem_usage)
                .sum(),
            cpu_time_ratio: system_cpu_ratio,
            processes_amount: self.system_processes.len(),
            containerization: Containerization::None,
        });
        return_vec
    }

    /// Refreshes the statistics about the running applications and processes.
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are problems getting the new list of
    /// running processes or if there are anomalies in a process procfs
    /// directory.
    pub fn refresh(&mut self) -> Result<()> {
        // look for processes that might have died since we last checked
        // and update the stats of the processes that are still alive
        // while we're at it
        let mut dead_processes = Vec::new();
        self.apps
            .values_mut()
            .for_each(|app| dead_processes.extend(app.refresh()));
        dead_processes.extend(
            self.system_processes
                .drain_filter(|process| !process.refresh())
                .map(|process| process.proc_path),
        );
        // now get the processes that might have been added:
        for entry in glob("/proc/[0-9]*/").context("unable to glob")?.flatten() {
            // is the current proc_path already known?
            if self
                .known_proc_paths
                .iter()
                .any(|proc_path| *proc_path == entry)
            {
                // if so, we can continue
                continue;
            }
            // if not, insert it into our known_proc_paths
            let process = Process::try_from(entry.clone())?;
            if let Some(app) = self
                .apps
                .get_mut(process.cgroup.as_deref().unwrap_or_default())
            {
                app.processes.insert(process.pid, process);
            } else {
                self.system_processes.push(process);
            }
            self.known_proc_paths.push(entry);
        }
        // we still have to remove the processes that died from
        // known_proc_paths
        for dead_process in &dead_processes {
            if let Some(pos) = self
                .known_proc_paths
                .iter()
                .position(|x| *x == *dead_process)
            {
                self.known_proc_paths.swap_remove(pos);
            }
        }
        Ok(())
    }
}