use process_data::{Niceness, ProcessData};
use std::path::PathBuf;
use std::time::Duration;

use adw::{prelude::*, subclass::prelude::*, ToolbarView};
use adw::{Toast, ToastOverlay};
use anyhow::{Context, Result};
use gtk::glib::{clone, timeout_future, GString, MainContext};
use gtk::{gio, glib, Widget};
use log::{info, warn};

use crate::application::Application;
use crate::config::PROFILE;
use crate::i18n::{i18n, i18n_f, ni18n_f};
use crate::ui::pages::applications::ResApplications;
use crate::ui::pages::battery::ResBattery;
use crate::ui::pages::drive::ResDrive;
use crate::ui::pages::processes::ResProcesses;
use crate::utils::app::AppsContext;
use crate::utils::battery::{Battery, BatteryData};
use crate::utils::cpu::{self, CpuData};
use crate::utils::drive::{Drive, DriveData};
use crate::utils::gpu::{Gpu, GpuData};
use crate::utils::memory::MemoryData;
use crate::utils::network::{NetworkData, NetworkInterface};
use crate::utils::process::{Process, ProcessAction};
use crate::utils::settings::SETTINGS;

use super::pages::gpu::ResGPU;
use super::pages::network::ResNetwork;
use super::pages::{applications, processes};

#[derive(Debug, Clone)]
pub enum Action {
    ManipulateProcess(ProcessAction, libc::pid_t, String, ToastOverlay),
    ManipulateApp(ProcessAction, String, ToastOverlay),
    AdjustProcess(libc::pid_t, Niceness, Vec<bool>, String, ToastOverlay),
}

mod imp {
    use std::{cell::RefCell, collections::HashMap};

    use crate::{
        ui::{
            pages::{
                applications::ResApplications, cpu::ResCPU, memory::ResMemory,
                processes::ResProcesses,
            },
            widgets::stack_sidebar::ResStackSidebar,
        },
        utils::app::AppsContext,
    };

    use super::*;

    use async_channel::{unbounded, Receiver, Sender};
    use gtk::CompositeTemplate;
    use process_data::pci_slot::PciSlot;

    #[derive(Debug, CompositeTemplate)]
    #[template(resource = "/net/nokyan/Resources/ui/window.ui")]
    pub struct MainWindow {
        #[template_child]
        pub split_view: TemplateChild<adw::OverlaySplitView>,
        #[template_child]
        pub processor_window_title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub resources_sidebar: TemplateChild<ResStackSidebar>,
        #[template_child]
        pub content_stack: TemplateChild<gtk::Stack>,
        #[template_child]
        pub cpu: TemplateChild<ResCPU>,
        #[template_child]
        pub cpu_page: TemplateChild<gtk::StackPage>,
        #[template_child]
        pub applications: TemplateChild<ResApplications>,
        #[template_child]
        pub applications_page: TemplateChild<gtk::StackPage>,
        #[template_child]
        pub processes: TemplateChild<ResProcesses>,
        #[template_child]
        pub processes_page: TemplateChild<gtk::StackPage>,
        #[template_child]
        pub memory: TemplateChild<ResMemory>,
        #[template_child]
        pub memory_page: TemplateChild<gtk::StackPage>,

        pub drive_pages: RefCell<HashMap<PathBuf, adw::ToolbarView>>,

        pub network_pages: RefCell<HashMap<PathBuf, adw::ToolbarView>>,

        pub battery_pages: RefCell<HashMap<PathBuf, adw::ToolbarView>>,

        pub gpu_pages: RefCell<HashMap<PciSlot, (Gpu, adw::ToolbarView)>>,

        pub apps_context: RefCell<AppsContext>,

        pub sender: Sender<Action>,
        pub receiver: RefCell<Option<Receiver<Action>>>,
    }

    impl Default for MainWindow {
        fn default() -> Self {
            let (sender, r) = unbounded();
            let receiver = RefCell::new(Some(r));

            Self {
                drive_pages: RefCell::default(),
                network_pages: RefCell::default(),
                battery_pages: RefCell::default(),
                split_view: TemplateChild::default(),
                resources_sidebar: TemplateChild::default(),
                content_stack: TemplateChild::default(),
                applications: TemplateChild::default(),
                applications_page: TemplateChild::default(),
                processes: TemplateChild::default(),
                processes_page: TemplateChild::default(),
                cpu: TemplateChild::default(),
                cpu_page: TemplateChild::default(),
                memory: TemplateChild::default(),
                memory_page: TemplateChild::default(),
                apps_context: Default::default(),
                sender,
                receiver,
                processor_window_title: TemplateChild::default(),
                gpu_pages: RefCell::default(),
            }
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for MainWindow {
        const NAME: &'static str = "MainWindow";
        type Type = super::MainWindow;
        type ParentType = adw::ApplicationWindow;

        fn class_init(klass: &mut Self::Class) {
            Self::bind_template(klass);
        }

        // You must call `Widget`'s `init_template()` within `instance_init()`.
        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for MainWindow {
        fn constructed(&self) {
            self.parent_constructed();
            let obj = self.obj();

            // Devel Profile
            if PROFILE == "Devel" {
                obj.add_css_class("devel");
            }

            // Load latest window state
            obj.load_window_size();
        }
    }

    impl WidgetImpl for MainWindow {}

    impl WindowImpl for MainWindow {
        // Save window state on delete event
        fn close_request(&self) -> glib::Propagation {
            if let Err(err) = self.obj().save_window_size() {
                log::warn!("Failed to save window state, {}", &err);
            }

            // Pass close request on to the parent
            self.parent_close_request()
        }
    }

    impl ApplicationWindowImpl for MainWindow {}

    impl AdwApplicationWindowImpl for MainWindow {}
}

glib::wrapper! {
    pub struct MainWindow(ObjectSubclass<imp::MainWindow>)
        @extends gtk::Widget, gtk::Window, gtk::ApplicationWindow, adw::ApplicationWindow,
        @implements gio::ActionMap, gio::ActionGroup, gtk::Root;
}

struct RefreshData {
    cpu_data: CpuData,
    mem_data: Result<MemoryData>,
    gpu_data: Vec<GpuData>,
    drive_paths: Vec<PathBuf>,
    drive_data: Vec<DriveData>,
    network_paths: Vec<PathBuf>,
    network_data: Vec<NetworkData>,
    battery_paths: Vec<PathBuf>,
    battery_data: Vec<BatteryData>,
    process_data: Vec<ProcessData>,
}

impl MainWindow {
    pub fn new(app: &Application) -> Self {
        let window = glib::Object::builder::<Self>()
            .property("application", app)
            .build();

        if let Some(receiver) = &*window.imp().receiver.borrow() {
            let main_context = MainContext::default();
            main_context.spawn_local(clone!(
                #[strong]
                receiver,
                #[weak]
                window,
                async move {
                    while let Ok(action) = receiver.recv().await {
                        window.process_action(action);
                    }
                }
            ));
        }
        window.setup_widgets();
        window
    }

    fn get_selected_page(&self) -> Option<Widget> {
        self.imp()
            .content_stack
            .visible_child()
            .and_downcast::<adw::ToolbarView>()
            .and_then(|toolbar| toolbar.content())
    }

    pub fn shortcut_toggle_search(&self) {
        let imp = self.imp();

        let selected_page = self.get_selected_page().unwrap();

        if selected_page.is::<ResApplications>() {
            imp.applications.toggle_search();
        } else if selected_page.is::<ResProcesses>() {
            imp.processes.toggle_search();
        }
    }

    pub fn shortcut_manipulate_app_process(&self, process_action: ProcessAction) {
        let imp = self.imp();

        let selected_page = self.get_selected_page().unwrap();

        if selected_page.is::<ResApplications>() {
            if let Some(app_item) = imp.applications.get_selected_app_entry() {
                imp.applications
                    .execute_app_action_dialog(&app_item, process_action);
            }
        } else if selected_page.is::<ResProcesses>() {
            if let Some(process_item) = imp.processes.get_selected_process_entry() {
                imp.processes
                    .execute_process_action_dialog(&process_item, process_action);
            }
        }
    }

    pub fn shortcut_information_app_process(&self) {
        let imp = self.imp();

        let selected_page = self.get_selected_page().unwrap();

        if selected_page.is::<ResApplications>() {
            if let Some(app_item) = imp.applications.get_selected_app_entry() {
                imp.applications.open_information_dialog(&app_item);
            }
        } else if selected_page.is::<ResProcesses>() {
            if let Some(process_item) = imp.processes.get_selected_process_entry() {
                imp.processes.open_info_dialog(&process_item);
            }
        }
    }

    pub fn shortcut_process_options(&self) {
        let imp = self.imp();

        let selected_page = self.get_selected_page().unwrap();

        if selected_page.is::<ResProcesses>() {
            if let Some(process_item) = imp.processes.get_selected_process_entry() {
                imp.processes.open_options_dialog(&process_item);
            }
        }
    }

    fn init_gpu_pages(self: &MainWindow) -> Vec<Gpu> {
        let imp = self.imp();

        let gpus = Gpu::get_gpus().unwrap_or_default();
        let gpus_len = gpus.len();

        for (i, gpu) in gpus.iter().enumerate() {
            let page = ResGPU::new();

            let tab_name = if gpus_len > 1 {
                i18n_f("GPU {}", &[&(i + 1).to_string()])
            } else {
                i18n("GPU")
            };

            page.set_tab_name(&*tab_name);

            let added_page = if let Ok(gpu_name) = gpu.name() {
                self.add_page(&page, &gpu_name, &tab_name)
            } else {
                self.add_page(&page, &tab_name, &tab_name)
            };

            page.init(gpu, i as u32);

            imp.gpu_pages
                .borrow_mut()
                .insert(gpu.pci_slot(), (gpu.clone(), added_page));
        }
        gpus
    }

    fn setup_widgets(&self) {
        let imp = self.imp();

        imp.resources_sidebar.set_stack(&imp.content_stack);

        imp.applications.init(imp.sender.clone());
        imp.processes.init(imp.sender.clone());
        imp.memory.init();

        if SETTINGS.show_search_on_start() {
            // we want the search bar to show up for both but also let the last viewed page grab the focus, so order is
            // important here
            if SETTINGS.last_viewed_page() == applications::TAB_ID {
                imp.processes.toggle_search();
                imp.applications.toggle_search();
            } else if SETTINGS.last_viewed_page() == processes::TAB_ID {
                imp.applications.toggle_search();
                imp.processes.toggle_search();
            }
        }

        *self.imp().apps_context.borrow_mut() = AppsContext::new();

        let cpu_info = cpu::cpu_info().context("unable to get CPUInfo").unwrap();
        if let Some(model_name) = cpu_info.model_name.as_deref() {
            imp.processor_window_title.set_title(model_name);
            imp.processor_window_title.set_subtitle(&i18n("Processor"));
        }
        self.imp().cpu.init(cpu_info);

        if SETTINGS.check_for_gpu() {
            self.init_gpu_pages();
        }

        let main_context = MainContext::default();

        main_context.spawn_local(clone!(
            #[weak(rename_to = this)]
            self,
            async move {
                this.periodic_refresh_all().await;
            }
        ));
    }

    fn gather_refresh_data(logical_cpus: usize, gpus: &[Gpu]) -> RefreshData {
        let cpu_data = CpuData::new(logical_cpus);

        let mem_data = MemoryData::new();

        let mut gpu_data = Vec::with_capacity(gpus.len());
        for gpu in gpus {
            let data = GpuData::new(gpu);

            gpu_data.push(data);
        }

        let drive_paths = Drive::get_sysfs_paths().unwrap_or_default();
        let mut drive_data = Vec::with_capacity(drive_paths.len());
        for path in &drive_paths {
            drive_data.push(DriveData::new(path));
        }

        let network_paths = NetworkInterface::get_sysfs_paths().unwrap_or_default();
        let mut network_data = Vec::with_capacity(network_paths.len());
        for path in &network_paths {
            network_data.push(NetworkData::new(path));
        }

        let battery_paths = Battery::get_sysfs_paths().unwrap_or_default();
        let mut battery_data = Vec::with_capacity(battery_paths.len());
        for path in &battery_paths {
            battery_data.push(BatteryData::new(path));
        }

        let process_data = Process::all_data()
            .inspect_err(|e| {
                warn!(
                    "Unable to update process and app data!\n{e}\n{}",
                    e.backtrace()
                );
            })
            .unwrap_or_default();

        RefreshData {
            cpu_data,
            mem_data,
            gpu_data,
            drive_paths,
            drive_data,
            network_paths,
            network_data,
            battery_paths,
            battery_data,
            process_data,
        }
    }

    fn refresh_ui(&self, refresh_data: RefreshData) {
        let imp = self.imp();

        let RefreshData {
            cpu_data,
            mem_data,
            gpu_data,
            drive_paths,
            drive_data,
            network_paths,
            network_data,
            battery_paths,
            battery_data,
            process_data,
        } = refresh_data;

        /*
         * Apps and processes
         */

        let mut apps_context = imp.apps_context.borrow_mut();
        apps_context.refresh(process_data);

        imp.applications.refresh_apps_list(&apps_context);
        imp.processes.refresh_processes_list(&apps_context);

        /*
         *  Gpu
         */
        let gpu_pages = imp.gpu_pages.borrow();
        for ((_, page), mut gpu_data) in gpu_pages.values().zip(gpu_data) {
            let page = page.content().and_downcast::<ResGPU>().unwrap();

            if !gpu_data.nvidia {
                // for non-NVIDIA GPUs, we prefer getting the fractions from the processes because they represent the
                // average usage during now and the last refresh, while gpu_busy_percent is a snapshot of the current
                // usage, which might not be what we want

                let processes_gpu_fraction = apps_context.gpu_fraction(gpu_data.pci_slot);
                gpu_data.usage_fraction = Some(processes_gpu_fraction.into());

                let processes_encode_fraction = apps_context.encoder_fraction(gpu_data.pci_slot);
                gpu_data.encode_fraction = Some(processes_encode_fraction.into());

                let processes_decode_fraction = apps_context.decoder_fraction(gpu_data.pci_slot);
                gpu_data.decode_fraction = Some(processes_decode_fraction.into());
            }

            page.refresh_page(&gpu_data);
        }

        std::mem::drop(apps_context);

        /*
         * Cpu
         */
        imp.cpu.refresh_page(&cpu_data);

        /*
         * Memory
         */
        if let Ok(mem_data) = mem_data {
            imp.memory.refresh_page(mem_data);
        } else if let Err(error) = mem_data {
            warn!("Unable to update memory data, reason: {error}");
        }

        /*
         *  Drives
         */
        // Make sure there is a page for every drive that is shown
        self.refresh_drive_pages(drive_paths, &drive_data);

        // Update drive pages
        for drive_data in drive_data {
            if drive_data.is_virtual && !SETTINGS.show_virtual_drives() {
                continue;
            }

            let drive_pages = imp.drive_pages.borrow();
            let page = drive_pages.get(&drive_data.inner.sysfs_path).unwrap();
            let page = page.content().and_downcast::<ResDrive>().unwrap();

            page.refresh_page(drive_data);
        }

        /*
         *  Network
         */
        // Make sure there is a page for every network interface that is shown
        self.refresh_network_pages(network_paths, &network_data);

        // Update network pages
        for network_data in network_data {
            if network_data.is_virtual && !SETTINGS.show_virtual_network_interfaces() {
                continue;
            }

            let network_pages = imp.network_pages.borrow();
            let page = network_pages.get(&network_data.inner.sysfs_path).unwrap();
            let page = page.content().and_downcast::<ResNetwork>().unwrap();

            page.refresh_page(network_data);
        }

        /*
         *  Batteries
         */
        // Make sure there is a page for every battery that is shown
        self.refresh_battery_pages(battery_paths, &battery_data);

        // Update battery pages
        for battery_data in battery_data {
            let battery_pages = imp.battery_pages.borrow();
            let page = battery_pages.get(&battery_data.inner.sysfs_path).unwrap();
            let page = page.content().and_downcast::<ResBattery>().unwrap();

            page.refresh_page(battery_data);
        }
    }

    pub async fn periodic_refresh_all(&self) {
        let imp = self.imp();

        let gpus = imp
            .gpu_pages
            .borrow()
            .values()
            .map(|(gpu, _)| gpu)
            .cloned()
            .collect::<Vec<Gpu>>();

        let logical_cpus = imp.cpu.imp().logical_cpus_amount.get();

        let (tx_data, rx_data) = std::sync::mpsc::sync_channel(1);
        let (tx_wait, rx_wait) = std::sync::mpsc::sync_channel(1);

        std::thread::spawn(move || {
            loop {
                let data = Self::gather_refresh_data(logical_cpus, &gpus);
                tx_data.send(data).unwrap();

                // Wait on delay so we don't gather data multiple times in a short time span
                // Which usually just yields the same data and makes changes appear delayed by (up to) multiple refreshes
                rx_wait.recv().unwrap();
            }
        });

        let mut first_refresh = true;

        loop {
            // gather_refresh_data()
            let refresh_data = rx_data.recv().unwrap();

            self.refresh_ui(refresh_data);

            // if this is our first refresh, we want to set the opening view to what it was when the last session was ended
            if first_refresh {
                let saved_page = SETTINGS.last_viewed_page();

                // yes, this is bad and O(n).
                for page in imp.content_stack.pages().iter::<gtk::StackPage>().flatten() {
                    let toolbar = page.child().downcast::<adw::ToolbarView>().unwrap();

                    let child_id = toolbar.content().unwrap().property::<GString>("tab_id");

                    if child_id == saved_page {
                        imp.content_stack.set_visible_child(&toolbar);
                        imp.resources_sidebar
                            .set_selected_list_item_by_tab_id(&child_id);
                        break;
                    }
                }

                first_refresh = false;
            }

            // Total time before next ui refresh
            let total_delay = SETTINGS.refresh_speed().ui_refresh_interval();

            // Reasonable timespan before total_delay ends to gather all data
            let gather_time = 0.2;

            timeout_future(Duration::from_secs_f32(total_delay - gather_time)).await;

            // Tell other threads to start gethering data
            tx_wait.send(()).unwrap();

            timeout_future(Duration::from_secs_f32(gather_time)).await;
        }
    }

    /// Wrapper to remove page, and check if removed page was visible with global default behavior
    fn remove_page(&self, page: &ToolbarView) {
        let imp = self.imp();
        imp.content_stack.remove(page);

        // no visible child exists
        if imp.content_stack.is_child_visible() {
            imp.resources_sidebar
                .set_selected_list_item_by_tab_id(applications::TAB_ID);
        }
    }

    /// Create page for every drive that is shown
    fn refresh_drive_pages(&self, mut paths: Vec<PathBuf>, drive_data: &[DriveData]) {
        let imp = self.imp();

        let mut drive_pages = imp.drive_pages.borrow_mut();

        let mut highest_secondary_ord = drive_pages
            .values()
            .filter_map(adw::ToolbarView::content)
            .map(|widget| widget.property::<u32>("secondary_ord"))
            .max()
            .unwrap_or_default();

        let old_page_paths: Vec<PathBuf> = drive_pages
            .iter()
            .map(|(path, _)| path.to_owned())
            .collect();

        // Filter hidden drives
        for data in drive_data {
            if data.is_virtual && !SETTINGS.show_virtual_drives() {
                let idx = paths
                    .iter()
                    .position(|p| **p == data.inner.sysfs_path)
                    .unwrap();
                paths.remove(idx);
            }
        } // paths now contains all the (paths to) drives we want to show

        // Delete hidden old drive pages
        for page_path in &old_page_paths {
            if !paths.contains(page_path) {
                // A drive has been removed
                info!(
                    "A drive has been removed (or turned invisible): {}",
                    page_path.display()
                );

                let page = drive_pages.remove(page_path).unwrap();
                self.remove_page(&page);
            }
        }

        // Add new drive pages
        for path in paths {
            if !drive_pages.contains_key(&path) {
                // A drive has been added
                info!(
                    "A drive has been added (or turned visible): {}",
                    path.display()
                );

                highest_secondary_ord = highest_secondary_ord.saturating_add(1);

                let drive = drive_data
                    .iter()
                    .find(|d| d.inner.sysfs_path == path)
                    .unwrap();

                let display_name = drive.inner.display_name();

                let page = ResDrive::new();
                page.init(drive, highest_secondary_ord);

                let toolbar = if let Some(model) = &drive.inner.model {
                    self.add_page(&page, model, &display_name)
                } else {
                    self.add_page(&page, &drive.inner.block_device, &display_name)
                };

                drive_pages.insert(path, toolbar);
            }
        }
    }

    /// Create page for every network interface that is shown
    fn refresh_network_pages(&self, mut paths: Vec<PathBuf>, network_data: &[NetworkData]) {
        let imp = self.imp();

        let mut network_pages = imp.network_pages.borrow_mut();

        let mut highest_secondary_ord = network_pages
            .values()
            .filter_map(adw::ToolbarView::content)
            .map(|widget| widget.property::<u32>("secondary_ord"))
            .max()
            .unwrap_or_default();

        let old_page_paths: Vec<PathBuf> = network_pages
            .iter()
            .map(|(path, _)| path.to_owned())
            .collect();

        // Filter hidden networks
        for data in network_data {
            if data.is_virtual && !SETTINGS.show_virtual_network_interfaces() {
                let idx = paths
                    .iter()
                    .position(|p| **p == data.inner.sysfs_path)
                    .unwrap();
                paths.remove(idx);
            }
        } // paths now contains all the (paths to) network interfaces we want to show

        // Delete hidden old network pages
        for page_path in &old_page_paths {
            if !paths.contains(page_path) {
                // A network interface has been removed
                info!(
                    "A network interface has been removed (or turned invisible): {}",
                    page_path.display()
                );

                let page = network_pages.remove(page_path).unwrap();
                self.remove_page(&page);
            }
        }

        // Add new network pages
        for path in paths {
            if !network_pages.contains_key(&path) {
                // A network interface has been added
                info!(
                    "A network interface has been added (or turned visible): {}",
                    path.display()
                );

                highest_secondary_ord = highest_secondary_ord.saturating_add(1);

                let network_interface = network_data
                    .iter()
                    .find(|d| d.inner.sysfs_path == path)
                    .unwrap();

                // Insert stub page, values will be updated in refresh_page()
                let page = ResNetwork::new();
                page.init(network_interface, highest_secondary_ord);

                let toolbar = self.add_page(
                    &page,
                    &network_interface.inner.display_name(),
                    &network_interface.inner.interface_type.to_string(),
                );

                network_pages.insert(path.clone(), toolbar);
            }
        }
    }

    /// Create page for every battery that is shown
    fn refresh_battery_pages(&self, paths: Vec<PathBuf>, battery_data: &[BatteryData]) {
        let imp = self.imp();

        let mut battery_pages = imp.battery_pages.borrow_mut();

        let mut highest_secondary_ord = battery_pages
            .values()
            .filter_map(adw::ToolbarView::content)
            .map(|widget| widget.property::<u32>("secondary_ord"))
            .max()
            .unwrap_or_default();

        let old_page_paths: Vec<PathBuf> = battery_pages
            .keys()
            .map(std::borrow::ToOwned::to_owned)
            .collect();

        // Delete hidden old battery pages
        for page_path in &old_page_paths {
            if !paths.contains(page_path) {
                // A battery has been removed
                info!("A battery has been removed: {}", page_path.display());

                let page = battery_pages.remove(page_path).unwrap();
                self.remove_page(&page);
            }
        }

        // Add new network pages
        for path in paths {
            if !battery_pages.contains_key(&path) {
                // A battery has been added
                info!("A battery has been added: {}", path.display());

                highest_secondary_ord = highest_secondary_ord.saturating_add(1);

                let battery = battery_data
                    .iter()
                    .find(|d| d.inner.sysfs_path == path)
                    .unwrap();

                // Insert stub page, values will be updated in refresh_page()
                let page = ResBattery::new();
                page.init(battery, highest_secondary_ord);

                let toolbar = self.add_page(
                    &page,
                    &battery
                        .inner
                        .sysfs_path
                        .file_name()
                        .unwrap()
                        .to_string_lossy(),
                    &battery.inner.display_name(),
                );

                battery_pages.insert(path.clone(), toolbar);
            }
        }
    }

    fn process_action(&self, action: Action) {
        let apps_context = self.imp().apps_context.borrow();
        match action {
            Action::ManipulateProcess(action, pid, display_name, toast_overlay) => {
                if let Some(process) = apps_context.get_process(pid) {
                    let toast_message = match process.execute_process_action(action) {
                        Ok(()) => get_action_success(action, &[&display_name]),
                        Err(_) => get_process_action_failure(action, &[&display_name]),
                    };
                    toast_overlay.add_toast(Toast::new(&toast_message));
                }
            }

            Action::ManipulateApp(action, id, toast_overlay) => {
                let app = apps_context.get_app(&Some(id.clone())).unwrap();
                let result = app.execute_process_action(&apps_context, action);

                let processes_tried = result.len();
                let processes_successful = result.iter().flatten().count();
                let processes_unsuccessful = processes_tried - processes_successful;

                let toast_message = if processes_unsuccessful > 0 {
                    get_app_action_failure(action, processes_unsuccessful as u32)
                } else {
                    get_action_success(action, &[&app.display_name])
                };

                toast_overlay.add_toast(Toast::new(&toast_message));
            }

            Action::AdjustProcess(pid, niceness, affinity, display_name, toast_overlay) => {
                if let Some(process) = apps_context.get_process(pid) {
                    let result = process.adjust(niceness, affinity);

                    let toast_message = match result {
                        Ok(()) => i18n_f("Successfully adjusted {}", &[&display_name]),
                        Err(_) => i18n_f("There was a problem adjusting {}", &[&display_name]),
                    };
                    toast_overlay.add_toast(Toast::new(&toast_message));
                }
            }
        };
    }

    fn save_window_size(&self) -> Result<(), glib::BoolError> {
        let (width, height) = self.default_size();

        SETTINGS.set_window_width(width)?;
        SETTINGS.set_window_height(height)?;

        SETTINGS.set_maximized(self.is_maximized())?;

        Ok(())
    }

    fn load_window_size(&self) {
        let width = SETTINGS.window_width();
        let height = SETTINGS.window_height();
        let is_maximized = SETTINGS.maximized();

        self.set_default_size(width, height);

        if is_maximized {
            self.maximize();
        }
    }

    fn add_page(
        &self,
        widget: &impl IsA<Widget>,
        window_title: &str,
        window_subtitle: &str,
    ) -> adw::ToolbarView {
        let imp = self.imp();

        let title_widget = adw::WindowTitle::new(window_title, window_subtitle);

        let sidebar_button = gtk::ToggleButton::new();
        sidebar_button.set_icon_name("sidebar-show-symbolic");
        imp.split_view
            .bind_property("collapsed", &sidebar_button, "visible")
            .sync_create()
            .build();
        imp.split_view
            .bind_property("show-sidebar", &sidebar_button, "active")
            .sync_create()
            .bidirectional()
            .build();

        let header_bar = adw::HeaderBar::new();
        header_bar.add_css_class("flat");
        header_bar.set_title_widget(Some(&title_widget));
        header_bar.pack_start(&sidebar_button);

        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&header_bar);
        toolbar.set_content(Some(widget));

        imp.content_stack.add_child(&toolbar);

        toolbar
    }
}

impl Default for MainWindow {
    fn default() -> Self {
        Application::default()
            .active_window()
            .unwrap()
            .downcast()
            .unwrap()
    }
}

fn get_action_success(action: ProcessAction, args: &[&str]) -> String {
    match action {
        ProcessAction::TERM => i18n_f("Successfully ended {}", args),
        ProcessAction::STOP => i18n_f("Successfully halted {}", args),
        ProcessAction::KILL => i18n_f("Successfully killed {}", args),
        ProcessAction::CONT => i18n_f("Successfully continued {}", args),
    }
}

fn get_app_action_failure(action: ProcessAction, args: u32) -> String {
    match action {
        ProcessAction::TERM => ni18n_f(
            "There was a problem ending a process",
            "There were problems ending {} processes",
            args,
            &[&args.to_string()],
        ),
        ProcessAction::STOP => ni18n_f(
            "There was a problem halting a process",
            "There were problems halting {} processes",
            args,
            &[&args.to_string()],
        ),
        ProcessAction::KILL => ni18n_f(
            "There was a problem killing a process",
            "There were problems killing {} processes",
            args,
            &[&args.to_string()],
        ),
        ProcessAction::CONT => ni18n_f(
            "There was a problem continuing a process",
            "There were problems continuing {} processes",
            args,
            &[&args.to_string()],
        ),
    }
}

pub fn get_process_action_failure(action: ProcessAction, args: &[&str]) -> String {
    match action {
        ProcessAction::TERM => i18n_f("There was a problem ending {}", args),
        ProcessAction::STOP => i18n_f("There was a problem halting {}", args),
        ProcessAction::KILL => i18n_f("There was a problem killing {}", args),
        ProcessAction::CONT => i18n_f("There was a problem continuing {}", args),
    }
}
