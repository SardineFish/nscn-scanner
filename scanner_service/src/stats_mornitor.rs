use std::{sync::Arc, time::Duration};

use serde::{Serialize, Deserialize};
use sysinfo::{ProcessorExt, System, SystemExt, NetworkExt, NetworksExt};
use tokio::{sync::Mutex, task, time::sleep};

use crate::{GLOBAL_CONFIG};

#[derive(Serialize, Deserialize)]
pub struct SystemStats {
    cpu_usage: f32,
    total_memory_kb: u64,
    used_memory_kb: u64,
    total_swap_kb: u64,
    used_swap_kb: u64,
    network_in_bytes: u64,
    network_out_bytes: u64,
    load_one: f64,
    load_five: f64,
    load_fifteen: f64,
}

#[derive(Clone)]
pub struct SystemStatsMornitor {
    sys: Arc<Mutex<System>>,
}
impl SystemStatsMornitor {
    pub fn start() -> Self {
        let tracker = Self {
            sys: Arc::new(Mutex::new(System::new_all())),
        };
        task::spawn(tracker.clone().update());
        tracker
    }
    pub async fn get_stats(&self) -> SystemStats {
        let sys = self.sys.lock().await;

        let data = GLOBAL_CONFIG.stats.net_interface.as_ref()
            .and_then(|stats_interface| sys.get_networks().iter()
                .find(|(interface, _)|interface == &stats_interface)
                .map(|(_, data)| data));
        let net_in;
        let net_out;
        if let Some(data) = data {
            net_in = data.get_received();
            net_out = data.get_transmitted();
        }
        else {
            net_in = sys.get_networks().iter()
                .map(|(_, data)|data.get_received())
                .sum();
            net_out = sys.get_networks().iter()
                .map(|(_, data)|data.get_transmitted())
                .sum();
        }
        
        SystemStats {
            cpu_usage: sys.get_global_processor_info().get_cpu_usage(),
            used_memory_kb: sys.get_used_memory(),
            total_memory_kb: sys.get_total_memory(),
            used_swap_kb: sys.get_used_swap(),
            total_swap_kb: sys.get_total_swap(),
            network_in_bytes: net_in,
            network_out_bytes: net_out,
            load_one: sys.get_load_average().one,
            load_five: sys.get_load_average().five,
            load_fifteen: sys.get_load_average().fifteen,
        }
    }
    async fn update(self) {
        loop {
            sleep(Duration::from_millis(GLOBAL_CONFIG.stats.sys_update_interval)).await;
            {
                let mut sys = self.sys.lock().await;
                sys.refresh_cpu();
                sys.refresh_memory();
                sys.refresh_networks();
            }
        }
    }
}