use crate::{error::SimpleError, parse_ipv4_cidr, scheduler::{SharedSchedulerInternalStats, SharedSchedulerStats, master_scheduler::MasterScheduler}};
use crate::config::GLOBAL_CONFIG;

#[derive(Clone)]
pub struct ScannerMasterScheduler {
    scheduler: MasterScheduler,
    internal_stats: SharedSchedulerInternalStats,
    stats: SharedSchedulerStats,
}

impl ScannerMasterScheduler {
    pub async fn new() -> Result<Self, SimpleError> {
        let internal_stats = SharedSchedulerInternalStats::new();
        let (_, stats) = internal_stats.clone().spawn_mornitor(10.0);
        Ok(Self {
            scheduler: MasterScheduler::start("scanner", GLOBAL_CONFIG.redis.as_str()).await?,
            internal_stats,
            stats,
        })
    }

    pub fn scheduler(&self) -> &MasterScheduler {
        &self.scheduler
    }

    pub async fn enqueue_addr_list(&self, addr_cidr_list: Vec<String>) -> Result<usize, SimpleError> {
        let count = Self::count_ips(&addr_cidr_list)?;
        self.internal_stats.add_pending_tasks(count).await;
        self.scheduler.dispathcer().enqueue_tasks(addr_cidr_list).await?;
        Ok(count)
    }

    pub async fn complete_addr_list(&self, addr_cidr_list: Vec<String>) -> Result<usize, SimpleError> {
        let count = Self::count_ips(&addr_cidr_list)?;
        self.internal_stats.remove_pending_tasks(count).await;
        self.internal_stats.dispatch_tasks(count).await;
        self.scheduler.dispathcer().enqueue_tasks(addr_cidr_list).await?;
        Ok(count)
    }

    pub async fn clear_tasks(&self) -> Result<usize, SimpleError> {
        let count = self.scheduler.dispathcer().clear_tasks().await?;
        self.internal_stats.update_pending_tasks(0).await;
        Ok(count)
    }

    pub async fn remove_tasks(&self, addr_cidr_list: Vec<String>) -> Result<usize, SimpleError> {
        let count = Self::count_ips(&addr_cidr_list)?;
        self.internal_stats.remove_pending_tasks(count).await;
        self.scheduler.dispathcer().enqueue_tasks(addr_cidr_list).await?;
        Ok(count)
    }

    fn count_ips(addr_cidr_list: &Vec<String>) -> Result<usize, SimpleError> {
        let mut count = 0;
        for addr_cidr in addr_cidr_list {
            let range = parse_ipv4_cidr(addr_cidr)?;
            count += range.len();
        }
        Ok(count)
    }
}
