mod scan;
mod search;
mod web_statics;
mod stats;
mod analyser;
mod scheduler;

use actix_web::web::{scope, ServiceConfig};

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(scope("/api")
        .configure(scan::config)
        .configure(search::config)
        .configure(stats::config)
        .configure(analyser::config)
        .configure(scheduler::config)
    ).service(scope("")
        .configure(web_statics::config)
    );
}
