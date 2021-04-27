mod scan;
mod search;
mod web_statics;
mod stats;

use actix_web::web::{scope, ServiceConfig};

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(scope("/api")
        .configure(scan::config)
        .configure(search::config)
        .configure(stats::config)
    ).service(scope("")
        .configure(web_statics::config)
    );
}
