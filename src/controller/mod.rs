mod scan;
mod search;

use actix_web::web::{scope, ServiceConfig};

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(scope("/api")
        .configure(scan::config)
        .configure(search::config)
    );
}
