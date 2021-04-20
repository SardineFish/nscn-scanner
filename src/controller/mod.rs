mod scan;
mod search;
mod web_statics;

use actix_web::web::{scope, ServiceConfig};

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(scope("/api")
        .configure(scan::config)
        .configure(search::config)
    ).service(scope("")
        .configure(web_statics::config)
    );
}
