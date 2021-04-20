use actix_web::web::ServiceConfig;
use actix_files as fs;

pub fn config(cfg: &mut ServiceConfig) {
    let files = fs::Files::new("/", "./web/dist").index_file("index.html").use_last_modified(false);
    cfg.service(files);
}