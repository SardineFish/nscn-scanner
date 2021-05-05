use actix_web::{web::{ServiceConfig, scope}, get};
use actix_files as fs;
use actix_files::{NamedFile};
use nscn::GLOBAL_CONFIG;
use std::path::PathBuf;

pub fn concat_path(paths: &[&str]) -> PathBuf {
    let path: PathBuf = paths.into_iter().collect();
    path
}

macro_rules! static_file {
    ($name: ident, $url: expr, $file: expr) => {
        #[get($url)]
        async fn $name() -> actix_web::Result<NamedFile> {
            Ok(NamedFile::open(concat_path(&["./web/dist", $file]))?)
        }
    };
}

static_file!(task_index, "/tasks", "index.html");

pub fn config(cfg: &mut ServiceConfig) {
    match GLOBAL_CONFIG.role {
        nscn::NodeRole::Master | nscn::NodeRole::Standalone => {
            let files = fs::Files::new("/", "./web/dist").index_file("index.html").use_last_modified(false);
            cfg.service(scope("")
                .service(task_index)
                .service(files)
            );
        },
        _ => (),
    }
}