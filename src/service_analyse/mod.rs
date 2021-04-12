pub mod web;
pub mod scheduler;
pub mod ftp;
pub mod ssh;

pub struct ServiceInfo {
    pub name: String,
    pub version: String,
}