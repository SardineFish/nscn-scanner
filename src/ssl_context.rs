use lazy_static::lazy_static;
use openssl::ssl::{self, SslContext, SslMethod};

lazy_static!{
    pub static ref SSL_CONTEXT: SslContext = {
        SslContext::builder(SslMethod::tls()).unwrap()
            .build()
    };
}