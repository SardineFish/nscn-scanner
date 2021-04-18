use redis::RedisResult;
use std::{mem, ops::Deref, sync::Mutex};

pub struct RedisPool {
    url: String,
    pool: Mutex<Vec<redis::Client>>,
}

pub struct ManagedRedisClient<'a> {
    pool: &'a Mutex<Vec<redis::Client>>,
    client: Option<redis::Client>,
}

impl<'a> Drop for ManagedRedisClient<'a> {
    fn drop(&mut self) {
        let client = mem::replace(&mut self.client, None);
        self.pool.lock().unwrap().push(client.unwrap());
    }
}

impl<'a> Deref for ManagedRedisClient<'a> {
    type Target = redis::Client;
    fn deref(&self) -> &Self::Target {
        self.client.as_ref().unwrap()
    }
}

impl RedisPool {
    pub fn open(url: &str) -> Self {
        Self {
            url: url.to_owned(),
            pool: Mutex::new(Vec::new()),
        }
    }

    pub async fn get(&self) -> RedisResult<ManagedRedisClient<'_>> {
        let client = match self.pool.lock().unwrap().pop() {
            Some(client) => client,
            None => redis::Client::open(self.url.as_str())?,
        };

        Ok(ManagedRedisClient {
            pool: &self.pool,
            client: Some(client),
        })
    }
}