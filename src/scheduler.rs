use redis::AsyncCommands;

use crate::error::*;

pub struct Scheduler {
    redis_key: String,
    redis: redis::Client,
    redis_connection: redis::aio::Connection,
}

impl Scheduler {
    pub async fn new(redis_key: &str, redis_url: &str) -> Result<Self, SimpleError> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self {
            redis_key: redis_key.to_owned(),
            redis_connection: client.get_async_connection().await?, 
            redis: client,
        })
    }
    pub async fn clone(&self) -> Result<Self, SimpleError> {
        Ok(Self {
            redis_key: self.redis_key.clone(),
            redis: self.redis.clone(),
            redis_connection: self.redis.get_async_connection().await?,
        })
    }
    pub async fn fetch_task(&mut self) -> Result<String, SimpleError> {
        Ok(self.redis_connection.brpoplpush(
            format!("{}_taskqueue", self.redis_key), 
            format!("{}_running", self.redis_key),
            0
        ).await?)
    }
    pub async fn recover_tasks(&mut self) -> Result<(), SimpleError> {
        loop {
            let result: Result<Option<String>, redis::RedisError> = self.redis_connection.rpoplpush(
                format!("{}_running", self.redis_key), 
                format!("{}_taskqueue", self.redis_key)
            ).await;
            match result {
                Err(err) => Err(err)?,
                Ok(None) => return Ok(()),
                _ => (),
            }
        }
    }
    pub async fn complete_task(&mut self, task: &str) -> Result<(), SimpleError> {
        self.redis_connection.lrem(format!("{}_running", self.redis_key), 1, task).await?;
        Ok(())
    }
    pub async fn enqueue_task(&mut self, task: &str) -> Result<(), SimpleError> {
        self.redis_connection.lpush(format!("{}_taskqueue", self.redis_key), task).await?;
        Ok(())
    }
}
