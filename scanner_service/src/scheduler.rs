use redis::AsyncCommands;

use crate::{error::*};

pub struct Scheduler {
    redis_key: String,
    redis: redis::Client,
    redis_connection: Option<redis::aio::Connection>,
}

macro_rules! get_redis {
    ($self_mut: expr, $redis: ident) => {
        if let None = $self_mut.redis_connection {
            $self_mut.redis_connection = Some($self_mut.redis.get_async_connection().await?);
        }
        let $redis = $self_mut.redis_connection.as_mut().ok_or("Failed to get redis connection")?;
    };
}

impl Scheduler {
    pub async fn new(redis_key: &str, redis_url: &str) -> Result<Self, SimpleError> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self {
            redis_key: redis_key.to_owned(),
            redis_connection: None, 
            redis: client,
        })
    }
    pub async fn fetch_task(&mut self) -> Result<String, SimpleError> {
        get_redis!(self, redis);
        
        Ok(redis.brpoplpush(
            format!("{}_taskqueue", self.redis_key), 
            format!("{}_running", self.redis_key),
            0
        ).await?)
    }
    pub async fn recover_tasks(&mut self) -> Result<(), SimpleError> {
        get_redis!(self, redis);

        loop {
            let result: Result<Option<String>, redis::RedisError> = redis.rpoplpush(
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
        get_redis!(self, redis);
        redis.lrem(format!("{}_running", self.redis_key), 1, task).await?;
        Ok(())
    }
    pub async fn enqueue_task(&mut self, task: &str) -> Result<(), SimpleError> {
        get_redis!(self, redis);

        redis.lpush(format!("{}_taskqueue", self.redis_key), task).await?;
        Ok(())
    }
}

impl Clone for Scheduler {
    fn clone(&self) -> Self {
        Self {
            redis: self.redis.clone(),
            redis_key: self.redis_key.clone(),
            redis_connection: None, 
        }
    }
}
