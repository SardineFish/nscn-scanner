

use futures::{Future, future::select, pin_mut};
use tokio::{sync::oneshot, task::JoinHandle};
use tokio::task;
use futures::future::Either;

pub enum TaskResult {
    Terminated,
}

pub struct KillableTask<T> {
    kill_sender: oneshot::Sender<()>,
    join_handler: JoinHandle<Result<T, TaskResult>>,
}

impl<T> KillableTask<T> where T: Send + 'static {
    pub fn new(task: impl Future<Output=T> + Send + 'static) -> Self {
        let (sender, receiver) = oneshot::channel::<()>();
        Self {
            kill_sender: sender,
            join_handler: task::spawn(Self::run_task(task, receiver))
        }
    }

    async fn run_task(task: impl Future<Output=T> + Send, kill_receiver: oneshot::Receiver<()>) -> Result<T, TaskResult> {
        pin_mut!(task, kill_receiver);

        let result = select(task, kill_receiver).await;
        match result {
            Either::Left((result, _)) => Ok(result),
            Either::Right(_) => Err(TaskResult::Terminated),
        }
    }
}