use std::{io::{Read, Write}, sync::atomic::AtomicPtr, task::{Context, Poll}};
use std::pin::Pin;
use futures::{Future, future::poll_fn};
use openssl::{error::ErrorStack, ssl::{Error as SslError, HandshakeError as SyncHandshakeError, Ssl as SyncSsl, SslRef, SslStream as SyncSslStream}};
use openssl::ssl;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::ptr::NonNull;

pub struct StreamWrapper<S> {
    inner: S,
    ctx: AtomicPtr<Context<'static>>,
}

impl<S> StreamWrapper<S> {
    fn new(stream: S) -> Self {
        Self {
            inner: stream,
            ctx: AtomicPtr::default(),
        }
    }
    fn with_context<'ctx>(&mut self, cx: &mut Context<'ctx>) -> &mut Self {
        self.ctx = Self::wrap_context_ptr(cx);
        self
    }
    fn wrap_context_ptr(cx: &mut Context<'_>) -> AtomicPtr<Context<'static>> {
        unsafe { AtomicPtr::new(cx as *mut Context<'_> as usize as *mut Context<'static>) }   
    }
}

impl<S> Read for StreamWrapper<S> where S : AsyncRead + Unpin {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let stream = Pin::new(&mut self.inner);
        let mut buf = ReadBuf::new(buf);
        let ptr = self.ctx.get_mut();
        let ctx = unsafe {ptr.as_mut().unwrap()};

        match stream.poll_read(ctx, &mut buf) {
            Poll::Ready(Ok(_)) => Ok(buf.filled().len()),
            Poll::Ready(Err(err)) => Err(err),
            Poll::Pending => Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
        }
    }
}

impl<S> Write for StreamWrapper<S> where S: AsyncWrite + Unpin {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let stream = Pin::new(&mut self.inner);
        
        let ptr = self.ctx.get_mut();
        let ctx = unsafe {ptr.as_mut().unwrap()};
        match stream.poll_write(ctx, buf) {
            Poll::Ready(Ok(size)) => Ok(size),
            Poll::Ready(Err(err)) => Err(err),
            Poll::Pending => Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        let stream = Pin::new(&mut self.inner);
        
        let mut ptr = self.ctx.get_mut();
        let ctx = unsafe { ptr.as_mut().unwrap() };
        match stream.poll_flush(ctx) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
        }
    }
}

type SslResult<T> = Result<T, openssl::ssl::Error>;

// pub struct Ssl(pub SyncSsl);

// impl Ssl {
//     fn poll_connect<S: AsyncRead + AsyncWrite + Unpin>(
//         self,
//         stream: StreamWrapper<S>
//     ) -> Poll<Result<SslStream<StreamWrapper<S>>, HandshakeError>>
//     {
//         match self.0.connect(stream) {
//             Ok(stream) => Poll::Ready(Ok(SslStream(stream))),
//             Err(SyncHandshakeError::WouldBlock(_)) => Poll::Pending,
//             Err(SyncHandshakeError::SetupFailure(err)) => Poll::Ready(Err(HandshakeError::SetupFailure(err))),
//             Err(SyncHandshakeError::Failure(err)) => Poll::Ready(Err(HandshakeError::Failure(err.into_error()))),
//         }
//     }

//     pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(self, stream: S) -> Result<SslStream<StreamWrapper<S>>, HandshakeError> {
//         poll_fn_once(|cx| {
//             let stream = StreamWrapper::new(stream, cx);
//             self.poll_connect(stream)
//         }).await
//     }


//     fn wrap_poll<T>(result: SslResult<T>) -> Poll<SslResult<T>> {
//         match result {
//             Ok(val) => Poll::Ready(Ok(val)),
//             Err(err) => match err.code() {
//                 ssl::ErrorCode::WANT_READ | ssl::ErrorCode::WANT_WRITE => Poll::Pending,
//                 _ => Poll::Ready(Err(err)),
//             }
//         }
//     }
//     fn wrap_poll_void<T>(result: SslResult<T>) -> Poll<SslResult<()>> {
//         match result {
//             Ok(_) => Poll::Ready(Ok(())),
//             Err(err) => match err.code() {
//                 ssl::ErrorCode::WANT_READ | ssl::ErrorCode::WANT_WRITE => Poll::Pending,
//                 _ => Poll::Ready(Err(err)),
//             }
//         }
//     }
// }

struct FnFuture<F> {
    func: Option<F>,
}

impl<T, F> Future for FnFuture<F> where F: FnOnce(&mut Context<'_>) -> Poll<T> + Unpin {
    type Output = T;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let func = std::mem::replace(&mut self.func, None);
        match func {
            Some(func) => func(cx),
            None => panic!("FnOnce should not be called more than once."),
        }
    }
}

fn poll_fn_once<T, F: FnOnce(&mut Context<'_>) -> Poll<T>>(func: F) -> FnFuture<F> {
    FnFuture {
        func: Some(func),
    }
}

pub struct SslStream<S>(SyncSslStream<S>);

impl<S> SslStream<S> {
    pub fn sync_ssl(&self) -> &SslRef {
        self.0.ssl()
    }
}

impl<S> SslStream<StreamWrapper<S>> where S: AsyncRead + AsyncWrite + Unpin {
    pub fn new(ssl: SyncSsl, stream: S) -> SslResult<Self> {
        Ok(Self(SyncSslStream::new(ssl, StreamWrapper::new(stream))?))
    }

    fn poll_connect(&mut self) -> Poll<Result<(), SslError>>
    {
        match self.0.connect() {
            Ok(stream) => Poll::Ready(Ok(())),
            Err(err) => match err.code() {
                ssl::ErrorCode::WANT_READ | ssl::ErrorCode::WANT_WRITE => Poll::Pending,
                _ => Poll::Ready(Err(err)),
            }
        }
    }

    pub async fn connect(&mut self) -> Result<(), SslError> {
        poll_fn(|cx| {
            self.0.get_mut().with_context(cx);
            self.poll_connect()
        }).await
    }
}

#[derive(Debug)]
pub enum HandshakeError {
    SetupFailure(ErrorStack),
    Failure(SslError),
}