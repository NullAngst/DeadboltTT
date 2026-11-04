//! Async client for deadbolt-worker's socket.

use deadbolt_common::paths;
use deadbolt_common::protocol::{MAX_LINE, Reply, Request};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error("deadbolt-worker is not reachable: {0}")]
    Io(#[from] std::io::Error),
    #[error("deadbolt-worker sent a bad reply: {0}")]
    Bad(String),
    #[error("{0}")]
    Failed(String),
}

#[derive(Clone)]
pub struct Worker {
    sock: String,
}

async fn send(stream: &mut UnixStream, req: &Request) -> Result<(), WorkerError> {
    let mut line = serde_json::to_string(req).map_err(|e| WorkerError::Bad(e.to_string()))?;
    line.push('\n');
    stream.write_all(line.as_bytes()).await?;
    Ok(())
}

async fn recv(
    r: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
) -> Result<Option<Reply>, WorkerError> {
    let mut line = String::new();
    let n = r.read_line(&mut line).await?;
    if n == 0 {
        return Ok(None);
    }
    if line.len() > MAX_LINE {
        return Err(WorkerError::Bad("line too long".into()));
    }
    serde_json::from_str(&line)
        .map(Some)
        .map_err(|e| WorkerError::Bad(e.to_string()))
}

impl Worker {
    pub fn new() -> Worker {
        Worker {
            sock: std::env::var("DEADBOLT_WORKER_SOCK")
                .unwrap_or_else(|_| paths::WORKER_SOCK.into()),
        }
    }

    pub async fn call(&self, req: Request) -> Result<Reply, WorkerError> {
        let mut s = UnixStream::connect(&self.sock).await?;
        send(&mut s, &req).await?;
        let (r, _w) = s.into_split();
        let mut r = BufReader::new(r);
        match recv(&mut r).await? {
            Some(Reply::Error { message }) => Err(WorkerError::Failed(message)),
            Some(rep) => Ok(rep),
            None => Err(WorkerError::Bad("worker closed the connection".into())),
        }
    }

    /// Start a scan; replies stream into the returned channel until Done.
    pub async fn stream(&self, req: Request) -> Result<mpsc::Receiver<Reply>, WorkerError> {
        let mut s = UnixStream::connect(&self.sock).await?;
        send(&mut s, &req).await?;
        let (r, w) = s.into_split();
        let (tx, rx) = mpsc::channel(256);
        tokio::spawn(async move {
            let _keep = w;
            let mut r = BufReader::new(r);
            while let Ok(Some(rep)) = recv(&mut r).await {
                let done = matches!(rep, Reply::Done { .. });
                if tx.send(rep).await.is_err() || done {
                    break;
                }
            }
        });
        Ok(rx)
    }

    pub async fn ping(&self) -> bool {
        matches!(self.call(Request::Ping).await, Ok(Reply::Ok))
    }
}
