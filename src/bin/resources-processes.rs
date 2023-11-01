use std::sync::Arc;

use anyhow::{Context, Result};
use futures_util::future::join_all;
use glob::glob;
use process_data::ProcessData;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<()> {
    let return_vec = Arc::new(Mutex::new(Vec::new()));

    let mut handles = vec![];
    for entry in glob("/proc/[0-9]*/").context("unable to glob")?.flatten() {
        let return_vec = Arc::clone(&return_vec);

        let handle = tokio::task::spawn(async move {
            if let Ok(process_data) = ProcessData::try_from_path(entry).await {
                return_vec.lock().await.push(process_data);
            }
        });

        handles.push(handle);
    }
    join_all(handles).await;

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();

    let return_vec = return_vec.lock().await;
    rmp_serde::encode::write(&mut handle, &*return_vec).unwrap();

    Ok(())
}
