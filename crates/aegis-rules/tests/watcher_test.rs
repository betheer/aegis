use aegis_rules::watcher::RulesWatcher;
use std::io::Write;
use std::time::Duration;

#[tokio::test]
async fn watcher_detects_file_change() {
    // Create a temp file in a watchable location.
    // On Linux/WSL, /tmp works fine with inotify.
    // On Windows, AppData\Local\Temp is not reliably watchable by the notify crate,
    // so we use the current directory instead.
    let file = if cfg!(target_os = "linux") {
        tempfile::Builder::new()
            .prefix("aegis-watcher-test-")
            .suffix(".toml")
            .tempfile()
            .unwrap()
    } else {
        tempfile::Builder::new()
            .prefix("aegis-watcher-test-")
            .suffix(".toml")
            .tempfile_in(std::env::current_dir().unwrap())
            .unwrap()
    };

    // Close the NamedTempFile handle but keep the path alive via `keep()`.
    // This lets us write through new handles later, which is required on Windows
    // for ReadDirectoryChangesW to fire (writing through the original open handle
    // does not trigger the notification on Windows).
    let (mut file_handle, path) = file.keep().unwrap();
    writeln!(file_handle, "# initial").unwrap();
    file_handle.flush().unwrap();
    // Drop the handle so subsequent writes open a fresh handle (needed on Windows).
    drop(file_handle);

    let (watcher, mut rx) = RulesWatcher::new(&path).unwrap();

    // Wait for inotify/ReadDirectoryChangesW to register the watch before writing.
    // 200ms is sufficient on most Linux kernels; on very slow CI increase to 500ms.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Open a new handle to write — on Windows this is required to trigger a
    // file-change notification; on Linux inotify fires on any write.
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(f, "# changed").unwrap();
        f.flush().unwrap();
    }

    // Should receive a reload signal within 2s
    let result = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
    assert!(
        result.is_ok(),
        "Expected reload signal within 2s — if flaky, increase sleep above"
    );

    drop(watcher);
    // Clean up the persisted temp file
    let _ = std::fs::remove_file(&path);
}
