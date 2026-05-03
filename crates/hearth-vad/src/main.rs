use anyhow::Result;
use tracing_subscriber::EnvFilter;

mod audio;
mod log;
mod model;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("Hearth Voice Gate v0.1.0");

    #[cfg(target_os = "linux")]
    {
        tracing::info!("NFQUEUE mode available on Linux");
        // In production: open NFQUEUE, run packet gate loop
        // For now, log and wait
    }

    #[cfg(not(target_os = "linux"))]
    {
        tracing::warn!("Voice Gate NFQUEUE is only available on Linux.");
        tracing::info!("Running in monitor-only mode on this platform.");
    }

    // Initialize VAD event log
    let vad_log = log::VadLog::new("hearth_vad.db")?;
    tracing::info!("VAD event log initialized");

    // Demo: show that the model interface works
    let silence = [0.0f32; 512];
    let score = model::score_chunk(&silence);
    tracing::info!("VAD score for silence: {:.3}", score);

    tracing::info!("Voice Gate running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    tracing::info!("Voice Gate shutting down.");
    Ok(())
}
