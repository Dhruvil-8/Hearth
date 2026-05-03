/// Audio extraction utilities for the Voice Gate.
///
/// In a real TLS-intercepting scenario, we'd extract PCM from decrypted payloads.
/// Since we can't decrypt TLS, this module provides utilities for working with
/// raw audio data from alternative sources (e.g., local microphone).

/// Convert raw bytes to f32 PCM samples (16-bit LE assumed).
pub fn bytes_to_pcm_f32(raw: &[u8]) -> Vec<f32> {
    raw.chunks_exact(2)
        .map(|chunk| {
            let sample = i16::from_le_bytes([chunk[0], chunk[1]]);
            sample as f32 / 32768.0
        })
        .collect()
}

/// Extract a 512-sample chunk from a PCM buffer, zero-padding if needed.
pub fn extract_chunk(pcm: &[f32], offset: usize) -> [f32; 512] {
    let mut chunk = [0.0f32; 512];
    let available = pcm.len().saturating_sub(offset).min(512);
    if available > 0 {
        chunk[..available].copy_from_slice(&pcm[offset..offset + available]);
    }
    chunk
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_pcm() {
        // Silence (zeros)
        let raw = vec![0u8; 1024];
        let pcm = bytes_to_pcm_f32(&raw);
        assert_eq!(pcm.len(), 512);
        assert!(pcm.iter().all(|s| *s == 0.0));
    }

    #[test]
    fn test_extract_chunk_padding() {
        let pcm = vec![1.0f32; 100];
        let chunk = extract_chunk(&pcm, 0);
        assert_eq!(chunk[0], 1.0);
        assert_eq!(chunk[99], 1.0);
        assert_eq!(chunk[100], 0.0); // zero-padded
    }
}
