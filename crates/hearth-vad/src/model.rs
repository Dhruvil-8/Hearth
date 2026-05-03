/// Voice Activity Detection model interface.
///
/// In production, this loads Silero VAD ONNX model via tract-onnx.
/// For cross-platform builds, we provide a simple energy-based fallback.

/// Score a single 512-sample audio chunk for speech probability.
/// Returns a value in [0.0, 1.0] where > 0.5 indicates speech.
pub fn score_chunk(audio: &[f32; 512]) -> f32 {
    // Energy-based VAD fallback (used when tract-onnx is not available)
    // RMS energy of the chunk
    let rms = (audio.iter().map(|s| s * s).sum::<f32>() / 512.0).sqrt();

    // Map RMS to a probability-like score
    // Silence (rms ~0) → 0.0, Speech (rms > 0.02) → high score
    let score = (rms * 50.0).min(1.0);
    score
}

/// Check if a wake word is likely present in recent audio.
///
/// Examines the last ~3 seconds of audio (90 chunks at 16kHz).
/// Returns true if >= 3 consecutive chunks score > 0.5
/// (indicating sustained speech consistent with a wake word).
pub fn is_wake_word_likely(recent_chunks: &[[f32; 512]]) -> bool {
    let mut consecutive = 0u32;
    for chunk in recent_chunks {
        if score_chunk(chunk) > 0.5 {
            consecutive += 1;
            if consecutive >= 3 {
                return true;
            }
        } else {
            consecutive = 0;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_silence_scores_low() {
        let silence = [0.0f32; 512];
        let score = score_chunk(&silence);
        assert!(score < 0.1, "Silence should score below 0.1, got {}", score);
    }

    #[test]
    fn test_loud_signal_scores_high() {
        let mut signal = [0.0f32; 512];
        for (i, s) in signal.iter_mut().enumerate() {
            *s = (i as f32 * 0.1).sin() * 0.5; // sine wave
        }
        let score = score_chunk(&signal);
        assert!(
            score > 0.3,
            "Loud signal should score above 0.3, got {}",
            score
        );
    }

    #[test]
    fn test_wake_word_detection() {
        let silence = [0.0f32; 512];
        let mut speech = [0.0f32; 512];
        for (i, s) in speech.iter_mut().enumerate() {
            *s = (i as f32 * 0.1).sin() * 0.5;
        }

        // No wake word in silence
        let chunks: Vec<[f32; 512]> = (0..90).map(|_| silence).collect();
        assert!(!is_wake_word_likely(&chunks));

        // Wake word present with sustained speech
        let mut chunks: Vec<[f32; 512]> = (0..90).map(|_| silence).collect();
        for i in 40..50 {
            chunks[i] = speech;
        }
        assert!(is_wake_word_likely(&chunks));
    }
}
