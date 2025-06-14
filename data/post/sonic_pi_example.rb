use_bpm 130
use_synth_defaults sustain: 0

live_loop :drums do
  sample :drum_heavy_kick, amp: 2
  sleep 1
  sample :drum_snare_hard
  sleep 1
end

live_loop :hi_hat do
  sample :drum_cymbal_closed, amp: 0.5
  sleep 0.5
end

live_loop :bass do
  use_synth :pluck

  notes = %i[
    Eb3  Eb3  Eb3
    B2   B2   B2
    Fs2  Fs2  Fs2
    As2  As2  As2  As2
  ]

  beats = %w[
    2.0  1.0  1.0
    2.0  1.0  1.0
    2.0  1.0  1.0
    1.5  1.0  0.5  1.0
  ].map(&:to_f)

  with_fx :reverb do
    play_pattern_timed notes, beats
  end
end

live_loop :lead do
  use_synth :piano

  notes = %i[
    As4   As4   As4   As4   Gs4   As4   As4
    As4   As4   As4   Gs4   As4   As4
    Db5   As4   Gs4   Fs4
    Eb4   Eb4   F4    Fs4   Eb4
  ]

  beats = %w[
    2.00  0.50  0.25  0.25  0.25  0.75  2.00
    0.50  0.25  0.25  0.25  0.75  1.50
    1.00  1.00  1.00  1.00
    0.50  0.50  0.50  0.50  0.50
  ].map(&:to_f)

  with_fx :reverb do
    play_pattern_timed notes, beats
  end
end
