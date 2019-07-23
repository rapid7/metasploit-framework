use_bpm 130

define :play_sleep do |note, time|
  play note
  sleep time
end

4.times do
  sample :drum_cymbal_pedal
  sleep 1
end

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

sleep 8

live_loop :bass do
  use_synth :pluck

  with_fx :reverb do
    play_sleep :Eb3, 2
    play_sleep :Eb3, 1
    play_sleep :Eb3, 1

    play_sleep :B2,  2
    play_sleep :B2,  1
    play_sleep :B2,  1

    play_sleep :Fs2, 2
    play_sleep :Fs2, 1
    play_sleep :Fs2, 1

    play_sleep :As2, 1.5
    play_sleep :As2, 1
    play_sleep :As2, 0.5
    play_sleep :As2, 1
  end
end

sleep 32

live_loop :lead do
  use_synth :piano

  with_fx :reverb do
    play_sleep :As4, 2
    play_sleep :As4, 0.5
    play_sleep :As4, 0.25
    play_sleep :As4, 0.25
    play_sleep :Gs4, 0.5
    play_sleep :As4, 0.5
    play_sleep :As4, 2

    play_sleep :As4, 0.5
    play_sleep :As4, 0.25
    play_sleep :As4, 0.25
    play_sleep :Gs4, 0.5
    play_sleep :As4, 0.5
    play_sleep :As4, 1.5

    play_sleep :Db5, 1
    play_sleep :As4, 1
    play_sleep :Gs4, 1
    play_sleep :Fs4, 1

    play_sleep :Eb4, 0.5
    play_sleep :Eb4, 0.5
    play_sleep :F4,  0.5
    play_sleep :Fs4, 0.5
    play_sleep :Eb4, 0.5
  end
end

sleep 32

live_loop :cowbell do
  sample :drum_cowbell, amp: 0.25
  sleep 1
end
