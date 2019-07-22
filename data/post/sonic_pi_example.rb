use_bpm 130

define :play_sleep do |note, time|
  play note
  sleep time
end

live_loop :beat do
  sample :bd_haus
  sleep 1
end

live_loop :bass do
  use_synth :chipbass

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

live_loop :lead do
  use_synth :chiplead

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
