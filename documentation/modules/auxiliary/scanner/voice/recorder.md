## Vulnerable Application

This module dials a range of phone numbers and records audio from each answered call.

## Verification Steps

1. Start msfconsole
2. Do: `use modules/auxiliary/scanner/voice/recorder`
3. Do: `set IAX_HOST [ip]`
4. Do: `set OUTPUT_PATH [path]`
5. Do: `set TARGETS [phone numbers]`
6. Do: `run`

## Scenarios

 ```
  msf > use modules/auxiliary/scanner/voice/recorder
  msf auxiliary(scanner/voice/recorder) > set IAX_HOST 10.0.183.93
    IAX_HOST => 10.0.183.93
  msf auxiliary(scanner/voice/recorder) > set OUTPUT_PATH /root/audio
    OUTPUT_PATH => /root/voice
  msf auxiliary(scanner/voice/recorder) > set TARGETS 123-456-7890
    TARGETS => 123-456-7890
  msf auxiliary(scanner/voice/recorder) > run
    [*] Dialing 123-456-7890...
    [*]   Number: 123-456-7890 ringing  Frames 0 DTMF ''
    [*]   Number: 123-456-7890 ringing  Frames 0 DTMF ''
    [*]   Number: 123-456-7890 ringing  Frames 0 DTMF ''
    [*]   Number: 123-456-7890 answered  Frames 51 DTMF ''
    [*]   Number: 123-456-7890 answered  Frames 101 DTMF ''
    [*]   Number: 123-456-7890 answered  Frames 151 DTMF ''
    [*]   Number: 123-456-7890 answered  Frames 201 DTMF ''
    [*]   Number: 123-456-7890 answered  Frames 252 DTMF ''
    [*]   Number: 123-456-7890 answered  Frames 302 DTMF ''
    [*]   Completed   Number: 123-456-7890  State: hangup Frames: 302 DTMF ''
    [+] 123-456-7890 resulted in 15420 bytes of audio to /root/audio/123-456-7890.raw
    [*] Auxiliary module execution completed
  ```
