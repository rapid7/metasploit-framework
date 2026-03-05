module Msf::Payload::Linux::Aarch64::SleepEvasion

  def sleep_evasion(opts = {})
    seconds = opts[:seconds] || rand(60)
    seconds_lo = seconds & 0xffff
    seconds_hi = (seconds >> 16) & 0xffff
    sleep_evasion_stub = [
      (0xd2800000 | (seconds_lo << 5) | 0x0),   #   mov     x0
      (0xf2a00000 | (seconds_hi << 5) | 0x0),   #   movk    x0, #<seconds_hi>, lsl #16
      0xa9bf07e0,                               #   stp     x0, xzr, [sp, #-16]!
      0x910003e0,                               #   mov     x0, sp
      0xd2800001,                               #   mov     x1, #0
      0xd2800ca8,                               #   mov     x8, #101
      0xd4000001,                               #   svc     #0
      0x910043ff,                               #   add     sp, sp, #16
    ].pack('V*')

    sleep_evasion_stub
  end
  
end