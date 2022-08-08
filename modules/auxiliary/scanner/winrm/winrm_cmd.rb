##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/winrm/connection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::WinRM
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::AuthOption

  def initialize
    super(
      'Name' => 'WinRM Command Runner',
      'Description' => %q{
        This module runs arbitrary Windows commands using the WinRM Service
        },
      'Author' => [ 'thelightcosine' ],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('CMD', [ true, 'The windows command to run', 'ipconfig /all' ]),
        OptString.new('USERNAME', [ true, 'The username to authenticate as']),
        OptString.new('PASSWORD', [ true, 'The password to authenticate with'])
      ]
    )

    register_advanced_options(
      [
        OptEnum.new('WinrmAuth', [true, 'The Authentication mechanism to use', Msf::Exploit::Remote::AuthOption::AUTO, Msf::Exploit::Remote::AuthOption::WINRM_OPTIONS], fallbacks: ['Auth']),
        OptString.new('WinrmRhostname', [false, 'The rhostname which is required for kerberos'], fallbacks: ['RHOSTNAME']),
        OptAddress.new('DomainControllerRhost', [false, 'The resolvable rhost for the Domain Controller'])
      ]
    )
  end

  def run
    if datastore['WinrmAuth'] == KERBEROS
      fail_with(Msf::Exploit::Failure::BadConfig, 'The WinrmRhostname option is required when using kerberos authentication.') if datastore['WinrmRhostname'].blank?
    end
    super
  end

  def run_host(ip)
    rhost = datastore['RHOST']
    rport = datastore['RPORT']
    uri = datastore['URI']
    ssl = datastore['SSL']
    schema = ssl ? 'https' : 'http'
    endpoint = "#{schema}://#{rhost}:#{rport}#{uri}"
    opts = {
      endpoint: endpoint,
        host: rhost,
        port: rport,
        uri: uri,
        ssl: ssl,
        transport: :rexhttp,
        no_ssl_peer_verification: true,
        operation_timeout: 1,
        timeout: 20,
        retry_limit: 1,
        realm: datastore['DOMAIN']
    }
    case datastore['WinrmAuth']
    when KERBEROS
      kerberos_authenticator = Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::HTTP.new(
        host: datastore['DomainControllerRhost'],
        hostname: datastore['WinrmRhostname'],
        realm: datastore['DOMAIN'],
        username: datastore['USERNAME'],
        password: datastore['PASSWORD'],
        timeout: 20, # datastore['timeout']
        framework: framework,
        framework_module: self,
        mutual_auth: true,
        use_gss_checksum: true
      )
      opts = opts.merge({
        user: '', # Need to provide it, otherwise the WinRM module complains
        password: '', # Need to provide it, otherwise the WinRM module complains
        kerberos_authenticator: kerberos_authenticator,
        vhost: datastore['RHOSTNAME']
      })
    else
      opts = opts.merge({
        user: datastore['USERNAME'],
        password: datastore['PASSWORD'],
      })
    end
    conn = Net::MsfWinRM::RexWinRMConnection.new(opts)

    begin
      shell = conn.shell(:powershell)
      lines = []
      shell.run(datastore['CMD']) do |stdout, stderr|
        stdout&.each_line do |line|
          print_line(line.rstrip)
          lines << line
        end
        print_error(stderr) if stderr
      end
      data = lines.join
      path = store_loot('winrm.cmd_results', 'text/plain', ip, data, 'winrm_cmd_results.txt', 'WinRM CMD Results')
      print_good "Results saved to #{path}"
    ensure
      shell.close if shell
    end
  end
end
