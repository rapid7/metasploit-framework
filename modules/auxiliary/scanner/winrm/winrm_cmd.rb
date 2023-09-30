##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/winrm/connection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::WinRM
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

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
        OptString.new('USERNAME', [ true, 'The username to authenticate as'])
      ]
    )
  end

  def run
    check_winrm_parameters
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
      proxies: datastore['Proxies'],
      uri: uri,
      ssl: ssl,
      transport: :rexhttp,
      no_ssl_peer_verification: true,
      operation_timeout: 1,
      timeout: 20,
      retry_limit: 1,
      realm: datastore['DOMAIN']
    }
    case datastore['Winrm::Auth']
    when Msf::Exploit::Remote::AuthOption::KERBEROS
      kerberos_authenticator = Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::HTTP.new(
        host: datastore['DomainControllerRhost'],
        hostname: datastore['Winrm::Rhostname'],
        proxies: datastore['proxies'],
        realm: datastore['DOMAIN'],
        username: datastore['USERNAME'],
        password: datastore['PASSWORD'],
        timeout: 20, # datastore['timeout']
        framework: framework,
        framework_module: self,
        cache_file: datastore['Winrm::Krb5Ccname'].blank? ? nil : datastore['Winrm::Krb5Ccname'],
        mutual_auth: true,
        use_gss_checksum: true,
        ticket_storage: kerberos_ticket_storage,
        offered_etypes: Msf::Exploit::Remote::AuthOption.as_default_offered_etypes(datastore['Winrm::KrbOfferedEncryptionTypes'])
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
