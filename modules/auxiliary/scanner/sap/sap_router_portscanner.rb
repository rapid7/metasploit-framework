##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'SAPRouter Port Scanner',
      'Description' => %q{
          This module allows for mapping ACLs and identify open/closed ports accessible
        on hosts through a saprouter.
      },
      'Author' => [
        'Bruno Morisson <bm[at]integrity.pt>', # metasploit module
        'nmonkee' # saprouter packet building code from sapcat.rb and default sap ports information
      ],
      'References' =>
        [
          # General
          ['URL', 'http://help.sap.com/saphelp_nw70/helpdata/EN/4f/992dfe446d11d189700000e8322d00/frameset.htm'],
          ['URL', 'http://help.sap.com/saphelp_dimp50/helpdata/En/f8/bb960899d743378ccb8372215bb767/content.htm'],
          ['URL', 'http://labs.mwrinfosecurity.com/blog/2012/09/13/sap-smashing-internet-windows/'],
          ['URL', 'http://conference.hitb.org/hitbsecconf2010ams/materials/D2T2%20-%20Mariano%20Nunez%20Di%20Croce%20-%20SAProuter%20.pdf'],
          ['URL', 'http://scn.sap.com/docs/DOC-17124'] # SAP default ports
        ],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        OptAddress.new('SAPROUTER_HOST', [true, 'SAPRouter address', '']),
        OptString.new('RHOSTS', [true, 'Comma delimited target hostnames, target address range or CIDR identifier', '']),
        OptPort.new('SAPROUTER_PORT', [true, 'SAPRouter TCP port', '3299']),
        OptEnum.new('MODE', [true, 'Connection Mode: SAP_PROTO or TCP ', 'SAP_PROTO', ['SAP_PROTO', 'TCP']]),
        OptString.new('INSTANCES', [false, 'SAP instance numbers to scan (NN in PORTS definition)', '00-99']),
        OptString.new('PORTS', [true, 'Ports to scan (e.g. 3200-3299,5NN13)', '32NN']),
        # Default ports: 32NN,33NN,48NN,80NN,36NN,81NN,5NN00-5NN19,21212,21213,
        # 59975,59976,4238-4241,3299,3298,515,7200,7210,7269,7270,7575,39NN,
        # 3909,4NN00,8200,8210,8220,8230,4363,4444,4445,9999,3NN01-3NN08,
        # 3NN11,3NN17,20003-20007,31596,31597,31602,31601,31604,2000-2002,
        # 8355,8357,8351-8353,8366,1090,1095,20201,1099,1089,443NN,444NN
        OptInt.new('CONCURRENCY', [true, 'The number of concurrent ports to check per host', 10]),
        OptEnum.new('RESOLVE',[true,'Where to resolve RHOSTS',false,['remote','local']])
      ], self.class)

    deregister_options('RPORT')
    deregister_options('RHOST')

  end

  # Converts a instance specification like "4,21-23,33" into a sorted,
  # unique array of valid port numbers like [4,21,22,23,33]
  def sap_instance_to_list(instance)
    instances = []

    return if !instance

    # Build ports array from port specification
    instance.split(/,/).each do |item|
      start, stop = item.split(/-/).map { |p| p.to_i }

      start ||= 0
      stop ||= item.match(/-/) ? 99 : start

      start, stop = stop, start if stop < start

      start.upto(stop) { |p| instances << p }
    end

    # Sort, and remove dups and invalid instances
    instances.sort.uniq.delete_if { |p| p < 0 or p > 99 }
  end

  def build_sap_ports(ports)
    sap_ports = []

    sap_instances = sap_instance_to_list(datastore['INSTANCES'])

    # if we have INSTANCES, let's fill in the NN on PORTS
    if sap_instances and ports.include? 'NN'
      sap_instances.each { |i| sap_ports << (ports.gsub('NN', "%02d" % i)).to_s }
      ports = Rex::Socket.portspec_crack(sap_ports.join(','))
    else
      ports = Rex::Socket.portspec_crack(ports)
    end

    return ports
  end

  def build_ni_packet(routes)

    mode = {'SAP_PROTO' => 0, 'TCP' => 1}[datastore['MODE']]

    route_data=''
    ni_packet = [
      'NI_ROUTE',
      0,
      2,
      39,
      2,
      mode,
      0,
      0,
      1
    ].pack("A8c8")

    first = false

    routes.each do |host, port| # create routes
      route_item = [host, 0, port.to_s, 0, 0].pack("A*CA*cc")
      if !first
        route_data = [route_data, route_item.length, route_item].pack("A*NA*")
        first = true
      else
        route_data = route_data << route_item
      end
    end

    ni_packet << [route_data.length - 4].pack('N') << route_data # add routes to packet
    ni_packet = [ni_packet.length].pack('N') << ni_packet # add size
  end

  def sap_port_info(port)

    case port.to_s

    when /^3299$/
      service = "SAP Router"
    when /^3298$/
      service = "SAP niping (Network Test Program)"
    when /^32[0-9][0-9]/
      service = "SAP Dispatcher sapdp" + port.to_s[-2, 2]
    when /^33[0-9][0-9]/
      service = "SAP Gateway sapgw" + port.to_s[-2, 2]
    when /^48[0-9][0-9]/
      service = "SAP Gateway [SNC] sapgw" + port.to_s[-2, 2]
    when /^80[0-9][0-9]/
      service = "SAP ICM HTTP"
    when /^443[0-9][0-9]/
      service = "SAP ICM HTTPS"
    when /^36[0-9][0-9]/
      service = "SAP Message Server sapms<SID>" + port.to_s[-2, 2]
    when /^81[0-9][0-9]/
      service = "SAP Message Server [HTTP]"
    when /^444[0-9][0-9]/
      service = "SAP Message Server [HTTPS]"
    when /^5[0-9][0-9]00/
      service = "SAP JAVA EE Dispatcher [HTTP]"
    when /^5[0-9][0-9]01/
      service = "SAP JAVA EE Dispatcher [HTTPS]"
    when /^5[0-9][0-9]02/
      service = "SAP JAVA EE Dispatcher [IIOP]"
    when /^5[0-9][0-9]03/
      service = "SAP JAVA EE Dispatcher [IIOP over SSL]"
    when /^5[0-9][0-9]04/
      service = "SAP JAVA EE Dispatcher [P4]"
    when /^5[0-9][0-9]05/
      service = "SAP JAVA EE Dispatcher [P4 over HTTP]"
    when /^5[0-9][0-9]06/
      service = "SAP JAVA EE Dispatcher [P4 over SSL]"
    when /^5[0-9][0-9]07/
      service = "SAP JAVA EE Dispatcher [IIOP]"
    when /^5[0-9][0-9]08$/
      service = "SAP JAVA EE Dispatcher [Telnet]"
    when /^5[0-9][0-9]10/
      service = "SAP JAVA EE Dispatcher [JMS]"
    when /^5[0-9][0-9]16/
      service = "SAP JAVA Enq. Replication"
    when /^5[0-9][0-9]13/
      service = "SAP StartService [SOAP] sapctrl" + port.to_s[1, 2]
    when /^5[0-9][0-9]14/
      service = "SAP StartService [SOAP over SSL] sapctrl" + port.to_s[1, 2]
    when /^5[0-9][0-9]1(7|8|9)/
      service = "SAP Software Deployment Manager"
    when /^2121(2|3)/
      service = "SAPinst"
    when /^5997(5|6)/
      service = "SAPinst (IBM AS/400 iSeries)"
    when /^42(3|4)(8|9|0|1$)/
      service = "SAP Upgrade"
    when /^515$/
      service = "SAPlpd"
    when /^7(2|5)(00|10|69|70|75$)/
      service = "LiveCache MaxDB (formerly SAP DB)"
    when /^5[0-9][0-9]15/
      service = "DTR - Design Time Repository"
    when /^3909$/
      service = "ITS MM (Mapping Manager) sapvwmm00_<INST>"
    when /^39[0-9][0-9]$/
      service = "ITS AGate sapavw00_<INST>"
    when /^4[0-9][0-9]00/
      service = "IGS Multiplexer"
    when /^8200$/
      service = "XI JMS/JDBC/File Adapter"
    when /^8210$/
      service = "XI JMS Adapter"
    when /^8220$/
      service = "XI JDBC Adapter"
    when /^8230$/
      service = "XI File Adapter"
    when /^4363$/
      service = "IPC Dispatcher"
    when /^4444$/
      service = "IPC Dispatcher"
    when /^4445$/
      service = "IPC Data Loader"
    when /^9999$/
      service = "IPC Server"
    when /^3[0-9][0-9](0|1)(1|2|3|4|5|6|7|8$)/
      service = "SAP Software Deployment Manager"
    when /^2000(3|4|5|6|7$)/
      service = "MDM (Master Data Management)"
    when /^3159(6|7$)/
      service = "MDM (Master Data Management)"
    when /^3160(2|3|4$)/
      service = "MDM (Master Data Management)"
    when /^200(0|1|2$)/
      service = "MDM Server (Master Data Management)"
    when /^83(5|6)(1|2|3|5|6|7$)/
      service = "MDM Server (Master Data Management)"
    when /^109(0|5$)/
      service = "Content Server / Cache Server"
    when /^20201$/
      service = "CRM - Central Software Deployment Manager"
    when /^10(8|9)9$/
      service = "PAW - Performance Assessment Workbench"
    else
      service = ''
    end

  end

  def parse_response_packet(response, ip, port)

    #vprint_error("#{ip}:#{port} - response packet: #{response}")

    case response
    when /NI_RTERR/
      case response
      when /timed out/
        vprint_error ("#{ip}:#{port} - connection timed out")
      when /refused/
        vprint_error("#{ip}:#{port} - TCP closed")
        return [ip, port, "closed", sap_port_info(port)]
      when /denied/
        vprint_error("#{ip}:#{port} - blocked by ACL")
      when /invalid/
        vprint_error("#{ip}:#{port} - invalid route")
      when /reacheable/
        vprint_error("#{ip}:#{port} - unreachable")
      when /hostname '#{ip}' unknown/
        vprint_error("#{ip}:#{port} - unknown host")
      when /GetHostByName: '#{ip}' not found/
        vprint_error("#{ip}:#{port} - unknown host")
      when /connection to .* timed out/
        vprint_error("#{ip}:#{port} - connection timed out")
      when /partner .* not reached/
        vprint_error("#{ip}:#{port} - host unreachable")
      else
        vprint_error("#{ip}:#{port} - unknown error message")
      end
    when /NI_PONG/
      vprint_good("#{ip}:#{port} - TCP OPEN")
      return [ip, port, "open", sap_port_info(port)]
    else
      vprint_error("#{ip}:#{port} - unknown response")
    end

    return nil
  end

  def run
    if datastore['RESOLVE'] == 'remote'
        datastore['RHOSTS'].split(/,/).each do |host|
          run_host(host)
        end
    else
    # resolve IP or crack IP range
    ip_list = Rex::Socket::RangeWalker.new(datastore['RHOSTS'])
    ip_list.each do |ip|
        run_host(ip)
      end
    end
  end

  def run_host(ip)

    sap_host = datastore['SAPROUTER_HOST']
    sap_port = datastore['SAPROUTER_PORT']

    ports = datastore['PORTS']

    # if port definition has NN then we require INSTANCES
    if ports.include? 'NN' and datastore['INSTANCES'].nil?
      print_error('Error: No instances specified')
      return
    end

    ports = build_sap_ports(ports)

    if ports.empty?
      print_error('Error: No valid ports specified')
      return
    end

    print_status("Scanning #{ip}")
    thread = []
    r = []

    begin
      ports.each do |port|

        if thread.length >= datastore['CONCURRENCY']
          # Assume the first thread will be among the earliest to finish
          thread.first.join
        end
        thread << framework.threads.spawn("Module(#{self.refname})-#{ip}:#{port}", false) do

          begin
            # create ni_packet to send to saprouter
            routes = {sap_host => sap_port, ip => port}
            ni_packet = build_ni_packet(routes)

            s = connect(false,
              {
                'RPORT' => sap_port,
                'RHOST' => sap_host
              }
            )

            s.write(ni_packet, ni_packet.length)
            response = s.get()

            res = parse_response_packet(response, ip, port)
            if res
              r << res
            end

          rescue ::Rex::ConnectionRefused
            print_error("#{ip}:#{port} - Unable to connect to SAPRouter #{sap_host}:#{sap_port} - Connection Refused")

          rescue ::Rex::ConnectionError, ::IOError, ::Timeout::Error
          rescue ::Rex::Post::Meterpreter::RequestError
          rescue ::Interrupt
            raise $!
          ensure
            disconnect(s) rescue nil
          end
        end
      end
      thread.each { |x| x.join }

    rescue ::Timeout::Error
    ensure
      thread.each { |x| x.kill rescue nil }
    end

    tbl = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Header' => "Portscan Results",
      'Prefix' => "\n",
      'Postfix' => "\n",
      'Indent' => 1,
      'Columns' =>
        [
          "Host",
          "Port",
          "State",
          "Info",
        ])

    r.each do |res|
      tbl << [res[0], res[1], res[2], res[3]]
      # we can't report if resolution is remote, since host is unknown locally

      if datastore['RESOLVE'] == 'local'
         report_service(:host => res[0], :port => res[1], :state => res[2])
      end
    end

    print_warning("Warning: Service info could be innacurated")
    print(tbl.to_s)

  end

end
