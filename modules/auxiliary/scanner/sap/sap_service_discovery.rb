##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner


  def initialize
    super(
      'Name'         => 'SAP Service Discovery',
      'Description'  => %q{ Scans for listening SAP services. },
      'References'   =>
        [
          # General
          [ 'URL', 'http://blog.c22.cc' ]
        ],
      'Author'       => [ 'Chris John Riley' ],
      'License'      => MSF_LICENSE
    )

    register_options(
    [
      OptString.new('INSTANCES', [true, "Instance numbers to scan (e.g. 00-05,00-99)", "00-01"]),
      OptInt.new('TIMEOUT', [true, "The socket connect timeout in milliseconds", 1000]),
      OptInt.new('CONCURRENCY', [true, "The number of concurrent ports to check per host", 10]),
    ], self.class)

    deregister_options('RPORT')
  end

  def run_host(ip)

    timeout = datastore['TIMEOUT'].to_i

    instances = datastore['INSTANCES']

    # Default ports based on SAP "TCP/IP Ports Used by SAP Applications" Document
    # http://www.sdn.sap.com/irj/sdn/go/portal/prtroot/docs/library/uuid/4e515a43-0e01-0010-2da1-9bcc452c280b

    def_ports = [
      '32NN', '33NN', '48NN', '80NN', '36NN', '81NN', '5NN00', '5NN01', '5NN02',
      '5NN03', '5NN04', '5NN05', '5NN06', '5NN07', '5NN08', '5NN10', '5NN16',
      '5NN13', '5NN14', '5NN17', '5NN18', '5NN19', '21212', '21213', '59975',
      '59976', '4238', '4239','4240', '4241', '3299', '3298', '515', '7200',
      '7210', '7269', '7270', '7575', '5NN15', '39NN', '3909', '4NN00', '8200',
      '8210', '8220', '8230', '4363', '4444', '4445', '9999', '3NN01', '3NN02',
      '3NN03', '3NN04', '3NN05', '3NN06', '3NN07', '3NN08', '3NN11', '3NN17',
      '20003', '20004', '20005', '20006', '20007', '31596', '31597', '31602',
      '31601', '31604', '2000', '2001', '2002', '8355', '8357', '8351' ,'8352',
      '8353', '8366', '1090', '1095', '20201', '1099', '1089'
    ]
    ports = []

    # Build ports array from valid instance numbers
    instances.split(/,/).each do |item|
      start, stop = item.split(/-/).map do |p|
        p.to_i
      end

      start ||= 0
      stop ||= item.match(/-/) ? 99 : start
      start, stop = stop, start if stop < start

      start.upto(stop) do |p|
        ports << p
      end

    end

    # Sort, and remove dups and invalid instance numbers (00-99 valid)
    ports.sort.uniq.delete_if do |p|
      p < 00 or p > 99
    end

    final_ports = []

    ports.each do |inst|
      inst = inst.to_s
      if inst.length < 2
        inst = '0' +inst
      end
      def_ports.each do |dport|
        if dport.length < 2
          dport = '0' +dport
        end

        final_ports << dport.gsub("NN", inst)
      end
    end

    ports = final_ports

    if ports.empty?
      print_error("Error: No valid ports specified")
      return
    end

    print_status("[SAP] Beginning service Discovery '#{ip}'\n")

    while(ports.length > 0)
      t = []
      r = []
      begin
        1.upto(datastore['CONCURRENCY']) do
          this_port = ports.shift
          break if not this_port
          t << framework.threads.spawn("Module(#{self.refname})-#{ip}:#{this_port}", false, this_port) do |port|
            begin
              s = connect(false,
                {
                  'RPORT' => port,
                  'RHOST' => ip,
                  'ConnectTimeout' => (timeout / 1000.0)
                })
              #print_status("#{ip}:#{port} - TCP OPEN")
              case port
              when /^3299$/
                service = "SAP Router"
              when /^3298$/
                service =  "SAP niping (Network Test Program)"
              when /^32[0-9][0-9]/
                service = "SAP Dispatcher sapdp" + port.to_s[-2,2]
              when /^33[0-9][0-9]/
                service = "SAP Gateway sapgw" + port.to_s[-2,2]
              when /^48[0-9][0-9]/
                service = "SAP Gateway [SNC] sapgw" + port.to_s[-2,2]
              when /^80[0-9][0-9]/
                service = "SAP ICM HTTP"
              when /^36[0-9][0-9]/
                service = "SAP Message Server sapms<SID>" + port.to_s[-2,2]
              when /^81[0-9][0-9]/
                service = "SAP Message Server [HTTP]"
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
              when /^5[0-9][0-9]08/
                service = "SAP JAVA EE Dispatcher [Telnet]"
              when /^5[0-9][0-9]10/
                service = "SAP JAVA EE Dispatcher [JMS]"
              when /^5[0-9][0-9]16/
                service = "SAP JAVA Enq. Replication"
              when /^5[0-9][0-9]13/
                service = "SAP StartService [SOAP] sapctrl" +port.to_s[1,2]
              when /^5[0-9][0-9]14/
                service = "SAP StartService [SOAP over SSL] sapctrl" +port.to_s[1,2]
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
                service = "Unknown Service"
              end
            print_good("#{ip}:#{port}\t - #{service} OPEN")

=begin
            report_note(:host => "#{ip}",
                  :proto => 'TCP',
                  :port => "#{port}",
                  :type => 'SAP',
                  :data => "#{service}")
=end

            r << [ip,port,"open", service]
            rescue ::Rex::ConnectionRefused
              vprint_status("#{ip}:#{port}\t - TCP closed")
              r << [ip,port,"closed", "service"]
            rescue ::Rex::ConnectionError, ::IOError, ::Timeout::Error
            rescue ::Interrupt
            raise $!
            rescue ::Exception => e
              print_error("#{ip}:#{port} exception #{e.class} #{e} #{e.backtrace}")
            ensure
              disconnect(s) rescue nil
          end
        end
      end
      t.each {|x| x.join }

      rescue ::Timeout::Error
      ensure
        t.each {|x| x.kill rescue nil }
      end

      r.each do |res|
        report_service(:host => res[0], :port => res[1], :state => res[2], :name => res[3])
      end
    end
  end
end
