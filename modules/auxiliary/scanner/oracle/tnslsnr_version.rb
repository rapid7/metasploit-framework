##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::TNS

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle TNS Listener Service Version Query',
      'Description'    => %q{
        This module simply queries the tnslsnr service for the Oracle build.
      },
      'Author'         => ['CG'],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'Jan 7 2009'))

    register_options(
      [
        Opt::RPORT(1521)
      ])

    deregister_options('RHOST')
  end

  def run_host(ip)
    begin
      connect

      pkt = tns_packet("(CONNECT_DATA=(COMMAND=VERSION))")

      sock.put(pkt)

      select(nil,nil,nil,0.5)

      data = sock.get_once

        if ( data && data =~ /\\*.TNSLSNR for (.*)/ )
          ora_version = data.match(/\\*.TNSLSNR for (.*)/)[1]
          report_service(
            :host => ip,
            :port => datastore['RPORT'],
            :name => "oracle",
            :info => ora_version
          )
          print_good("#{ip}:#{datastore['RPORT']} Oracle - Version: " + ora_version)
        elsif ( data && data =~ /\(ERR=(\d+)\)/ )
          case $1.to_i
          when 1189
            print_error( "#{ip}:#{datastore['RPORT']} Oracle - Version: Unknown - Error code #{$1} - The listener could not authenticate the user")
          else
            print_error( "#{ip}:#{datastore['RPORT']} Oracle - Version: Unknown - Error code #{$1}")
          end
        else
          print_error( "#{ip}:#{datastore['RPORT']} Oracle - Version: Unknown")
        end
      disconnect
    rescue ::Rex::ConnectionError
    rescue ::Errno::EPIPE
    end
  end
end
