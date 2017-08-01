##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::RealPort
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Digi RealPort Serial Server Version',
      'Description' => 'Detect serial servers that speak the RealPort protocol.',
      'References'  =>
        [
          ['URL', 'http://www.digi.com/pdf/fs_realport.pdf'],
          ['URL', 'http://www.digi.com/support/productdetail?pid=2229&type=drivers']
        ],
      'Author'      =>
        [
          'hdm'
        ],
      'License'     => MSF_LICENSE
    )
  end

  def run_host(target_host)
    if realport_connect
      info = "#{@realport_name} ( ports: #{@realport_port_count} )"
      print_good("#{target_host}:#{rport} #{info}")
      report_service(:host => rhost, :port => rport, :name => "realport", :info => info)
    end
    realport_disconnect
  end
end
