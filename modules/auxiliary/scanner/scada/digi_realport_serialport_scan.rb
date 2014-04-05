##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::RealPort
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Digi RealPort Serial Server Port Scanner',
      'Description' => 'Identify active ports on RealPort-enabled serial servers.',
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

    register_options(
      [
        OptInt.new("BANNER_TIMEOUT", [true, "How long to capture data from the serial port", 5]),
        OptString.new('BAUD_RATES', [true, "A space delimited list of baud rates to try for each port", "9600 115200"]),
        OptString.new('PORTS', [true, "A space delimited list of 1-indexed serial port numbers to try, default is all supported", "ALL"])
      ], self.class)
  end

  def setup
    test_speeds = datastore['BAUD_RATES'].split(/\s+/)
    test_speeds.each do |baud|
      valid = realport_baud_to_speed(baud)
      if not valid
        raise RuntimeError, "The baud rate #{baud} is not supported"
      end
    end
  end

  def run_host(target_host)
    test_ports  = datastore['PORTS'].upcase.split(/\s+/)
    test_speeds = datastore['BAUD_RATES'].split(/\s+/)

    return unless realport_connect

    info = "#{@realport_name} ( ports: #{@realport_port_count} )"
    vprint_status("#{target_host}:#{rport} is running #{info}")
    report_service(:host => rhost, :port => rport, :name => "realport", :info => info)

    1.upto(@realport_port_count) do |pnum|
      unless test_ports.include?('ALL') or test_ports.include?(pnum.to_s)
        # Skip this port
        next
      end

      test_speeds.each do |baud|
        ret = realport_open(pnum - 1, baud)
        break unless ret == :open
        res = realport_recv_banner(pnum - 1, datastore['BANNER_TIMEOUT'])
        if res and res.length > 0
          print_status("#{target_host}:#{rport} [port #{pnum} @ #{baud}bps] #{res.inspect}")
          report_note(
            :host   => target_host,
            :proto  => 'tcp',
            :port   => rport,
            :type   => "realport.port#{pnum}.banner",
            :data   => {:baud => baud, :banner => res},
            :update => :unique_data
          )

        end
        realport_close(pnum - 1)
      end
    end

    realport_disconnect
  end

end
