##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Module to Probe Different Data Points in a CAN Packet',
        'Description'   => %q{
                               Scans between two CAN IDs and writes data at each byte position. It will
                               either write a set byte value (Default 0xFF) or iterate through all possible values
                               of that byte position (takes much longer). Does not check for responses and is
                               basically a simple blind fuzzer.
        },
        'License'       => MSF_LICENSE,
        'Author'        => ['Craig Smith'],
        'Platform'      => ['hardware'],
        'SessionTypes'  => ['hwbridge']
      ))
    register_options([
      OptInt.new('STARTID', [false, "CAN ID to start scan", 0x300]),
      OptInt.new('STOPID', [false, "CAN ID to stop scan", nil]),
      OptInt.new('PROBEVALUE', [false, "Value to inject in the data stream", 0xFF]),
      OptInt.new('PADDING', [false, "If a value is given a full 8 bytes will be used and padded with this value", nil]),
      OptBool.new('FUZZ', [false, "If true interates through all possible values for each data position", false]),
      OptString.new('CANBUS', [false, "CAN Bus to perform scan on, defaults to connected bus", nil])
    ])
  end

  def run
    unless client.automotive
      print_error("The hwbridge requires a functional automotive extention")
      return
    end
    stopid = datastore['STARTID']
    stopid = datastore['STOPID'] unless datastore['STOPID'].nil?
    data = "%02X" % datastore['PROBEVALUE']
    (datastore['STARTID']..stopid).each do |id|
      print_status("Probing 0x#{id.to_s(16)}...")
      (0..7).each do |pos|
        padding = "00" * pos
        endpadding = ""
        endpadding = ("%02X" % datastore['PADDING']) * (7-pos) if not datastore['PADDING'].nil?
        if datastore['FUZZ'] then
          (0..255).each do |fuzzdata|
            client.automotive.cansend(datastore['CANBUS'], id.to_s(16), padding + ("%02X" % fuzzdata) + endpadding)
          end
        else
          client.automotive.cansend(datastore['CANBUS'], id.to_s(16), padding + data + endpadding)
        end
      end
    end
    print_status("Probe Complete")
  end
end
