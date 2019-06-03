##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/hardware/automotive/uds'

class MetasploitModule < Msf::Post
  include Msf::Post::Hardware::Automotive::UDS

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Scan CAN Bus for Diagnostic Modules',
        'Description'   => %q{ Post Module to scan the CAN bus for any modules that can respond to UDS DSC queries},
        'License'       => MSF_LICENSE,
        'Author'        => ['Craig Smith'],
        'Platform'      => ['hardware'],
        'SessionTypes'  => ['hwbridge']
      ))
    register_options([
      OptInt.new('STARTID', [true, "Start scan from this ID", 0x600]),
      OptInt.new('ENDID', [true, "End scan at this ID", 0x7F7]),
      OptString.new('CANBUS', [false, "CAN Bus to perform scan on, defaults to connected bus", nil])
    ])
    @found_id = []
  end

  def run
    scanned_ids = 0
    print_line("Starting scan...")
    (datastore['STARTID']..datastore['ENDID']).each do |id|
      res = set_dsc(datastore['CANBUS'], id, id + 8, 1)
      scanned_ids += 1
      next if res.nil?
      next unless res.key? "Packets"
      next unless res["Packets"].empty?
      if (res["Packets"][0].key? "DATA") && res["Packets"][0]["DATA"].size > 3
        if res["Packets"][0]["DATA"][0].hex == 3 && res["Packets"][0]["DATA"][1].hex == 0x7f && res["Packets"][0]["DATA"][2].hex == 0x10
          print_status("Identified module #{"%3x" % id}")
          @found_id << id
        end
      end
    end
    print_line("Scanned #{scanned_ids} IDs and found #{@found_id.size} modules that responded")
    @found_id.each do |id|
      print_line("  #{"%3x" % id}")
    end
  end
end
