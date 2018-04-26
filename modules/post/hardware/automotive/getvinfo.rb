##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/hardware/automotive/uds'

class MetasploitModule < Msf::Post
  include Msf::Post::Hardware::Automotive::UDS
  include Msf::Post::Hardware::Automotive::DTC

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Get the Vehicle Information Such as the VIN from the Target Module',
        'Description'   => %q{ Post Module to query DTCs, Some common engine info and Vehicle Info.
                               It returns such things as engine speed, coolant temp, Diagnostic
                               Trouble Codes as well as All info stored by Mode $09 Vehicle Info, VIN, etc},
        'License'       => MSF_LICENSE,
        'Author'        => ['Craig Smith'],
        'Platform'      => ['hardware'],
        'SessionTypes'  => ['hwbridge']
      ))
    register_options([
      OptInt.new('SRCID', [true, "Module ID to query", 0x7e0]),
      OptInt.new('DSTID', [false, "Expected reponse ID, defaults to SRCID + 8", 0x7e8]),
      OptInt.new('PADDING', [false, "Optinal end of packet padding", nil]),
      OptBool.new('FC', [false, "Optinal forces flow control", nil]),
      OptBool.new('CLEAR_DTCS', [false, "Clear any DTCs and reset MIL if errors are present", false]),
      OptString.new('CANBUS', [false, "CAN Bus to perform scan on, defaults to connected bus", nil])
    ])

  end

  def run
    opt = {}
    opt['PADDING'] = datastore["PADDING"] if datastore["PADDING"]
    opt['FC'] = datastore['FC'] if datastore['FC']
    pids = get_current_data_pids(datastore["CANBUS"], datastore["SRCID"], datastore["DSTID"], opt)
    if pids.size == 0
      print_status("No reported PIDs. You may not be properly connected")
    else
      print_status("Available PIDS for pulling realtime data: #{pids.size} pids")
      print_status("  #{pids.inspect}")
    end
    if pids.include? 1
      data = get_monitor_status(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], opt)
      print_status("  MIL (Engine Light) : #{data['MIL'] ? 'ON' : 'OFF'}") if data.key? "MIL"
      print_status("  Number of DTCs: #{data['DTC_COUNT']}") if data.key? "DTC_COUNT"
    end
    if pids.include? 5
      data = get_engine_coolant_temp(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], opt)
      print_status("  Engine Temp: #{data['TEMP_C']} \u00b0C / #{data['TEMP_F']} \u00b0F") if data.key? "TEMP_C"
    end
    if pids.include? 0x0C
      data = get_rpms(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], opt)
      print_status("  RPMS: #{data['RPM']}") if data.key? "RPM"
    end
    if pids.include? 0x0D
      data = get_vehicle_speed(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], opt)
      print_status("  Speed: #{data['SPEED_K']} km/h  /  #{data['SPEED_M']} mph") if data.key? "SPEED_K"
    end
    if pids.include? 0x1C
      print_status("Supported OBD Standards: #{get_obd_standards(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], opt)}")
    end
    dtcs = get_dtcs(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], opt)
    unless dtcs.empty?
      print_status("DTCS:")
      dtcs.each do |dtc|
        msg = dtc
        msg += ": #{DTC_CODES[dtc]}" if DTC_CODES.key? dtc
        print_status("  #{msg}")
      end
    end
    frozen_dtcs = get_frozen_dtcs(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], opt)
    unless frozen_dtcs.empty?
      print_status("Frozen DTCS:")
      frozen_dtcs.each do |dtc|
        msg = dtc
        msg += ": #{DTC_CODES[dtc]}" if DTC_CODES.key? dtc
        print_status("  #{msg}")
      end
    end
    pids = get_vinfo_supported_pids(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], opt)
    print_status("Mode $09 Vehicle Info Supported PIDS: #{pids.inspect}") if pids.size > 0
    pids.each do |pid|
      # Handle known pids
      if pid == 2
        vin = get_vin(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], opt)
        print_status("VIN: #{vin}")
      elsif pid == 4
        calid = get_calibration_id(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], opt)
        print_status("Calibration ID: #{calid}")
      elsif pid == 0x0A
        ecuname = get_ecu_name(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], opt)
        print_status("ECU Name: #{ecuname}")
      else
        data = get_vehicle_info(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], pid, opt)
        data = response_hash_to_data_array(datastore['DSTID'].to_s(16), data)
        print_status("PID #{pid} Response: #{data.inspect}")
      end
    end
    if datastore['CLEAR_DTCS'] == true
      clear_dtcs(datastore['CANBUS'], datastore['SRCID'], datastore['DSTID'], opt)
      print_status("Cleared DTCs and reseting MIL")
    end
  end
end
