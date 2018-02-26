# -*- coding: binary -*-
module Msf
class Post
module Hardware
module Automotive

module UDS

  #
  # Helper method to take client.automotive response hashes and return a single array in order, This
  # takes the ISO-TP Packets and assembles them in order, strips out the ISO-TP/UDS related info
  # and returns just the data section as an array
  #
  # @param id [String] Hex value as string. Example: 7e0
  # @param hash [Hash] Hash that includes "Packets" => [ { "ID" => "0xXXX", "DATA => [ "XX", "XX" ] } ]
  # @param start_offset [Integer] First packet start offset after meta data
  #
  # @return [Array] Just the data portion of an ISO-TP response represented as Hex Strings
  #
  def response_hash_to_data_array(id, hash, start_offset = 5)
    data = []
    return data unless hash
    bad_count = 0
    if hash.key? "Packets"
      unless hash["Packets"].size > 1 # Not multiple packets
        pktdata = hash["Packets"][0]["DATA"]
        if pktdata[1] == 0x7F
          print_line("Packet response was an error")
        else
          data = pktdata[3, pktdata.size-1]
        end
        return data
      end
      left2combine = hash["Packets"].size
      counter = 0
      while left2combine > 0 && (bad_count < (hash["Packets"].size * 2))
        # print_line("DEBUG Current status combine=#{left2combine} data=#{data.inspect}")
        hash["Packets"].each do |pkt|
          if (pkt.key? "ID") && pkt["ID"].hex == id.hex
            if pkt.key? "DATA"
              if counter.zero?  # Get starting packet
                if pkt["DATA"][0] == "10"
                  data += pkt["DATA"][start_offset, 8 - start_offset]
                  left2combine -= 1
                  counter += 1
                else
                  bad_count += 1
                end
              else # Got the first packet, get the 2x series
                # TODO: Support rollover counter, rare but technically possible
                if pkt["DATA"][0] == "%02x" % (0x20 + counter)
                  data += pkt["DATA"][1, pkt["DATA"].size]
                  left2combine -= 1
                  counter += 1
                else
                  bad_count += 1
                end
              end
            end
          end
        end
      end
      if bad_count >= (hash["Packets"].size * 2)
        print_error("bad packet count exceeded normal limits.  Packet parser failed")
      end
    end
    data
  end

  ### Mode $01 ###

  #
  # Shows the vehicles current data
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param pid [Integer] Integer of the PID to get data about
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [Hash] client.automotive response
  def get_current_data(bus, src_id, dst_id, pid, opt = {})
    unless client.automotive
      print_error("Not an automotive hwbridge session")
      return {}
    end
    src_id = src_id.to_s(16)
    dst_id = dst_id.to_s(16)
    bus = client.automotive.active_bus unless bus
    unless bus
      print_line("No active bus, use 'connect' or specify bus via the options")
      return {}
    end
    client.automotive.send_isotp_and_wait_for_response(bus, src_id, dst_id, [0x01, pid], opt)
  end

  #
  # Get all supported pids for current data
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [Array] All supported pids from Mode $01 get current data
  def get_current_data_pids(bus, src_id, dst_id, opt={})
    pids = []
    opt['MAXPKTS'] = 1
    packets = get_current_data(bus, src_id, dst_id, 0, opt)
    return pids if packets.nil?
    if (packets.key? "Packets") && !packets["Packets"].empty?
      hexpids = packets["Packets"][0]["DATA"][3, 6]
      hexpids = hexpids.join.hex.to_s(2).rjust(32, '0').split('') # Array of 1s and 0s
      (1..0x20).each do |pid|
        pids << pid if hexpids[pid-1] == "1"
      end
    end
    if pids.include? 0x20
      packets = get_current_data(bus, src_id, dst_id, 0x20, opt)
      if (packets.key? "Packets") && !packets["Packets"].empty?
        hexpids = packets["Packets"][0]["DATA"][3, 6]
        hexpids = hexpids.join.hex.to_s(2).rjust(32, '0').split('') # Array of 1s and 0s
        (0x20..0x40).each do |pid|
          pids << pid if hexpids[pid-0x21] == "1"
        end
      end
    end
    if pids.include? 0x40
      packets = get_current_data(bus, src_id, dst_id, 0x40, opt)
      if (packets.key? "Packets") && !packets["Packets"].empty?
        hexpids = packets["Packets"][0]["DATA"][3, 6]
        hexpids = hexpids.join.hex.to_s(2).rjust(32, '0').split('') # Array of 1s and 0s
        (0x40..0x60).each do |pid|
          pids << pid if hexpids[pid-0x41] == "1"
        end
      end
    end
    if pids.include? 0x60
      packets = get_current_data(bus, src_id, dst_id, 0x60, opt)
      if (packets.key? "Packets") && !packets["Packets"].empty?
        hexpids = packets["Packets"][0]["DATA"][3, 6]
        hexpids = hexpids.join.hex.to_s(2).rjust(32, '0').split('') # Array of 1s and 0s
        (0x60..0x80).each do |pid|
          pids << pid if hexpids[pid-0x61] == "1"
        end
      end
    end
    if pids.include? 0x80
      packets = get_current_data(bus, src_id, dst_id, 0x80, opt)
      if (packets.key? "Packets") && !packets["Packets"].empty?
        hexpids = packets["Packets"][0]["DATA"][3, 6]
        hexpids = hexpids.join.hex.to_s(2).rjust(32, '0').split('') # Array of 1s and 0s
        (0x80..0xA0).each do |pid|
          pids << pid if hexpids[pid-0x81] == "1"
        end
      end
    end
    if pids.include? 0xA0
      packets = get_current_data(bus, src_id, dst_id, 0xA0, opt)
      if (packets.key? "Packets") && !packets["Packets"].empty?
        hexpids = packets["Packets"][0]["DATA"][3, 6]
        hexpids = hexpids.join.hex.to_s(2).rjust(32, '0').split('') # Array of 1s and 0s
        (0xA0..0xC0).each do |pid|
          pids << pid if hexpids[pid-0xA1] == "1"
        end
      end
    end
    if pids.include? 0xC0
      packets = get_current_data(bus, src_id, dst_id, 0xC0, opt)
      if (packets.key? "Packets") && !packets["Packets"].empty?
        hexpids = packets["Packets"][0]["DATA"][3, 6]
        hexpids = hexpids.join.hex.to_s(2).rjust(32, '0').split('') # Array of 1s and 0s
        (0xC0..0xE0).each do |pid|
          pids << pid if hexpids[pid - 0xC1] == "1"
        end
      end
    end
    pids
  end

  #
  # Mode $01 Pid $01 gets and parses the monitor status
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [Hash] Packet Hash with { "MIL" => true|false "DTC_COUNT" => 0 }
  def get_monitor_status(bus, src_id, dst_id, opt = {})
    opt['MAXPKTS'] = 1
    packets = get_current_data(bus, src_id, dst_id, 0x01, opt)
    return {} if packets.nil?
    return packets if packets.key? "error"
    return packets unless packets.key? "Packets"
    packets["MIL"] = packets["Packets"][0]["DATA"][3].hex & 0xB0 == 1 ? true : false
    packets["DTC_COUNT"] = packets["Packets"][0]["DATA"][3].hex & 0x7F
    packets
  end

  #
  # Gets the engine coolant temprature in both Celcious and Fahrenheit
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [Hash] Packet Hash with { "TEMP_C" => <Celcious Temp>, "TEMP_F" => <Fahrenheit TEmp> }
  def get_engine_coolant_temp(bus, src_id, dst_id, opt = {})
    opt['MAXPKTS'] = 1
    packets = get_current_data(bus, src_id, dst_id, 0x05, opt)
    return {} if packets.nil?
    return packets if packets.key? "error"
    return packets unless packets.key? "Packets"
    celsius = packets["Packets"][0]["DATA"][3].hex - 40
    fahrenheit = celsius * 9 / 5 + 32
    packets["TEMP_C"] = celsius
    packets["TEMP_F"] = fahrenheit
    packets
  end

  #
  # Gets the engine's current RPMs
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [Hash] Packet Hash with { "RPM" => <RPMs> }
  def get_rpms(bus, src_id, dst_id, opt = {})
    opt['MAXPKTS'] = 1
    packets = get_current_data(bus, src_id, dst_id, 0x0C, opt)
    return {} if packets.nil?
    return packets if packets.key? "error"
    return packets unless packets.key? "Packets"
    packets["RPM"] = (256 * packets["Packets"][0]["DATA"][3].hex + packets["Packets"][0]["DATA"][4].hex) / 4
    packets
  end

  #
  # Gets the engine's current vehicle speed in km/h and mph
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [Hash] Packet Hash with { "SPEED_K" => <km/h>, "SPEED_M" => <mph> }
  def get_vehicle_speed(bus, src_id, dst_id, opt = {})
    opt['MAXPKTS'] = 1
    packets = get_current_data(bus, src_id, dst_id, 0x0D, opt)
    return {} if packets.nil?
    return packets if packets.key? "error"
    return packets unless packets.key? "Packets"
    packets["SPEED_K"] = packets["Packets"][0]["DATA"][3].hex
    packets["SPEED_M"] = packets["SPEED_K"] / 1.609344
    packets
  end

  #
  # Return which OBD standard this bus confirms to.  This method could utilizes bitmasks
  # but currently creates a human readable string instead.  This may change in the future.
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [String] Description of standard
  def get_obd_standards(bus, src_id, dst_id, opt = {})
    opt['MAXPKTS'] = 1
    packets = get_current_data(bus, src_id, dst_id, 0x1C, opt)
    return "" if packets.nil?
    if packets.key? "error"
      print_error("OBD ERR: #{packets['error']}")
      return ""
    end
    return "" unless packets.key? "Packets"
    case packets["Packets"][0]["DATA"][3].hex
    when 1
      return "OBD-II as defined by CARB"
    when 2
      return "OBD as defined by EPA"
    when 3
      return "OBD and OBD-II"
    when 4
      return "OBD-I"
    when 5
      return "Not OBD Compliant"
    when 6
      return "EOBD Europe"
    when 7
      return "EOBD and OBD-II"
    when 8
      return "EOBD and OBD"
    when 9
      return "EOBD, OBD, OBD-II"
    when 10
      return "JOBD Japan"
    when 11
      return "JOBD and OBD-II"
    when 12
      return "JOBD and EOBD"
    when 13
      return "JOBD, EOBD, OBD-II"
    when 17
      return "Engine Manufacturer Diagnostics (EMD)"
    when 18
      return "Engine Manufacturer Diagnostics Enhanced (EMD+)"
    when 19
      return "Heavy Duty On-Board Diagnostics (Child/Partial) (HD OBD-C)"
    when 20
      return "Heavy Duty On-Board Diagnostics (HD OBD)"
    when 21
      return "World Wide Harmonized OBD (WWH OBD)"
    when 23
      return "Heavy Duty Euro OBD Stage I without NOx control (HD EOBD-I)"
    when 24
      return "Heavy Duty Euro OBD Stage I with NOx control (HD EOBD-I N)"
    when 25
      return "Heavy Duty Euro OBD Stage II without NOx control (HD EOBD-II)"
    when 26
      return "Heavy Duty Euro OBD Stage II with NOx control (HD EOBD-II N)"
    when 28
      return "Brazil OBD Phase 1 (OBDBr-1)"
    when 29
      return "Brazil OBD Phase 2 (OBDBr-2)"
    when 30
      return "Korean OBD (KOBD)"
    when 31
      return "India OBD I (IOBD I)"
    when 32
      return "India OBD II (IOBD II)"
    when 33
      return "Heavy Duty Euro OBD Stage VI (HD EOBD-IV)"
    when 14..16, 22, 27, 34..250
      return "Reserved"
    end
    "SAE J1939 Special Meanings"
  end

  ### Mode $02 ###

  #
  # Shows the vehicles freeze frame data, Use the same PIDs as supported from Mode $01
  # #get_current_data_pids.  You must specify which freeze frame you want to recall data from.
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param pid [Integer] Integer of the PID to get data about
  # @param frame [Integer] Freeze Frame Number
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [Hash] client.automotive response
  def get_freeze_frame_data(bus, src_id, dst_id, pid, frame, opt = {})
    unless client.automotive
      print_error("Not an automotive hwbridge session")
      return {}
    end
    src_id = src_id.to_s(16)
    dst_id = dst_id.to_s(16)
    bus = client.automotive.active_bus unless bus
    pid = pid.to_s(16)
    frame = frame.to_s(16)
    unless bus
      print_line("No active bus, use 'connect' or specify bus via the options")
      return {}
    end
    client.automotive.send_isotp_and_wait_for_response(bus, src_id, dst_id, [0x02, pid, frame], opt)
  end

  ### Mode $03 ###

  #
  # Retrieves the Diagnostic Trouble Codes (DTCs)
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [Array] Array of DTCs
  def get_dtcs(bus, src_id, dst_id, opt = {})
    dtcs = []
    unless client.automotive
      print_error("Not an automotive hwbridge session")
      return {}
    end
    src_id = src_id.to_s(16)
    dst_id = dst_id.to_s(16)
    bus = client.automotive.active_bus unless bus
    unless bus
      print_line("No active bus, use 'connect' or specify bus via the options")
      return {}
    end
    data = client.automotive.send_isotp_and_wait_for_response(bus, src_id, dst_id, [0x03], opt)
    return [] if data.nil?
    if data.key? "error"
      print_error("UDS ERR: #{data['error']}")
      return []
    end
    if (data.key? "Packets") && !data["Packets"].empty?
      data = response_hash_to_data_array(dst_id, data, 4)
      if !data.empty? && data.size.even?
        (0..data.size / 2).step(2) do |idx|
          code = ""
          case data[idx].hex & 0xC0 >> 3
          when 0
            code = "P"
          when 1
            code = "C"
          when 2
            code = "B"
          when 3
            code = "U"
          end
          code += (data[idx].hex & 0x3F).to_s(16).rjust(2, '0')
          code += data[idx + 1]
          dtcs << code
        end
      end
    end
    dtcs
  end

  ### Mode $04 ###

  #
  # Clears the DTCs and Resets the MIL light back to the off position
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [Hash] No packets are expected to return but an error could be returned
  def clear_dtcs(bus, src_id, dst_id, opt = {})
    unless client.automotive
      print_error("Not an automotive hwbridge session")
      return {}
    end
    src_id = src_id.to_s(16)
    dst_id = dst_id.to_s(16)
    bus = client.automotive.active_bus unless bus
    unless bus
      print_line("No active bus, use 'connect' or specify bus via the options")
      return {}
    end
    client.automotive.send_isotp_and_wait_for_response(bus, src_id, dst_id, [0x04], opt)
  end

  ### Mode $07 ###

  #
  # Retrieves the Frozen Diagnostic Trouble Codes (DTCs)
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [Array] Array of DTCs
  def get_frozen_dtcs(bus, src_id, dst_id, opt = {})
    dtcs = []
    unless client.automotive
      print_error("Not an automotive hwbridge session")
      return {}
    end
    src_id = src_id.to_s(16)
    dst_id = dst_id.to_s(16)
    bus = client.automotive.active_bus unless bus
    unless bus
      print_line("No active bus, use 'connect' or specify bus via the options")
      return {}
    end
    data = client.automotive.send_isotp_and_wait_for_response(bus, src_id, dst_id, [0x07], opt)
    return [] if data.nil?
    if data.key? "error"
      print_error("UDS ERR: #{data['error']}")
      return []
    end
    if (data.key? "Packets") && !data["Packets"].empty?
      data = response_hash_to_data_array(dst_id, data, 4)
      if !data.empty? && data.size.even?
        (0..data.size / 2).step(2) do |idx|
          code = ""
          case data[idx].hex & 0xC0 >> 3
          when 0
            code = "P"
          when 1
            code = "C"
          when 2
            code = "B"
          when 3
            code = "U"
          end
          code += (data[idx].hex & 0x3F).to_s(16).rjust(2, '0')
          code += data[idx + 1]
          dtcs << code
        end
      end
    end
    dtcs
  end

  ### Mode  $09 ###

  #
  # Requests diagnostics 0x09 vehicle information for any given mode
  # No formatting is done on the response
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [Hash] client.automotive response
  def get_vehicle_info(bus, src_id, dst_id, mode, opt = {})
    unless client.automotive
      print_error("Not an automotive hwbridge session")
      return {}
    end
    src_id = src_id.to_s(16)
    dst_id = dst_id.to_s(16)
    bus = client.automotive.active_bus unless bus
    mode = mode.to_s(16)
    unless bus
      print_line("No active bus, use 'connect' or specify bus via the options")
      return {}
    end
    client.automotive.send_isotp_and_wait_for_response(bus, src_id, dst_id, [0x09, mode], opt)
  end

  #
  # Get all the supported pids by mode 0x09 Vehicle info
  # Returns them as an array of ints
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [Array] Array of PIDS supported by Mode $09
  def get_vinfo_supported_pids(bus, src_id, dst_id, opt = {})
    opt['MAXPKTS'] = 1
    pids = []
    packets = get_vehicle_info(bus, src_id, dst_id, 0, opt)
    return pids if packets.nil?
    if (packets.key? "Packets") && !packets["Packets"].empty?
      unless packets["Packets"][0]["DATA"][1].hex == 0x49
        print_error("ECU Did not return a valid response")
        return []
      end
      hexpids = packets["Packets"][0]["DATA"][3, 6]
      hexpids = hexpids.join.hex.to_s(2).rjust(32, '0').split('') # Array of 1s and 0s
      (1..20).each do |pid|
        pids << pid if hexpids[pid - 1] == "1"
      end
    end
    pids
  end

  #
  # Requests a VIN and formats the response as ASCII
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [String] VIN as ASCII
  def get_vin(bus, src_id, dst_id, opt = {})
    packets = get_vehicle_info(bus, src_id, dst_id, 0x02, opt)
    return "" if packets.nil?
    return "UDS ERR: #{packets['error']}" if packets.key? "error"
    data = response_hash_to_data_array(dst_id.to_s(16), packets)
    return "" if data.nil?
    data.map! { |d| d.hex.chr }
    data.join
  end

  # Gets the vehicle calibration ID and returns it as an ASCII string
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [String] Calibration ID as ASCII
  def get_calibration_id(bus, src_id, dst_id, opt = {})
    packets = get_vehicle_info(bus, src_id, dst_id, 0x04, opt)
    return "" if packets.nil?
    return "UDS ERR: #{packets['error']}" if packets.key? "error"
    data = response_hash_to_data_array(dst_id.to_s(16), packets)
    return "" if data.nil?
    data.map! { |d| d.hex.chr }
    data.join
  end

  # Get the vehicles ECU name pid 0x0A
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [String] ECU Name as ASCII
  def get_ecu_name(bus, src_id, dst_id, opt = {})
    packets = get_vehicle_info(bus, src_id, dst_id, 0x0A, opt)
    return "" if packets.nil?
    return "UDS ERR: #{packets['error']}" if packets.key? "error"
    data = response_hash_to_data_array(dst_id.to_s(16), packets)
    return "" if data.nil?
    data.map! { |d| d.hex.chr }
    data.join
  end

  ###############################################################################
  # Technically from here on down these are known as Service IDs or SIDs but we #
  # will keep calling them Modes for consitency in our comments                 #
  ###############################################################################
  #### Mode $10 ###

  # Set the diagnostic session code
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param level [Integer] The desired DSC level
  # @param opt [Hash] Optional arguments.  PADDING if set uses this hex value for padding
  #
  # @return [Hash] client.automtoive response
  def set_dsc(bus, src_id, dst_id, level, opt = {})
    unless client.automotive
      print_error("Not an automotive hwbridge session")
      return {}
    end
    level = level.to_s(16)
    src_id = src_id.to_s(16)
    dst_id = dst_id.to_s(16)
    bus = client.automotive.active_bus unless bus
    unless bus
      print_line("No active bus, use 'connect' or specify bus via the options")
      return {}
    end
    padding = nil
    padding = opt['PADDING'] if opt.key? 'PADDING'
    opt = {}
    opt["TIMEOUT"] = 20
    opt["MAXPKTS"] = 1
    opt["PADDING"] = padding unless padding.nil?
    client.automotive.send_isotp_and_wait_for_response(bus, src_id, dst_id, [0x10, level], opt)
  end

  ### Mode $11 ###

  #
  # Issues a reset of the ECU
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param hard [Boolean] If true a hard reset will be peformed
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [Hash] client.automtoive response (Could be no response)
  def reset_ecu(bus, src_id, dst_id, hard, opt = {})
    unless client.automotive
      print_error("Not an automotive hwbridge session")
      return {}
    end
    src_id = src_id.to_s(16)
    dst_id = dst_id.to_s(16)
    bus = client.automotive.active_bus unless bus
    unless bus
      print_line("No active bus, use 'connect' or specify bus via the options")
      return {}
    end
    reset_type = hard ? 1 : 0
    client.automotive.send_isotp_and_wait_for_response(bus, src_id, dst_id, [0x11, reset_type], opt)
  end

  ### Mode $22 ###

  #
  # Reads data from a memory region given a lookup ID value
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param id [Array] 2 Bytes in an array of the identifier.  Example [ 0xF1, 0x90 ]
  # @param opt [Hash] Additional Options.  SHOW_ERROR (Returns packet hash instead, default false)
  #                                        PADDING if set uses this hex value for padding
  #
  # @return [Array] Data retrieved.  If show_error is true and an error is detected, then packet hash will be returned instead
  def read_data_by_id(bus, src_id, dst_id, id, opt = {})
    data = []
    unless client.automotive
      print_error("Not an automotive hwbridge session")
      return {} if show_error
      return []
    end
    unless id.is_a? Array
      print_error("ID paramater must be a two byte array")
      return {} if show_error
      return []
    end
    unless id.size == 2
      print_error("ID paramater must be a two byte array")
      return {} if show_error
      return []
    end
    src_id = src_id.to_s(16)
    dst_id = dst_id.to_s(16)
    id.map! { |i| i.to_s(16) } if id[0].is_a? Integer
    bus = client.automotive.active_bus unless bus
    unless bus
      print_line("No active bus, use 'connect' or specify bus via the options")
      return {}
    end
    show_error = false
    padding = nil
    show_error = true if opt.key? 'SHOW_ERROR'
    padding = opt['PADDING'] if opt.key? 'PADDING'
    opt = {}
    opt["MAXPKTS"] = 15
    opt["PADDING"] = padding unless padding.nil?
    packets = client.automotive.send_isotp_and_wait_for_response(bus, src_id, dst_id, [0x22] + id, opt)
    return [] if packets.nil?
    if packets.key? "error"
      return packets if show_error
    else
      data = response_hash_to_data_array(dst_id, packets)
      if id.size > 1  # Remove IDs from return
        data = data[(id.size-1)..data.size]
      end
    end
    data
  end

  ### Mode $27 ###

  #
  # Retrieves the security access token
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param level [Integer] Requested security access level. Default is 1
  # @param opt [Hash] Optional settings.  PADDING if set uses this hex value for padding
  #
  # @return [Hash] Packet Hash with { "SEED" => [ XX, XX ] }
  def get_security_token(bus, src_id, dst_id, level = 1, opt = {})
    unless client.automotive
      print_error("Not an automotive hwbridge session")
      return {}
    end
    src_id = src_id.to_s(16)
    dst_id = dst_id.to_s(16)
    level = level.to_s(16)
    bus = client.automotive.active_bus unless bus
    unless bus
      print_line("No active bus, use 'connect' or specify bus via the options")
      return {}
    end
    padding = nil
    padding = opt['PADDING'] if opt.key? 'PADDING'
    opt = {}
    opt["MAXPKTS"] = 2
    opt["PADDING"] = padding unless padding.nil?
    packets = client.automotive.send_isotp_and_wait_for_response(bus, src_id, dst_id, [0x27, level], opt)
    return {} if packets.nil?
    unless packets.key? "error"
      packets["SEED"] = response_hash_to_data_array(dst_id, packets)
    end
    packets
  end

  #
  # Sends a security access tokens response to the seed request
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param key [Array] Array of Hex to be used as the key.  Same size as the seed
  # @param response_level [Integer] Requested security access level response. Usually level + 1. Default is 2
  # @param opt [Hash] Optional settings. PADDING if set uses this hex value for padding
  #
  # @return [Hash] packet response from client.automotoive
  def send_security_token_response(bus, src_id, dst_id, key, response_level = 2, opt = {})
    unless client.automotive
      print_error("Not an automotive hwbridge session")
      return {}
    end
    unless key.is_a? Array
      print_error("Key must be an array of hex values")
      return {}
    end
    src_id = src_id.to_s(16)
    dst_id = dst_id.to_s(16)
    key.map! { |k| k.to_s(16) } if key[0].is_a? Integer
    response_level = response_level.to_s(16)
    bus = client.automotive.active_bus unless bus
    unless bus
      print_line("No active bus, use 'connect' or specify bus via the options")
      return {}
    end
    padding = nil
    padding = opt['PADDING'] if opt.key? 'PADDING'
    opt = {}
    opt["MAXPKTS"] = 2
    opt["PADDING"] = padding unless padding.nil?
    client.automotive.send_isotp_and_wait_for_response(bus, src_id, dst_id, [0x27, response_level] + key, opt)
  end

  ### Mode $2E ###

  #
  # Writes data by ID
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param id [Array] 2 Bytes in an array of the identifier.  Example [ 0xF1, 0x90 ]
  # @param data [Array] Array of bytes to write
  # @param opt [Hash] Optional settings. PADDING if set uses this hex value for padding
  #
  # @return [Hash] Packet hash from client.automotive
  def write_data_by_id(bus, src_id, dst_id, id, data, opt = {})
    unless client.automotive
      print_error("Not an automotive hwbridge session")
      return {}
    end
    unless id.is_a? Array
      print_error("ID must be an array of hex values")
      return {}
    end
    unless data.is_a? Array
      print_error("DATA must be an array of hex values")
      return {}
    end
    src_id = src_id.to_s(16)
    dst_id = dst_id.to_s(16)
    id.map! { |i| i.to_s(16) } if id[0].is_a? Integer
    data.map! { |d| d.to_s(16) } if data[0].is_a? Integer
    bus = client.automotive.active_bus unless bus
    unless bus
      print_line("No active bus, use 'connect' or specify bus via the options")
      return {}
    end
    padding = nil
    padding = opt['PADDING'] if opt.key? 'PADDING'
    opt = {}
    opt["MAXPKTS"] = 1
    opt["PADDING"] = padding unless padding.nil?
    client.automotive.send_isotp_and_wait_for_response(bus, src_id, dst_id, [0x27] + id + data, opt)
  end

  ### Mode $31 ###

  #
  # Executes a builtin routine. Routines are a series of pre-programmed acutions setup by the
  # manufacturer.
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param routine_type [Integer] Type or routine request. Example: 1 = Start, 3 = Report
  # param id [Array] 2 byte Array for the routine identifier
  # @param data [Array] Array of routine data/params. Specific to the routine. Optional, Default []
  # @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
  #
  # @return [Hash] Packet hash from client.automotive
  def routine_control(bus, src_id, dst_id, routine_type, id, data = [], opt = {})
    unless client.automotive
      print_error("Not an automotive hwbridge session")
      return {}
    end
    unless id.is_a? Array
      print_error("ID must be an array of hex values")
      return {}
    end
    unless data.is_a? Array
      print_error("DATA must be an array of hex values")
      return {}
    end
    src_id = src_id.to_s(16)
    dst_id = dst_id.to_s(16)
    routine_type = routine_type.to_s(16)
    id.map! { |i| i.to_s(16) } if id[0].is_a? Integer
    data.map! { |d| d.to_s(16) } if !data.empty? && (data[0].is_a? Integer)
    bus = client.automotive.active_bus unless bus
    unless bus
      print_line("No active bus, use 'connect' or specify bus via the options")
      return {}
    end
    client.automotive.send_isotp_and_wait_for_response(bus, src_id, dst_id, [0x31, routine_type] + id + data, opt)
  end

  ### Mode $3E ###

  #
  # Sends a TestPresent message.  This message maintains previously set DSCs or Security Access levels so
  # they don't timeout and revert back to normal.  TesterPresent is typically transmitted on 2-3 second
  # intervals
  #
  # @param bus [String] unique CAN bus identifier
  # @param src_id [Integer] Integer representation of the Sending CAN ID
  # @param dst_id [Integer] Integer representation of the receiving CAN ID
  # @param opt [Hash] Optional arguments such as: PADDING if set uses this hex value for padding
  #    SUPPRESS_RESPONSE By default suppress ACK from ECU.  Set to false if you want confirmation
  #
  # @return [Hash] Packet hash from client.automotive.  Typically blank unless suppress_response is false
  def send_tester_present(bus, src_id, dst_id, opt = {})
    unless client.automotive
      print_error("Not an automotive hwbridge session")
      return {}
    end
    src_id = src_id.to_s(16)
    dst_id = dst_id.to_s(16)
    bus = client.automotive.active_bus unless bus
    unless bus
      print_line("No active bus, use 'connect' or specify bus via the options")
      return {}
    end
    padding = nil
    suppress = 0x80
    suppress = 0 unless (opt.key? 'SUPRESS_RESPONSE') && opt['SUPRESS_RESPONSE'] == false
    padding = opt['PADDING'] if opt.key? 'PADDING'
    opt = {}
    opt["MAXPKTS"] = 1
    opt["PADDING"] = padding unless padding.nil?
    client.automotive.send_isotp_and_wait_for_response(bus, src_id, dst_id, [0x3E, suppress], opt)
  end

end

end
end
end
end
