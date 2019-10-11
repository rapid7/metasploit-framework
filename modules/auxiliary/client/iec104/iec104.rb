##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  #
  # this module sends IEC104 commands
  #

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'IEC104 Client Utility',
      'Description'   => %q(
         This module allows sending 104 commands.
      ),
      'Author'         =>
        [
          'Michael John <mjohn.info[at]gmail.com>'
        ],
      'License'        => MSF_LICENSE,
      'Actions'        =>
      [
        ['SEND_COMMAND', { 'Description' => 'Send command to device' }]
      ],
      'DefaultAction' => 'SEND_COMMAND'))

    register_options(
      [
        Opt::RPORT(2404),
        OptInt.new('ORIGINATOR_ADDRESS', [true, "Originator Address", 0]),
        OptInt.new('ASDU_ADDRESS', [true, "Common Address of ASDU", 1]),
        OptInt.new('COMMAND_ADDRESS', [true, "Command Address / IOA Address", 0]),
        OptInt.new('COMMAND_TYPE', [true, "Command Type", 100]),
        OptInt.new('COMMAND_VALUE', [true, "Command Value", 20])
      ]
    )
  end

  # sends the frame data over tcp connection and returns received string
  # using sock.get is causing quite some delay, but scripte needs to process responses from 104 server
  def send_frame(data)
    begin
      sock.put(data)
      sock.get(-1, sock.def_read_timeout)
    rescue StandardError => e
      print_error("Error:" + e.message)
    end
  end

  # ACPI formats:
  # TESTFR_CON = '\x83\x00\x00\x00'
  # TESTFR_ACT = '\x43\x00\x00\x00'
  # STOPDT_CON = '\x23\x00\x00\x00'
  # STOPDT_ACT = '\x13\x00\x00\x00'
  # STARTDT_CON = '\x0b\x00\x00\x00'
  # STARTDT_ACT = '\x07\x00\x00\x00'

  # creates and STARTDT Activation frame -> answer should be a STARTDT confirmation
  def startcon
    apci_data = "\x68"
    apci_data << "\x04"
    apci_data << "\x07"
    apci_data << "\x00"
    apci_data << "\x00"
    apci_data << "\x00"
    apci_data
  end

  # creates and STOPDT Activation frame -> answer should be a STOPDT confirmation
  def stopcon
    apci_data = "\x68"
    apci_data << "\x04"
    apci_data << "\x13"
    apci_data << "\x00"
    apci_data << "\x00"
    apci_data << "\x00"
    apci_data
  end

  # creates the acpi header of a 104 message
  def make_apci(asdu_data)
    apci_data = "\x68"
    apci_data << [asdu_data.size + 4].pack("c") # size byte
    apci_data << String([$tx].pack('v'))
    apci_data << String([$rx].pack('v'))
    $rx = $rx + 2
    $tx = $tx + 2
    apci_data << asdu_data
    apci_data
  end

  # parses the header of a 104 message
  def parse_headers(response_data)
    if !response_data[0].eql?("\x04") && !response_data[1].eql?("\x01")
      $rx = + (response_data[2].unpack('H*').first + response_data[1].unpack('H*').first).to_i(16)
      print_good("    TX: " + response_data[4].unpack('H*').first + response_data[3].unpack('H*').first + \
                 " RX: " + response_data[2].unpack('H*').first + response_data[1].unpack('H*').first)
    end
    if response_data[7].eql?("\x07")
      print_good("    CauseTx: " + response_data[7].unpack('H*').first + " (Activation Confirmation)")
    elsif response_data[7].eql?("\x0a")
      print_good("    CauseTx: " + response_data[7].unpack('H*').first + " (Termination Activation)")
    elsif response_data[7].eql?("\x14")
      print_good("    CauseTx: " + response_data[7].unpack('H*').first + " (Inrogen)")
    elsif response_data[7].eql?("\x0b")
      print_good("    CauseTx: " + response_data[7].unpack('H*').first + " (Feedback by distant command / Retrem)")
    elsif response_data[7].eql?("\x03")
      print_good("    CauseTx: " + response_data[7].unpack('H*').first + " (Spontaneous)")
    elsif response_data[7].eql?("\x04")
      print_good("    CauseTx: " + response_data[7].unpack('H*').first + " (Initialized)")
    elsif response_data[7].eql?("\x05")
      print_good("    CauseTx: " + response_data[7].unpack('H*').first + " (Interrogation)")
    elsif response_data[7].eql?("\x06")
      print_good("    CauseTx: " + response_data[7].unpack('H*').first + " (Activiation)")

    # 104 error messages
    elsif response_data[7].eql?("\x2c")
      print_error("    CauseTx: " + response_data[7].unpack('H*').first + " (Type Identification Unknown)")
    elsif response_data[7].eql?("\x2d")
      print_error("   CauseTx: " + response_data[7].unpack('H*').first + " (Cause Unknown)")
    elsif response_data[7].eql?("\x2e")
      print_error("    CauseTx: " + response_data[7].unpack('H*').first + " (ASDU Address Unknown)")
    elsif response_data[7].eql?("\x2f")
      print_error("    CauseTx: " + response_data[7].unpack('H*').first + " (IOA Address Unknown)")
    elsif response_data[7].eql?("\x6e")
      print_error("    CauseTx: " + response_data[7].unpack('H*').first + " (Unknown Comm Address ASDU)")
    end
  end

  ##############################################################################################################
  # following functions parse different 104 ASDU messages and prints it content, not all messages of the standard are currently implemented
  ##############################################################################################################
  def parse_m_sp_na_1(response_data)
    sq_bit = Integer(response_data[6].unpack('C').first) & 0b10000000 # this bit determines the object addressing structure
    response_data = response_data[11..-1] # cut out acpi data
    if sq_bit.eql?(0b10000000)
      ioa = response_data[0..3] # extract ioa value
      response_data = response_data[3..-1] # cut ioa from message
      i = 0
      while response_data.length >= 1
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16) + i) + \
                   " SIQ: 0x" + response_data[0].unpack('H*').first)
        response_data = response_data[1..-1]
        i += 1
      end
    else
      while response_data.length >= 4
        ioa = response_data[0..3] # extract ioa
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16)) + \
                   " SIQ: 0x" + response_data[3].unpack('H*').first)
        response_data = response_data[4..-1]
      end
    end
  end

  def parse_m_me_nb_1(response_data)
    sq_bit = Integer(response_data[6].unpack('C').first) & 0b10000000
    response_data = response_data[11..-1] # cut out acpi data
    if sq_bit.eql?(0b10000000)
      ioa = response_data[0..3]
      response_data = response_data[3..-1]
      i = 0
      while response_data.length >= 3
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16) + i) + \
                   " Value: 0x" + response_data[0..1].unpack('H*').first + " QDS: 0x" + response_data[2].unpack('H*').first)
        response_data = response_data[3..-1]
        i += 1
      end
    else
      while response_data.length >= 6
        ioa = response_data[0..5]
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16)) + \
                   " Value: 0x" + response_data[3..4].unpack('H*').first + " QDS: 0x" + + response_data[5].unpack('H*').first)
        response_data = response_data[6..-1]
      end
    end
  end

  def parse_c_sc_na_1(response_data)
    sq_bit = Integer(response_data[6].unpack('C').first) & 0b10000000
    response_data = response_data[11..-1] # cut out acpi data
    if sq_bit.eql?(0b10000000)
      ioa = response_data[0..3]
      response_data = response_data[3..-1]
      i = 0
      while response_data.length >= 1
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16) + i) + \
                   " DIQ: 0x" + response_data[0].unpack('H*').first)
        response_data = response_data[1..-1]
        i += 1
      end
    else
      while response_data.length >= 4
        ioa = response_data[0..3]
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16)) + \
                   " DIQ: 0x" + response_data[3].unpack('H*').first)
        response_data = response_data[4..-1]
      end
    end
  end

  def parse_m_dp_na_1(response_data)
    sq_bit = Integer(response_data[6].unpack('C').first) & 0b10000000
    response_data = response_data[11..-1] # cut out acpi data
    if sq_bit.eql?(0b10000000)
      ioa = response_data[0..3]
      response_data = response_data[3..-1]
      i = 0
      while response_data.length >= 1
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16) + i) + \
                   " SIQ: 0x" + response_data[0].unpack('H*').first)
        response_data = response_data[1..-1]
        i += 1
      end
    else
      while response_data.length >= 4
        ioa = response_data[0..3]
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16)) + \
                   " SIQ: 0x" + response_data[3].unpack('H*').first)
        response_data = response_data[4..-1]
      end
    end
  end

  def parse_m_st_na_1(response_data)
    sq_bit = Integer(response_data[6].unpack('C').first) & 0b10000000
    response_data = response_data[11..-1] # cut out acpi data
    if sq_bit.eql?(0b10000000)
      ioa = response_data[0..3]
      response_data = response_data[3..-1]
      i = 0
      while response_data.length >= 2
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16) + i) + \
                   " VTI: 0x" + response_data[0].unpack('H*').first + " QDS: 0x" + response_data[1].unpack('H*').first)
        response_data = response_data[2..-1]
        i += 1
      end
    else
      while response_data.length >= 5
        ioa = response_data[0..4]
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16)) + \
                   " VTI: 0x" + response_data[3].unpack('H*').first + " QDS: 0x" + response_data[4].unpack('H*').first)
        response_data = response_data[5..-1]
      end
    end
  end

  def parse_m_dp_tb_1(response_data)
    sq_bit = Integer(response_data[6].unpack('C').first) & 0b10000000
    response_data = response_data[11..-1] # cut out acpi data
    if sq_bit.eql?(0b10000000)
      ioa = response_data[0..3]
      response_data = response_data[3..-1]
      i = 0
      while response_data.length >= 8
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16) + i) + \
                   " DIQ: 0x" + response_data[0].unpack('H*').first)
        print_cp56time2a(response_data[1..7])
        response_data = response_data[8..-1]
        i += 1
      end
    else
      while response_data.length >= 11
        ioa = response_data[0..10]
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16)) + \
                   " DIQ: 0x" + response_data[3].unpack('H*').first)
        print_cp56time2a(response_data[4..10])
        response_data = response_data[11..-1]
      end
    end
  end

  def parse_m_sp_tb_1(response_data)
    sq_bit = Integer(response_data[6].unpack('C').first) & 0b10000000
    response_data = response_data[11..-1] # cut out acpi data
    if sq_bit.eql?(0b10000000)
      ioa = response_data[0..3]
      response_data = response_data[3..-1]
      i = 0
      while response_data.length >= 8
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16) + i) + \
                   " SIQ: 0x" + response_data[0].unpack('H*').first)
        print_cp56time2a(response_data[1..7])
        response_data = response_data[8..-1]
        i += 1
      end
    else
      while response_data.length >= 11
        ioa = response_data[0..10]
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16)) + \
                   " SIQ: 0x" + response_data[3].unpack('H*').first)
        print_cp56time2a(response_data[4..10])
        response_data = response_data[11..-1]
      end
    end
  end

  def parse_c_dc_na_1(response_data)
    sq_bit = Integer(response_data[6].unpack('C').first) & 0b10000000
    response_data = response_data[11..-1] # cut out acpi data
    if sq_bit.eql?(0b10000000)
      ioa = response_data[0..3]
      response_data = response_data[3..-1]
      i = 0
      while response_data.length >= 1
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16) + i) + \
                   " DCO: 0x" + response_data[0].unpack('H*').first)
        response_data = response_data[1..-1]
        i += 1
      end
    else
      while response_data.length >= 4
        ioa = response_data[0..3]
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16)) + \
                   " DCO: 0x" + response_data[3].unpack('H*').first)
        response_data = response_data[4..-1]
      end
    end
  end

  def parse_m_me_na_1(response_data)
    sq_bit = Integer(response_data[6].unpack('C').first) & 0b10000000
    response_data = response_data[11..-1] # cut out acpi data
    if sq_bit.eql?(0b10000000)
      ioa = response_data[0..3]
      response_data = response_data[3..-1]
      i = 0
      while response_data.length >= 3
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16) + i) + \
                   " Value: 0x" + response_data[0..1].unpack('H*').first + " QDS: 0x" + response_data[2].unpack('H*').first)
        response_data = response_data[3..-1]
        i += 1
      end
    else
      while response_data.length >= 6
        ioa = response_data[0..3]
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16)) + \
                   " Value: 0x" + ioa[3..4].unpack('H*').first + " QDS: 0x" + response_data[5].unpack('H*').first)
        response_data = response_data[6..-1]
      end
    end
  end

  def parse_m_me_nc_1(response_data)
    sq_bit = Integer(response_data[6].unpack('C').first) & 0b10000000
    response_data = response_data[11..-1] # cut out acpi data
    if sq_bit.eql?(0b10000000)
      ioa = response_data[0..3]
      response_data = response_data[3..-1]
      i = 0
      while response_data.length >= 5
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16) + i) + \
                   " Value: 0x" + response_data[0..3].unpack('H*').first + " QDS: 0x" + response_data[4].unpack('H*').first)
        response_data = response_data[5..-1]
        i += 1
      end
    else
      while response_data.length >= 8
        ioa = response_data[0..3]
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16)) + \
                   " Value: 0x" + response_data[3..6].unpack('H*').first + " QDS: 0x" + response_data[7].unpack('H*').first)
        response_data = response_data[8..-1]
      end
    end
  end

  def parse_m_it_na_1(response_data)
    sq_bit = Integer(response_data[6].unpack('C').first) & 0b10000000
    response_data = response_data[11..-1] # cut out acpi data
    if sq_bit.eql?(0b10000000)
      response_data = response_data[11..-1]
      ioa = response_data[0..3]
      i = 0
      while response_data.length >= 5
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16) + i) + \
                   " Value: 0x" + response_data[0..3].unpack('H*').first + " QDS: 0x" + response_data[4].unpack('H*').first)
        response_data = response_data[5..-1]
        i += 1
      end
    else
      while response_data.length >= 8
        ioa = response_data[0..3]
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16)) + \
                   " Value: 0x" + response_data[3..6].unpack('H*').first + " QDS: 0x" + response_data[7].unpack('H*').first)
        response_data = response_data[8..-1]
      end
    end
  end

  def parse_m_bo_na_1(response_data)
    sq_bit = Integer(response_data[6].unpack('C').first) & 0b10000000
    response_data = response_data[11..-1] # cut out acpi data
    if sq_bit.eql?(0b10000000)
      ioa = response_data[0..3]
      response_data = response_data[3..-1]
      i = 0
      while response_data.length >= 5
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16) + i) + \
                   " Value: 0x" + response_data[0..3].unpack('H*').first + " QDS: 0x" + response_data[4].unpack('H*').first)
        response_data = response_data[5..-1]
        i += 1
      end
    else
      while response_data.length >= 8
        ioa = response_data[0..3]
        print_good("    IOA: " + String((ioa[2].unpack('H*').first + ioa[1].unpack('H*').first + ioa[0].unpack('H*').first).to_i(16)) + \
                   " Value: 0x" + response_data[3..6].unpack('H*').first + " QDS: 0x" + response_data[7].unpack('H*').first)
        response_data = response_data[8..-1]
      end
    end
  end

  # function to parses time format used in IEC 104
  # function ported to ruby from: https://github.com/Ebolon/iec104
  def print_cp56time2a(buf)
    us = ((Integer(buf[1].unpack('c').first) & 0xFF) << 8) | (Integer(buf[0].unpack('c').first) & 0xFF)
    second = Integer(us) / 1000
    us = us % 1000
    minute = Integer(buf[2].unpack('c').first) & 0x3F
    hour = Integer(buf[3].unpack('c').first) & 0x1F
    day = Integer(buf[4].unpack('c').first) & 0x1F
    month = (Integer(buf[5].unpack('c').first) & 0x0F) - 1
    year = (Integer(buf[6].unpack('c').first) & 0x7F) + 2000
    print_good("    Timestamp: " + String(year) + "-" + String(format("%02d", month)) + "-" + String(format("%02d", day)) + " " + \
               String(format("%02d", hour)) + ":" + String(format("%02d", minute)) + ":" + String(format("%02d", second)) + "." + String(us))
  end

  ##############################################################################################################
  # END of individual parse functions section
  ##############################################################################################################

  # parses the 104 response string of a message
  def parse_response(response)
    response_elements = response.split("\x68")
    response_elements.shift
    response_elements.each do |response_element|
      if response_element[5].eql?("\x64")
        print_good("  Parsing response: Interrogation command (C_IC_NA_1)")
        parse_headers(response_element)
      elsif response_element[5].eql?("\x01")
        print_good("  Parsing response: Single point information (M_SP_NA_1)")
        parse_headers(response_element)
        parse_m_sp_na_1(response_element)
      elsif response_element[5].eql?("\x0b")
        print_good("  Parsing response: Measured value, scaled value (M_ME_NB_1)")
        parse_headers(response_element)
        parse_m_me_nb_1(response_element)
      elsif response_element[5].eql?("\x2d")
        print_good("  Parsing response: Single command (C_SC_NA_1)")
        parse_headers(response_element)
        parse_c_sc_na_1(response_element)
      elsif response_element[5].eql?("\x03")
        print_good("  Parsing response: Double point information (M_DP_NA_1)")
        parse_headers(response_element)
        parse_m_dp_na_1(response_element)
      elsif response_element[5].eql?("\x05")
        print_good("  Parsing response: Step position information (M_ST_NA_1)")
        parse_headers(response_element)
        parse_m_st_na_1(response_element)
      elsif response_element[5].eql?("\x1f")
        print_good("  Parsing response: Double point information with time (M_DP_TB_1)")
        parse_headers(response_element)
        parse_m_dp_tb_1(response_element)
      elsif response_element[5].eql?("\x2e")
        print_good("  Parsing response: Double command (C_DC_NA_1)")
        parse_headers(response_element)
        parse_c_dc_na_1(response_element)
      elsif response_element[5].eql?("\x1e")
        print_good("  Parsing response: Single point information with time (M_SP_TB_1)")
        parse_headers(response_element)
        parse_m_sp_tb_1(response_element)
      elsif response_element[5].eql?("\x09")
        print_good("  Parsing response: Measured value, normalized value (M_ME_NA_1)")
        parse_headers(response_element)
        parse_m_me_na_1(response_element)
      elsif response_element[5].eql?("\x0d")
        print_good("  Parsing response: Measured value, short floating point value (M_ME_NC_1)")
        parse_headers(response_element)
        parse_m_me_nc_1(response_element)
      elsif response_element[5].eql?("\x0f")
        print_good("  Parsing response: Integrated total without time tag (M_IT_NA_1)")
        parse_headers(response_element)
        parse_m_it_na_1(response_element)
      elsif response_element[5].eql?("\x07")
        print_good("  Parsing response: Bitstring of 32 bits without time tag. (M_BO_NA_1)")
        parse_headers(response_element)
        parse_m_bo_na_1(response_element)

      elsif response_element[5].eql?("\x46")
        print_good("Received end of initialisation confirmation")
        parse_headers(response_element)
      elsif response_element[0].eql?("\x04") && response_element[1].eql?("\x01") && response_element[2].eql?("\x00")
        print_good("Received S-Frame")
        parse_headers(response_element)
      elsif response_element[0].eql?("\x04") && response_element[1].eql?("\x0b") && response_element[2].eql?("\x00") && response_element[3].eql?("\x00")
        print_good("Received STARTDT_ACT")
      elsif response_element[0].eql?("\x04") && response_element[1].eql?("\x23") && response_element[2].eql?("\x00") && response_element[3].eql?("\x00")
        print_good("Received STOPDT_ACT")
      elsif response_element[0].eql?("\x04") && response_element[1].eql?("\x43") && response_element[2].eql?("\x00") && response_element[3].eql?("\x00")
        print_good("Received TESTFR_ACT")
      else
        print_status("Received unknown message")
        parse_headers(response_element)
        print_status(response_element.unpack('H*').first)
      end
      # Uncomment for print received data
      # print_good("DEBUG: " + response_element.unpack('H*').first)
    end
  end

  # sends 104 command with configure datastore options
  # default values are for a general interrogation command
  # for example a switching command would be:
  #    COMMAND_TYPE => 46   // double command without time
  #    COMMAND_ADDRESS => 100 // any IOA address that should be switched
  #    COMMAND_VALUE => 6 // switching off with short pulse
  #                          use value 5 to switch on with short pulse
  #
  # Structure of 104 message:
  #    1byte command type
  #    1byte num ix -> 1 (one item send)
  #    1byte cause of transmission -> 6 (activation)
  #    1byte originator address
  #    2byte common adsu address
  #    3byte command address
  #    1byte command value
  def func_send_command
    print_status("Sending 104 command")

    asdu = [datastore['COMMAND_TYPE']].pack("c") # type of command
    asdu << "\x01" # num ix -> only one item is send
    asdu << "\x06" # cause of transmission = activation, 6
    asdu << [datastore['ORIGINATOR_ADDRESS']].pack("c") # sets originator address of client
    asdu << String([Integer(datastore['ASDU_ADDRESS'])].pack('v')) # sets the common address of ADSU
    asdu << String([Integer(datastore['COMMAND_ADDRESS'])].pack('V'))[0..2] # sets the IOA address, todo: check command address fits in the 3byte address field
    asdu << [datastore['COMMAND_VALUE']].pack("c") # sets the value of the command

    # Uncomment for debugging
    # print_status("Sending: " + make_apci(asdu).unpack('H*').first)
    response = send_frame(make_apci(asdu))

    if response.nil?
      print_error("No answer")
    else
      parse_response(response)
    end
    print_status("operation ended")
  end

  def run
    $rx = 0
    $tx = 0
    begin
      connect
    rescue StandardError => e
      print_error("Error:" + e.message)
      return
    end

    # send STARTDT_CON to activate connection
    response = send_frame(startcon)
    if response.nil?
      print_error("Could not connect to 104 service")
      return
    else
      parse_response(response)
    end

    # send the 104 command
    case action.name
    when "SEND_COMMAND"
      func_send_command
    else
      print_error("Invalid ACTION")
    end

    # send STOPDT_CON to terminate connection
    response = send_frame(stopcon)
    if response.nil?
      print_error("Terminating Connection")
      return
    else
      print_status("Terminating Connection")
      parse_response(response)
    end

    begin
      disconnect
    rescue StandardError => e
      print_error("Error:" + e.message)
    end
  end
end
