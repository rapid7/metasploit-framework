# -*- coding: binary -*-
module Msf

module Exploit::Remote::Dialup

  def initialize(info = {})
    super

    register_options(
      [
        OptInt.new(   'BAUDRATE',     [true, 'Baud Rate', 19200]),
        OptEnum.new(  'DATABITS',     [true, 'Data Bits (4 is Windows Only)', '8', ['4', '5', '6', '7', '8'], '8']),
        OptString.new('DIALPREFIX',   [true, 'Dial Prefix', 'ATDT *67, *70,']),
        OptString.new('DIALSUFFIX',   [false, 'Dial Suffix', nil]),
        OptInt.new(   'DIALTIMEOUT',  [true, 'Dial Timeout in seconds', 60]),
        OptBool.new(  'DISPLAYMODEM', [true, 'Displays modem commands and responses on the console', false]),
        OptEnum.new(  'FLOWCONTROL',  [true, 'Flow Control', 'None', ['None', 'Hardware', 'Software', 'Both'], 'None']),
        OptString.new('INITSTRING',   [true, 'Initialization String', 'AT X6 S11=80']),
        OptString.new('NUMBER',       [true, 'Number to Dial (e.g. 1.800.950.9955, (202) 358-1234, 358.1234 etc.)', nil]),
        OptEnum.new(  'PARITY',       [true, 'Parity (Mark & Space are Windows Only)', 'None', ['None', 'Even', 'Odd', 'Mark', 'Space'], 'None']),
        OptString.new('SERIALPORT',   [true, 'Serial Port (e.g. 0 (COM1), 1 (COM2), /dev/ttyS0, etc.)', '/dev/ttyS0']),
        OptEnum.new(  'STOPBITS',     [true, 'Stop Bits', '1', ['1', '2'], '1']),
      ], self.class)

    deregister_options('RHOST')

    begin
      require 'telephony'
      @telephony_loaded = true
    rescue ::Exception => e
      @telephony_loaded = false
      @telephony_error  = e
    end
  end

  # Opens the modem connection
  def connect_dialup(global = true, opts={})

    if (not @telephony_loaded)
      print_status("The serialport module is not available: #{telephony_error}")
      raise RuntimeError, "Telephony not available"
    end

    serialport = datastore['SERIALPORT']
    baud       = datastore['BAUDRATE'].to_i
    data_bits  = datastore['DATABITS'].to_i
    stop_bits  = datastore['STOPBITS'].to_i
    parity     = case datastore['PARITY']
      when 'Even' ; Telephony::Modem::EVEN
      when 'Odd'  ; Telephony::Modem::ODD
      when 'Mark' ; Telephony::Modem::MARK
      when 'Space'; Telephony::Modem::SPACE
      else          Telephony::Modem::NONE
    end
    flowcontrol  = case datastore['FLOWCONTROL']
      when 'Hardware' ; Telephony::Modem::HARD
      when 'Software' ; Telephony::Modem::SOFT
      when 'Both'     ; Telephony::Modem::HARD | Telephony::Modem::SOFT
      else              Telephony::Modem::NONE
    end

    initstring   = datastore['INITSTRING']
    dialprefix   = datastore['DIALPREFIX']
    dialsuffix   = datastore['DIALSUFFIX']
    dialtimeout  = datastore['DIALTIMEOUT'].to_i
    number       = datastore['NUMBER'].tr(' ', '')

    modem = Telephony::Modem.new(serialport)
    modem.params = {
      'baud'      => baud,
      'data_bits' => data_bits,
      'parity'    => parity,
      'stop_bits' => stop_bits
    }
    modem.flow_control = flowcontrol
    modem.display = datastore['DISPLAYMODEM']

    print_status("Initializing Modem")
    result = modem.put_command('ATZ', 3)
    if result != 'OK'
      print_error("Error resetting modem")
      return
    end
    result = modem.put_command(initstring, 3)
    if result != 'OK'
      print_error("Error initializing modem")
      return
    end

    print_status("Dialing: #{number} (#{dialtimeout} sec. timeout)")
    dialstring = dialprefix + ' ' + number
    dialstring += (' ' + dialsuffix) if dialsuffix

    time = Time.now
    result = modem.put_command(dialstring, dialtimeout)
    while result =~ /RINGING/i
      result = modem.get_response(dialtimeout-(Time.now-time))
    end

    case result
      when /CONNECT/i
        print_status("Carrier: #{result}" )
        self.modem = modem if global
        return modem
      else
        print_error("No Carrier")
        disconnect_dialup(modem)
        return nil
    end
  end

  # Closes the modem connection
  def disconnect_dialup(nmodem = self.modem)
    if(nmodem)
      nmodem.flush
      nmodem.hangup
      nmodem.close
    end
  end

  # Reads until timeout looking for regexp
  def dialup_expect(regexp, timeout)
    res = {
      :match  => false,
      :buffer => nil,
    }
    return res if ! self.modem

    res[:buffer] = ''

    time = Time.now
    while Time.now < time + timeout
      c = self.modem.getc
      res[:buffer] += c.chr if c
      if res[:buffer].match(regexp) != nil
        res[:match] = true
        while c
          c = self.modem.getc
          res[:buffer] += c.chr if c
        end
        return res
      end
    end
    return res
  end

  def dialup_getc
    return false if ! self.modem
    return self.modem.getc
  end

  def dialup_gets
    return false if ! self.modem
    buffer = ''
    c = self.modem.getc
    while c != 0x0a
      buffer += c
      c = self.modem.getc
    end
    buffer += c
    return buffer
  end

  def dialup_putc(c)
    return false if ! self.modem
    return self.modem.putc(c)
  end

  def dialup_puts(string)
    return false if ! self.modem
    return self.modem.puts(string)
  end

  def handler(nmodem = self.modem)
    # If the handler claims the modem, then we don't want it to get closed
    # during cleanup
    if ((rv = super) == Handler::Claimed)
      if (nmodem == self.modem)
        self.modem = nil
      end
    end

    return rv
  end

  attr_accessor :modem

end
end
