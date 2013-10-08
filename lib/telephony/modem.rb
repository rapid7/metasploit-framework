module Telephony

class Modem
  attr_accessor :serialport, :sp, :sock
  attr_accessor :baud, :data_bits, :parity, :stop_bits
  attr_accessor :flowcontrol
  attr_accessor :display
  attr_reader   :commandstate

  NONE  = SerialPort::NONE
  HARD  = SerialPort::HARD
  SOFT  = SerialPort::SOFT
  SPACE = SerialPort::SPACE
  MARK  = SerialPort::MARK
  EVEN  = SerialPort::EVEN
  ODD   = SerialPort::ODD

  def initialize(serialport = '/dev/ttyS0')
    @serialport = serialport || '/dev/ttyS0'
    @sp = nil
    @baud = 2400
    @data_bits = 8
    @parity = NONE
    @stop_bits = 1
    @flowcontrol = NONE
    @commandstate = true
    @display = true

    # Connect to and init modem
    begin
      #print("Opening Serial Port #{@serialport} (#{@baud} #{@data_bits}#{@parity}#{@stop_bits})\r\n")
      @sp = SerialPort.create(serialport)
      @sp.modem_params = {'baud' => @baud, 'data_bits' => @data_bits, 'parity' => @parity, 'stop_bits' => @stop_bits}
      @sp.read_timeout = -1
      @sp.rts = 1
      @sp.dtr = 1 if sp.respond_to?:dtr= # unsupported in windows ):
      @sock = @sp
      @sock.extend(Rex::IO::Stream)
      @sock.extend(Rex::IO::StreamAbstraction::Ext)
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print("Error opening serial port #{@serialport} : #{e.class} #{e} #{e.backtrace}\r\n")
      return true
    end
  end

  # This provides pass-through method support for the SerialPort object
  def method_missing(meth, *args); self.sp.send(meth, *args); end

  def put_command(command, timeout)
    switchback = false
    if ! @commandstate
      commandstate
      switchback = true
    end

    begin
      self.flush  # TODO: This doesn't work in exploits for some reason but it does in aux modules
      @sp.puts command + "\r\n"
      echo = get_response(timeout) # read back the echoed command (not really a response)

    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print("Error sending command to modem: #{e.class} #{e} #{e.backtrace}\r\n")
      return
    end

    result = get_response(timeout)

    datastate if switchback == true

    return result
  end

  def get_response(timeout)
    time = Time.now

    @sp.read_timeout = -1
    result = ''
    while Time.now <= time + timeout
      # get a char from the modem
      begin
        c = @sp.getc
        if c
          c = c.chr
          result += c
          if c == "\n"
            result = result.chomp
            break if result.length > 0
          end
        end
      rescue ::Interrupt
        raise $!
      rescue ::Exception => e
        print("Error reading from modem: #{e.class} #{e} #{e.backtrace}\r\n")
        return
      end
    end

    if result.length > 0
      print "[m] #{result}\r\n" if @display
    else
      result = 'TIMEOUT'
    end

    return result
  end

  def commandstate
    if ! @commandstate 
      @sp.break 10 # tenths of a second
      @sp.puts '+++'
      @sp.break 10 # tenths of a second
      result = get_response(3)
      if result != 'OK'
        print( "Error switching to command state: FAILED\r\n" )
        return false
      else
        @commandstate = true
      end
    end
  
    return true	
  end

  def datastate
    if @commandstate
      result = put_command('ATO0', 3)
      if result =~ /CONNECT/i
        @commandstate = false
      else
        print( "Error switching to data state: FAILED\r\n" )
        return false
      end
    end

    return true
  end

  def hangup
    flush
    if @commandstate == true
      #print( "Hanging up... (commandstate ATH0)\r\n" )
      result = put_command('ATH0', 3)
      return true if result == 'OK' or result == 'NO CARRIER'
    else
      if @sp.respond_to?:dtr= # unsupported in windows ):
        #print( "Hanging up... (DTR = 0)\r\n" )
        @sp.dtr = 0
        sleep 0.75
        @sp.dtr = 1
        result = get_response(3)
        @commandstate = true if result == 'NO CARRIER'
        return true
      else
        #print( "Hanging up... (datastate ATH0)\r\n" )
        commandstate
        result = put_command('ATH0', 3)
        return true if result == 'OK'
      end
    end

    return false
  end

  # flush any stale data in the read buffer
  def flush
    @sp.read_timeout = -1
    while @sp.getc; end
  end

  # TODO: confert all calls to Modem.params to Modem.modem_params and remove this def
  def params=(params)
    @sp.modem_params = params
  end

end

end
