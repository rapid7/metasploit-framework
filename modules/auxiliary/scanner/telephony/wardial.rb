##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'zlib'


# Extend Object class to include save_to_file and load_from_file methods
class Object
  def self.save_to_file obj, filename, options={}
    #obj = self
    marshal_dump = Marshal.dump(obj)
    file = File.new(filename,'w')
    file = Zlib::GzipWriter.new(file) unless options[:gzip] == false
    file.write marshal_dump
    file.close
    return obj
  end

  def self.load_from_file filename
    begin
      file = Zlib::GzipReader.open(filename)
    rescue Zlib::GzipFile::Error
      file = File.open(filename, 'rb')
    ensure
      return nil if ! file
      #obj = Marshal.load file.read
      obj = Marshal.load file.read
      file.close
      return obj
    end
  end
end

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Wardialer',
      'Description' => 'Scan for dial-up systems that are connected to modems and answer telephony indials.',
      'Author'      => [ 'I)ruid' ],
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      OptString.new('DIALMASK',     [true,  'Dial Mask (e.g. 1.800.95X.99XX, (202) 358-XXXX, 358.####, etc.)', '202.358.XXXX']),
      OptString.new('DIALPREFIX',   [true,  'Dial Prefix', 'ATDT']),
      OptString.new('INITSTRING',   [true,  'Initialization String', 'AT X6 S11=80']),
      OptString.new('SERIALPORT',   [true,  'Serial Port (e.g. 0 (COM1), 1 (COM2), /dev/ttyS0, etc.)', '/dev/ttyS0']),
    ])

    register_advanced_options(
    [
      OptInt.new(   'BaudRate',     [true,  'Baud Rate', 19200]),
      OptEnum.new(  'DataBits',     [true,  'Data Bits (4 is Windows Only)', '8', ['4', '5', '6', '7', '8'], '8']),
      OptInt.new(   'ConnTimeout',  [true,  'Timeout per data connection in seconds', 45]),
      OptInt.new(   'DialDelay',    [true,  'Time to wait between dials in seconds (rec. min. 1)', 1]),
      OptString.new('DialSuffix',   [false, 'Dial Suffix', nil]),
      OptInt.new(   'DialTimeout',  [true,  'Timeout per dialed number in seconds', 40]),
      OptBool.new(  'DisplayModem', [false,  'Displays modem commands and responses on the console', false]),
      OptEnum.new(  'FlowControl',  [true,  'Flow Control', 'None', ['None', 'Hardware', 'Software', 'Both'], 'None']),
      OptInt.new(   'InitInterval', [true,  'Number of dials before reinitializing modem', 30]),
      #OptEnum.new(  'LogMethod',    [true,  'Log Method', 'File', ['File', 'DataBase', 'TIDBITS'], 'File']),
      OptEnum.new(  'LogMethod',    [true,  'Log Method', 'File', ['File'], 'File']),
      OptString.new('NudgeString',  [false, 'Nudge String', '\x1b\x1b\r\n\r\n']),
      OptEnum.new(  'Parity',       [false,  'Parity (Mark & Space are Windows Only)', 'None', ['None', 'Even', 'Odd', 'Mark', 'Space'], 'None']),
      OptBool.new(  'RedialBusy',   [false,  'Redials numbers found to be busy', false]),
      OptEnum.new(  'StopBits',     [true,  'Stop Bits', '1', ['1', '2'], '1']),
    ])

    deregister_options('NUMBER')
    deregister_options('RPORT')
    deregister_options('RHOSTS')
    deregister_options('PAYLOAD')

    @logmethod = :file
    @commandstate = true

    begin
      require 'telephony'
      @telephony_loaded = true
    rescue ::Exception => e
      @telephony_loaded = false
      @telephony_error  = e
    end
  end

  def run
    if ! @telephony_loaded
      print_error("The Telephony module is not available: #{@telephony_error}")
      raise RuntimeError, "Telephony not available"
    end

    @confdir      = File.join(Msf::Config.get_config_root, 'wardial')
    @datadir      = File.join(Msf::Config.get_config_root, 'logs', 'wardial')

    # make sure working dirs exist
    FileUtils.mkdir_p(@confdir)
    FileUtils.mkdir_p(@datadir)

    @logmethod   = case datastore['LogMethod']
      when 'DataBase' ; :database
      when 'TIDBITS'  ; :tidbits
      else              :file
    end
    serialport   = datastore['SERIALPORT']
    baud         = datastore['BaudRate'].to_i
    data_bits    = datastore['DataBits'].to_i
    stop_bits    = datastore['StopBits'].to_i
    parity       = case datastore['Parity']
      when 'Even' ; Telephony::Modem::EVEN
      when 'Odd'  ; Telephony::Modem::ODD
      when 'Mark' ; Telephony::Modem::MARK
      when 'Space'; Telephony::Modem::SPACE
      else          Telephony::Modem::NONE
    end
    flowcontrol  = case datastore['FlowControl']
      when 'Hardware' ; Telephony::Modem::HARD
      when 'Software' ; Telephony::Modem::SOFT
      when 'Both'     ; Telephony::Modem::HARD | Telephony::Modem::SOFT
      else            ; Telephony::Modem::NONE
    end
    initstring   = datastore['INITSTRING']
    initinterval = datastore['InitInterval']
    dialprefix   = datastore['DIALPREFIX']
    dialsuffix   = datastore['DialSuffix']
    nudgestring  = datastore['NudgeString'] ? eval('"'+datastore['NudgeString']+'"') : "\r\n\r\n"
    dialtimeout  = datastore['DialTimeout'].to_i
    conntimeout  = datastore['ConnTimeout'].to_i
    dialmask     = datastore['DIALMASK'].tr(' ', '')
    dialdelay    = datastore['DialDelay'].to_i
    redialbusy   = datastore['RedialBusy']
    @displaymodem = datastore['DisplayModem']

    # Connect to and init modem
    modem = Telephony::Modem.new(serialport)
    modem.params = {
      'baud'      => baud,
      'data_bits' => data_bits,
      'parity'    => parity,
      'stop_bits' => stop_bits
    }
    modem.flow_control = flowcontrol
    modem.display = @displaymodem

    modem.flush

    # reload data from previous scan
    datfile = @datadir + '/' + dialmask.gsub(/[( ]/, '').gsub(/[).]/, '-').gsub(/[#]/, 'X').upcase + '.dat'
    dialrange = Object.load_from_file(datfile)
    if dialrange
      print_status( "Previous scan data loaded from #{datfile}" )
      select = dialrange.select {|key, value|
        case @target
          when :carrier ; value[:carrier] == true
          when :fax     ; value[:fax]     == true
        end
      }
      num_identified = select.size
      select = dialrange.select {|key, value|
        value[:carrier] == true
      }
      num_carriers = select.size
      select = dialrange.select {|key, value|
        value[:fax] == true
      }
      num_faxes = select.size
      select = dialrange.select {|key, value|
        value[:busy] == true
      }
      num_busy = select.size
    else
      print_status( "No previous scan data found (#{datfile})" )
      dialrange = build_dialrange(dialmask)
      num_identified = 0
      num_carriers   = 0
      num_faxes      = 0
      num_busy       = 0
    end

    # Dial loop
    begin
      done = false
      nextnum = true
      dialcount = 0
      while true

        if dialcount % initinterval == 0
          return if initmodem(modem, initstring) == false
        end

        if nextnum == true
          unidentified = dialrange.select {|key, value|
            value[:identified] == false
          }
          if redialbusy
            unidentified += unidentified.select {|key, value|
              value[:busy] == true
            }
          end
          break if unidentified.size == 0

          chosen  = rand(unidentified.size)
          dialnum = unidentified[chosen][0]
          dialval = unidentified[chosen][1]
        end
        print_status("#{unidentified.size} of #{dialrange.size} numbers unidentified, #{num_carriers} carriers found, #{num_faxes} faxes found, #{num_busy} busy")
        if dialval[:busy] == true
          print_status("Dialing: #{dialnum} (#{dialtimeout} sec. timeout, previously busy)")
        else
          print_status("Dialing: #{dialnum} (#{dialtimeout} sec. timeout, previously undialed)")
        end

        dialstring = dialprefix + ' ' + dialnum
        dialstring += (' ' + dialsuffix) if dialsuffix

        modem.flush
        time = Time.now
        result = modem.put_command(dialstring, dialtimeout)
        while result =~ /RINGING/i
          result = modem.get_response(dialtimeout-(Time.now-time))
        end
        dialcount += 1
        dialrange[dialnum][:dialed] = dialnum

        case result
          when /TIMEOUT/i
            print_status( 'Timeout' )
            dialrange[dialnum][:identified] = true
            dialrange[dialnum][:result] = result
            dialrange[dialnum][:timeout] = true
            dialrange[dialnum][:timestamp] = Time.now
            modem.puts "\r\n" # force the modem to respond to last command (hangup/abort)
            result = modem.get_response(3)
          when /CONNECT/i
            print_status( "Carrier: #{result}" )
            @commandstate = false
            dialrange[dialnum][:identified] = true
            dialrange[dialnum][:result] = result
            dialrange[dialnum][:carrier] = true
            dialrange[dialnum][:timestamp] = Time.now
            dialrange[dialnum][:banner] = get_banner(modem, conntimeout, nudgestring)
            modem.hangup
            initmodem(modem, initstring)
            num_carriers += 1
            note = dialrange[dialnum][:result] + "\n" + dialrange[dialnum][:banner]
            report_note(:host => dialnum, :type => "wardial_result", :data => note)
            log_result(dialrange[dialnum])
          when /HK_CARRIER/i
            print_status( "Carrier: #{result}" )
            dialrange[dialnum][:identified] = true
            dialrange[dialnum][:result] = result
            dialrange[dialnum][:carrier] = true
            dialrange[dialnum][:timestamp] = Time.now
            modem.hangup
            initmodem(modem, initstring)
            num_carriers += 1
            note = dialrange[dialnum][:result] + "\n" + dialrange[dialnum][:banner]
            report_note(:host => dialnum, :type => "wardial_result", :data => note)
            log_result(dialrange[dialnum])
          when /\+FCO/i
            print_status( "Fax: #{result}" )
            dialrange[dialnum][:identified] = true
            dialrange[dialnum][:result] = result
            dialrange[dialnum][:fax] = true
            dialrange[dialnum][:timestamp] = Time.now
            modem.hangup
            initmodem(modem, initstring)
            num_faxes += 1
            note = dialrange[dialnum][:result] + "\n" + dialrange[dialnum][:banner]
            report_note(:host => dialnum, :type => "wardial_result", :data => note)
            log_result(dialrange[dialnum])
          when /VOICE/i
            print_status( "Voice" )
            dialrange[dialnum][:identified] = true
            dialrange[dialnum][:result] = result
            dialrange[dialnum][:voice] = true
            dialrange[dialnum][:timestamp] = Time.now
            modem.hangup
          when /HK_VMB/i
            dialrange[dialnum][:identified] = true
            dialrange[dialnum][:result] = result
            dialrange[dialnum][:voicemail] = true
            dialrange[dialnum][:timestamp] = Time.now
            modem.hangup
          when /HK_AVS/i
            dialrange[dialnum][:identified] = true
            dialrange[dialnum][:result] = result
            dialrange[dialnum][:avs] = true
            dialrange[dialnum][:timestamp] = Time.now
            modem.hangup
          when /HK_NOTED/i
            dialrange[dialnum][:identified] = true
            dialrange[dialnum][:result] = result
            dialrange[dialnum][:noted] = true
            dialrange[dialnum][:timestamp] = Time.now
            modem.hangup
          when /HK_GIRL/i
            dialrange[dialnum][:identified] = true
            dialrange[dialnum][:result] = result
            dialrange[dialnum][:girl] = true
            dialrange[dialnum][:timestamp] = Time.now
            modem.hangup
          when /NO CARRIER/i
            print_status( "No Carrier" )
            dialrange[dialnum][:identified] = true #TODO: should this be false?
            dialrange[dialnum][:result] = result
            dialrange[dialnum][:timestamp] = Time.now
          when /BUSY/i
            print_status( "Busy" )
            dialrange[dialnum][:identified] = false
            dialrange[dialnum][:result] = result
            dialrange[dialnum][:busy] = true
            dialrange[dialnum][:timestamp] = Time.now
            num_busy += 1
          when /OK/i
            print_status( "Unexpected OK response..." )
          when /NO DIAL *TONE/i
            nextnum = false
            modem.hangup
            select(nil,nil,nil,1)
            next
          when nil
            modem.hangup
          else
            print_status( "Unrecognized Response String" )
        end

        Object.save_to_file(dialrange, datfile)
        #dialrange.save_to_file(datfile)
        nextnum = true
        select(nil,nil,nil,1) # we need at least a little buffer for the modem to hangup/reset
        select(nil,nil,nil,dialdelay-1) if dialdelay >= 1
      end

    rescue ::Interrupt
      modem.hangup
      Object.save_to_file(dialrange, datfile)
      #dialrange.save_to_file(datfile)
      raise $!
    rescue ::Exception => e
      print_error("Error during dial process: #{e.class} #{e} #{e.backtrace}")
      return
    end

    print_status("Dialing Complete")
    modem.close
  end

  def initmodem(modem, initstring)
    print_status("Initializing Modem")
    result = modem.put_command('ATZ', 3)
    if result != 'OK'
      print_error("Error resetting modem")
      return false
    end
    result = modem.put_command(initstring, 3)
    if result != 'OK'
      print_error("Error initializing modem")
      return false
    end

    return true
  end

  def build_dialrange(dialmask)
    dialrange = {}

    incdigits = 0
    dialmask.each_char {|c|
      incdigits += 1 if c =~ /^[X#]$/i
    }
    max = (10**incdigits)-1
    print_status("Detected #{incdigits} masked digits in DIALMASK (#{dialmask})")
    print_status("Generating storage for #{max+1} numbers to dial")

    (0..max).each {|num|
      number = dialmask.dup # copy the mask
      numstr = sprintf("%0#{incdigits}d", num) # stringify our incrementing number
      j = 0 # index for numstr
      for i in 0..number.length-1 do # step through the number (mask)
        if number[i].chr =~ /^[X#]$/i
          number[i] = numstr[j] # replaced masked indexes with digits from incrementing number
          j += 1
        end
      end
      dialrange[number] = {}
      dialrange[number][:identified] = false
    }
    #print_status("Storage for #{dialrange.size} numbers generated")

    return dialrange
  end

  def log_result(dialnum)
    case @logmethod
      when :file
        logfile = File.join(@datadir, 'found.log')
        file = File.new(logfile, 'a')
        file.puts( "#####( NEW LOG ENTRY )#####\n")
        file.puts( "#{Time.now}\n")
        file.puts( "#{dialnum[:dialed]} : #{dialnum[:result]}\n")
        file.puts( "#{dialnum[:banner]}\n") if dialnum[:banner]
        file.puts( "#####( END LOG ENTRY )#####\n")
        file.close
      when :database
      when :tidbits
    end
  end

  def get_banner(modem, timeout, nudgestring)
    print_status("Grabbing banner...")
    banner = ''

    time = Time.now
    gotchar = Time.now
    while Time.now < time + timeout
      if Time.now >= gotchar + 8 # nudges after 8 seconds of receiving nothing
        if nudgestring
          print_status( "Nudging..." )
          modem.puts nudgestring
        end
        gotchar = Time.now # resets timer so we don't nudge too often
      end

      c = modem.getc
      next if ! c

      gotchar = Time.now
      print( c.chr ) if @displaymodem

      # stop if carrier dropped
      break if modem.dcd == 0

      banner += c.chr
    end

    print("\n") if @displaymodem
    return banner
  end
end
