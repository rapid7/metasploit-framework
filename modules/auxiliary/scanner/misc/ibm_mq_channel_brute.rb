##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'IBM WebSphere MQ Channel Name Bruteforce',
      'Description' => 'This module uses a dictionary to bruteforce MQ channel names. For all identified channels it also returns if SSL is used and whether it is a server-connection channel.',
      'Author'      => 'Petros Koutroumpis',
      'License'     => MSF_LICENSE
    )
    register_options([
      Opt::RPORT(1414),
      OptInt.new('TIMEOUT', [true, "The socket connect timeout in seconds", 10]),
      OptInt.new('CONCURRENCY', [true, "The number of concurrent channel names to check", 10]),
      OptPath.new('CHANNELS_FILE',
        [ true, "The file that contains a list of channel names"]
      )])
  end

  def create_packet(chan)
    packet = "\x54\x53\x48\x20"+ 	# StructID
    "\x00\x00\x01\x0c"+ 		# MQSegmLen
    "\x02" +			 	# Byte Order
    "\x01" +			 	# SegmType
    "\x01" +				# CtlFlag1
    "\x00" +				# CtlFlag2
    "\x00\x00\x00\x00\x00\x00\x00\x00"+	# LUWIdent
    "\x22\x02\x00\x00"+			# Encoding
    "\xb5\x01" +			# CCSID
    "\x00\x00" +			# Reserved
    "\x49\x44\x20\x20" +		# StructID
    "\x0d" +				# FAP Level
    "\x26" +				# CapFlag1 - Channel Type
    "\x00" +				# ECapFlag1
    "\x00" +				# IniErrFlg1
    "\x00\x00" +			# Reserved
    "\x32\x00" +			# MaxMsgBtch
    "\xec\x7f\x00\x00" +		# MaxTrSize
    "\x00\x00\x40\x00" +		# MaxMsgSize
    "\xff\xc9\x9a\x3b" +		# SegWrapVal
    + chan + 				# Channel name
    "\x20" +				# CapFlag2
    "\x20" +				# ECapFlag2
    "\x20\x20" +			# ccsid
    "QM1" + "\x20"*45 +			# Queue Manager Name
    "\x20\x20\x20\x20" +		# HBInterval
    "\x20\x20" +			# EFLLength
    "\x20" +				# IniErrFlg2
    "\x20" +				# Reserved1
    "\x20\x20" +			# HdrCprLst
    "\x20\x20\x20\x20\x2c\x01\x00\x00"+ # MSGCprLst1
    "\x8a\x00\x00\x55\x00\xff\x00\xff"+ # MsgCprLst2
    "\xff\xff" +			# Reserved2
    "\xff\xff\xff\xff" +		# SSLKeyRst
    "\xff\xff\xff\xff" +		# ConvBySKt
    "\xff" +				# CapFlag3
    "\xff" +				# ECapFlag3
    "\xff\xff" +			# Reserved3
    "\x00\x00\x00\x00" +		# ProcessId
    "\x00\x00\x00\x00" +		# ThreadId
    "\x00\x00\x05\x00" +		# TraceId
    "\x00\x00\x10\x13\x00\x00" + 	# ProdId
    "\x01\x00\x00\x00\x01\x00" + 	# ProdId
    "MQMID" + "\x20"*43 +		# MQM Id
    "\x20\x20\x20\x20\x20\x20\x20\x20"+ # Unknown
    "\x20\x20\x20\x20\x20\x20\x00\x00"+ # Unknown
    "\xff\xff\xff\xff\xff\xff\xff\xff"+ # Unknown
    "\xff\xff\xff\xff\xff\xff\xff\xff"+ # Unknown
    "\xff\xff\x00\x00\x00\x00\x00\x00"+ # Unknown
    "\x00\x00\x00\x00\x00\x00"		# Unknown
  end


  def run_host(ip)
    @channels = []
    @unencrypted_mqi_channels = []
    begin
      channel_list
      rescue ::Rex::ConnectionRefused
        fail_with(Failure::Unreachable, "TCP Port closed.")
      rescue ::Rex::ConnectionError, ::IOError, ::Timeout::Error, Errno::ECONNRESET
        fail_with(Failure::Unreachable, "Connection Failed.")
      rescue ::Exception => e
        fail_with(Failure::Unknown, e)
      end
      if(@channels.empty?)
        print_status("#{ip}:#{rport} No channels found.")
      else
        print_good("Channels found: #{@channels}")
        print_good("Unencrypted MQI Channels found: #{@unencrypted_mqi_channels}")
        report_note(
          :host => rhost,
          :port => rport,
          :type => 'mq.channels'
        )
      print_line
    end
  end

  def channel_list
    channel_data = get_channel_names
    while (channel_data.length > 0)
      t = []
      r = []
      begin
        1.upto(datastore['CONCURRENCY']) do
          this_channel = channel_data.shift
          if this_channel.nil?
            next
          end
          t << framework.threads.spawn("Module(#{self.refname})-#{rhost}:#{rport}", false, this_channel) do |channel|
            connect
            vprint_status "#{rhost}:#{rport} - Sending request for #{channel}..."
            if channel.length.to_i > 20
              print_error("Channel names cannot exceed 20 characters.  Skipping.")
              next
            end
            chan = channel + "\x20"*(20-channel.length.to_i)
            timeout = datastore['TIMEOUT'].to_i
            s = connect(false,
              {
                'RPORT' => rport,
                'RHOST' => rhost,
              }
            )
            s.put(create_packet(chan))
            data = s.get_once(-1,timeout)
            if data.nil?
              print_status("No response received. Try increasing timeout.")
              next
            end
            if not data[0...3].include? 'TSH'
              next
            end
            if data[-4..-1] == "\x01\x00\x00\x00" # NO_CHANNEL code
              next
            end
            if data[-4..-1] == "\x18\x00\x00\x00" # CIPHER_SPEC code
              print_status("Found channel: #{channel}, IsEncrypted: True, IsMQI: N/A")
            elsif data[-4..-1] == "\x02\x00\x00\x00" # CHANNEL_WRONG_TYPE code
              print_status("Found channel: #{channel}, IsEncrypted: False, IsMQI: False")
            else
              print_status("Found channel: #{channel}, IsEncrypted: False, IsMQI: True")
              @unencrypted_mqi_channels << channel
            end
            @channels << channel
            disconnect
          end
        end
        t.each {|x| x.join }
      end
    end
  end

  def get_channel_names
    if(! @common)
      File.open(datastore['CHANNELS_FILE'], "rb") do |fd|
        data = fd.read(fd.stat.size)
        @common = data.split(/\n/).compact.uniq
      end
    end
    @common
  end

end
