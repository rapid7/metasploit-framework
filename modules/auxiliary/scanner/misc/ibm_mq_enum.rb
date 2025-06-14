##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Identify Queue Manager Name and MQ Version',
      'Description'    => 'Run this auxiliary against the listening port of an IBM MQ Queue Manager to identify its name and version. Any channel type can be used to get this information as long as the name of the channel is valid.',
      'Author'         => [ 'Petros Koutroumpis' ],
      'License'        => MSF_LICENSE
    ))
    register_options(
      [
        OptString.new('CHANNEL', [ true, "Channel to use" ,"SYSTEM.DEF.SVRCONN"]),
        OptInt.new('CONCURRENCY', [true, "The number of concurrent ports to check per host", 10]),
        OptInt.new('TIMEOUT', [true, "The socket connect timeout in seconds", 10]),
        OptString.new('PORTS', [true, 'Ports to probe', '1414']),

      ])
    deregister_options('RPORT')
  end


  def create_packet(channel_type)
    chan = datastore['CHANNEL'] + "\x20"*(20-datastore['CHANNEL'].length.to_i)
    if channel_type == 0
      chan_type = "\x26"
    elsif channel_type == 1
      chan_type = "\x07"
    elsif channel_type == 2
      chan_type = "\x08"
    end

    packet = "\x54\x53\x48\x20" + 		# StructID
    "\x00\x00\x01\x0c" + 			# MQSegmLen
    "\x02" + 					# ByteOrder
    "\x01" + 					# SegmType
    "\x01" + 					# CtlFlag1
    "\x00" + 					# CtlFlag2
    "\x00\x00\x00\x00\x00\x00\x00\x00" +	# LUW Ident
    "\x22\x02\x00\x00" + 			# Encoding
    "\xb5\x01" + 				# CCSID
    "\x00\x00" + 				# Reserved
    "\x49\x44\x20\x20" + 			# StructId
    "\x0d" + 					# FAP level
    chan_type + 				# CapFlag1 - Message Type
    "\x00" + 					# ECapFlag1
    "\x00" + 					# IniErrFlg1
    "\x00\x00" + 				# Reserved
    "\x32\x00" + 				# MaxMsgBtch
    "\xec\x7f\x00\x00" + 			# MaxTrSize
    "\x00\x00\x40\x00" + 			# MaxMsgSize
    "\xff\xc9\x9a\x3b" + 			# SeqWrapVal
    chan + 					# Channel Name
    "\x87" + 					# CapFlag2
    "\x00" + 					# ECapFlag2
    "\x5b\x01" +				# ccsid
    "QM1" + "\x20"*45 +			# Queue Manager Name
    "\x2c\x01\x00\x00" + 			# HBInterval
    "\x8a\x00" + 				# EFLLength
    "\x00" + 					# IniErrFlg2
    "\x55" + 					# Reserved1
    "\x00\xff" +				# HdrCprsLst
    "\x00\xff\xff\xff\xff\xff\xff\xff\xff" + 	# MsgCprsLst1
    "\xff\xff\xff\xff\xff\xff\xff" + 		# MsgCprsLst2
    "\x00\x00" + 				# Reserved2
    "\x00\x00\x00\x00" + 			# SSLKeyRst
    "\x00\x00\x00\x00" + 			# ConvBySkt
    "\x05" + 					# CapFlag3
    "\x00" + 					# ECapFlag3
    "\x00\x00" + 				# Reserved3
    "\x10\x13\x00\x00" + 			# ProcessId
    "\x01\x00\x00\x00" + 			# ThreadId
    "\x01\x00\x00\x00" + 			# TraceId
    "MQMM09000000" +		 		# ProdId
    "MQMID" + "\x20"*43 + 			# MQM ID
    "\x00\x00\xff\xff\xff\xff\xff\xff\xff" +	# Unknown1
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff" + 	# Unknown2
    "\xff\xff\x00\x00\x00\x00\x00\x00\x00" + 	# Unknown3
    "\x00\x00\x00\x00\x00" 			# Unknown4
  end


  def run_host(ip)
    chan = datastore['CHANNEL']
    if chan.length > 20
      print_error("Channel name must be less than 20 characters.")
      raise Msf::OptionValidateError.new(['CHANNEL'])
    end
    ports = Rex::Socket.portspec_crack(datastore['PORTS'])
    while(ports.length > 0)
      t = []
      r = []
      begin
        1.upto(datastore['CONCURRENCY']) do
          this_port = ports.shift
          break if not this_port
          t << framework.threads.spawn("Module(#{self.refname})-#{ip}:#{this_port}", false, this_port) do |port|
            begin
                data_recv = ""
                3.times do |channel_type|
                  data_recv = send_packet(ip,port,channel_type)
                  if data_recv.nil?
                    next
                  end
                  # check if CHANNEL_WRONG_TYPE error received and retry with different type
                  if data_recv[data_recv.length-4...data_recv.length] != "\x02\x00\x00\x00"
                    break
                  end
                end
                if data_recv.nil?
                  print_status("No response received. Try increasing TIMEOUT value.")
                  print_line
                  next
                end
                status_code = data_recv[-4..-1]
                if status_code == "\x18\x00\x00\x00"
                  print_status("Channel Requires SSL. Could not get more information.")
                  print_line
                end
                if not data_recv[0...3].include?('TSH')
                  next
                end
                if status_code == "\x01\x00\x00\x00"
                  print_error('Channel "' + chan + '" does not exist.')
                  print_line
                end
                if status_code == "\x02\x00\x00\x00" or status_code == "\x06\x00\x00\x00"
                  print_error('Unsupported channel type. Try a different channel.')
                  print_line
                end
                if data_recv.length < 180
                  next
                end
                qm_name = data_recv[76...124].delete(' ')
                mq_version = data_recv[180...188].scan(/../).collect{|x| x.to_i}.join('.')
                print_good("#{ip}:#{port} - Queue Manager Name: #{qm_name} - MQ Version: #{mq_version}")
                print_line
            end
          end
        end
        t.each {|x| x.join }
      end
    end
  end

  def send_packet(ip,port,channel_type)
    begin
      timeout = datastore['TIMEOUT'].to_i
      packet = create_packet(channel_type)
      s = connect(false,
       {
         'RPORT' => port,
         'RHOST' => ip,
        }
      )
      s.put(packet)
      data = s.get_once(-1,timeout)
      return data
    rescue ::Rex::ConnectionRefused
      print_error("#{ip}:#{port} - TCP Port Closed.")
      print_line
    rescue ::Rex::ConnectionError, ::IOError, ::Timeout::Error, Errno::ECONNRESET
      print_error("#{ip}:#{port} - Connection Failed.")
      print_line
    rescue ::Interrupt
      raise $!
    ensure
      if s
        disconnect(s) rescue nil
      end
    end
  end

end
