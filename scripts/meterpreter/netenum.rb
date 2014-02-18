#Meterpreter script for ping sweeps on Windows 2003, Windows Vista
#Windows 2008 and Windows XP targets using native windows commands.
#Provided by Carlos Perez at carlos_perez[at]darkoperator.com
#Verion: 0.1.2
#Note:
################## Variable Declarations ##################
@@exec_opts = Rex::Parser::Arguments.new(
  "-h"  => [ false, "Help menu." ],
  "-r"  => [ true,  "The target address range or CIDR identifier" ],
  "-ps" => [ false, "To Perform Ping Sweep on IP Range" ],
  "-rl" => [ false, "To Perform DNS Reverse Lookup on IP Range" ],
  "-fl" => [ false, "To Perform DNS Forward Lookup on host list and domain" ],
  "-hl" => [ true,  "File with Host List for DNS Forward Lookup" ],
  "-d"  => [ true,  "Domain Name for DNS Forward Lookup" ],
  "-st" => [ false, "To Perform DNS lookup of MX and NS records for a domain" ],
  "-sr" => [ false, "To Perform Service Record DNS lookup for a domain" ]
)
session = client
host,port = session.session_host, session.session_port

# Create Filename info to be appended to downloaded files
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

# Create a directory for the logs
logs = ::File.join(Msf::Config.log_directory,'scripts', 'netenum', host)

# Create the log directory
::FileUtils.mkdir_p(logs)

#logfile name
dest = logs + "/" + host + filenameinfo

#-------------------------------------------------------------------------------
# Function for performing regular lookup of MX and NS records
def stdlookup(session, domain, dest)
  dest = dest + "-general-record-lookup.txt"
  print_status("Getting MX and NS Records for domain #{domain}")
  filewrt(dest,"SOA, NS and MX Records for domain #{domain}")
  types = ["SOA","NS","MX"]
  mxout = []
  results = []
  garbage = []
  types.each do |t|
    begin
      r = session.sys.process.execute("nslookup -type=#{t} #{domain}", nil, {'Hidden' => true, 'Channelized' => true})
      while(d = r.channel.read)
        mxout << d
      end
      r.channel.close
      r.close
      results = mxout.join.split(/\n/)
      results.each do |rec|
        if  rec.match(/\s*internet\saddress\s\=\s/)
          garbage << rec.split(/\s*internet\saddress\s\=/)
          print_status("#{garbage[0].join.sub(" ","   ")} #{t} ")
          filewrt(dest,garbage[0].join.sub(" ","   ")+" #{t} ")
          garbage.clear
        end
        garbage.clear
      end

    rescue ::Exception => e
      print_status("The following error was encountered: #{e.class} #{e}")
    end
  end
end

#-------------------------------------------------------------------------------
# Function for writing results of other functions to a file
def filewrt(file2wrt, data2wrt)
  output = ::File.open(file2wrt, "ab")
  data2wrt.each_line do |d|
    output.puts(d)
  end
  output.close
end

#-------------------------------------------------------------------------------
# Function for Executing Reverse lookups
def reverselookup(session, iprange, dest)
  dest = dest + "-DNS-reverse-lookup.txt"
  print_status("Performing DNS reverse lookup for IP range #{iprange}")
  filewrt(dest,"DNS reverse lookup for IP range #{iprange}")
  iplst =[]
  i, a = 0, []
  begin
    ipadd = Rex::Socket::RangeWalker.new(iprange)
    numip = ipadd.num_ips
    while (iplst.length < numip)
      ipa = ipadd.next_ip
      if (not ipa)
        break
      end
      iplst << ipa
    end
    begin
      iplst.each do |ip|
        if i < 10
          a.push(::Thread.new {
              r = session.sys.process.execute("nslookup #{ip}", nil, {'Hidden' => true, 'Channelized' => true})
              while(d = r.channel.read)
                if d =~ /(Name)/
                  d.scan(/Name:\s*\S*\s/) do |n|
                    hostname = n.split(":    ")
                    print_status "\t #{ip} is #{hostname[1].chomp("\n")}"
                    filewrt(dest,"#{ip} is #{hostname[1].chomp("\n")}")
                  end
                  break

                end

              end

              r.channel.close
              r.close

            })
          i += 1
        else
          sleep(0.05) and a.delete_if {|x| not x.alive?} while not a.empty?
          i = 0
        end
      end
      a.delete_if {|x| not x.alive?} while not a.empty?
    end
  rescue ::Exception => e
    print_status("The following error was encountered: #{e.class} #{e}")
  end
end

#-------------------------------------------------------------------------------
#Function for Executing Forward Lookups
def frwdlp(session, hostlst, domain, dest)
  dest = dest + "-DNS-forward-lookup.txt"
  print_status("Performing DNS forward lookup for hosts in #{hostlst} for domain #{domain}")
  filewrt(dest,"DNS forward lookup for hosts in #{hostlst} for domain #{domain}")
  result = []
  threads = []
  tmpout = []
  begin
    if ::File.exists?(hostlst)
      ::File.open(hostlst).each {|line|
        threads << ::Thread.new(line) { |h|
          #print_status("checking #{h.chomp}")
          r = session.sys.process.execute("nslookup #{h.chomp}.#{domain}", nil, {'Hidden' => true, 'Channelized' => true})
          while(d = r.channel.read)
            if d =~ /(Name)/
              d.scan(/Name:\s*\S*\s*Address\w*:\s*.*?.*?.*/) do |n|
                tmpout << n.split
              end
              break
            end
          end

          r.channel.close
          r.close
        }
      }
      threads.each { |aThread|  aThread.join }
      tmpout.uniq.each do |t|
        print_status("\t#{t.join.sub(/Address\w*:/, "\t")}")
        filewrt(dest,"#{t.join.sub(/Address\w*:/, "\t")}")
      end

    else
      print_status("File #{hostlst} doesn't exists!")
      exit
    end
  rescue ::Exception => e
    print_status("The following error was encountered: #{e.class} #{e}")
  end
end

#-------------------------------------------------------------------------------
#Function for Executing Ping Sweep
def pingsweep(session, iprange, dest)
  dest = dest + "-pingsweep.txt"
  print_status("Performing ping sweep for IP range #{iprange}")
  filewrt(dest,"Ping sweep for IP range #{iprange}")
  iplst = []
  begin
    i, a = 0, []
    ipadd = Rex::Socket::RangeWalker.new(iprange)
    numip = ipadd.num_ips
    while (iplst.length < numip)
      ipa = ipadd.next_ip
      if (not ipa)
        break
      end
      iplst << ipa
    end
    begin
      iplst.each do |ip|
        if i < 10
          a.push(::Thread.new {
              r = session.sys.process.execute("ping #{ip} -n 1", nil, {'Hidden' => true, 'Channelized' => true})
              while(d = r.channel.read)
                if d =~ /(Reply)/
                  print_status "\t#{ip} host found"
                  filewrt(dest,"#{ip} host found")
                  r.channel.close
                elsif d =~ /(Antwort)/
                  print_status "\t#{ip} host found"
                  filewrt(dest,"#{ip} host found")
                  r.channel.close
                end
              end
              r.channel.close
              r.close

            })
          i += 1
        else
          sleep(0.05) and a.delete_if {|x| not x.alive?} while not a.empty?
          i = 0
        end
      end
      a.delete_if {|x| not x.alive?} while not a.empty?
    end
  rescue ::Exception => e
    print_status("The following error was encountered: #{e.class} #{e}")
  end
end
#-------------------------------------------------------------------------------
#Function for enumerating srv records
def srvreclkp(session, domain, dest)
  dest = dest + "-srvenum.txt"
  srout = []
  garbage = []
  srvrcd = [
    "_gc._tcp.","_kerberos._tcp.", "_kerberos._udp.","_ldap._tcp.","_test._tcp.",
    "_sips._tcp.","_sip._udp.","_sip._tcp.","_aix._tcp.","_aix._tcp.","_finger._tcp.",
    "_ftp._tcp.","_http._tcp.","_nntp._tcp.","_telnet._tcp.","_whois._tcp."
  ]
  print_status("Performing SRV record enumeration for #{domain}")
  filewrt(dest,"SRV record enumeration for #{domain}")
  srvrcd.each do |srv|
    r = session.sys.process.execute("nslookup -query=srv #{srv}#{domain}", nil, {'Hidden' => true, 'Channelized' => true})
    while(d = r.channel.read)
      srout << d
    end
    r.channel.close
    r.close
    results = srout.join.split(/\n/)
    results.each do |rec|
        if  rec.match(/\s*internet\saddress\s\=\s/)
          garbage << rec.split(/\s*internet\saddress\s\=/)
          print_status("\tfor #{srv}#{domain}   #{garbage[0].join.sub(" ","   ")}")
          filewrt(dest,"for #{srv}#{domain}   #{garbage[0].join.sub(" ","   ")}")
          garbage.clear
        end
    garbage.clear
    srout.clear
    end
  end

end
#-------------------------------------------------------------------------------
#Function to print message during run
def message(dest)
  print_status "Network Enumerator Meterpreter Script "
  print_status "Log file being saved in #{dest}"
end

################## MAIN ##################
# Variables for Options
stdlkp = nil
range = nil
pngsp = nil
rvrslkp = nil
frdlkp = nil
dom = nil
hostlist = nil
helpcall = nil
srvrc = nil

# Parsing of Options
@@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-sr"
    srvrc = 1
  when "-rl"
    rvrslkp = 1
  when "-fl"
    frdlkp = 1
  when "-ps"
    pngsp = 1
  when "-st"
    stdlkp = 1
  when "-d"
    dom = val
  when "-hl"
    hostlist = val
  when "-r"
    range = val
  when "-h"
    print(
      "Network Enumerator Meterpreter Script\n" +
      "Usage:\n" +
      @@exec_opts.usage
      )
    helpcall = 1
  end
}

if client.platform =~ /win32|win64/
  if  pngsp == 1
    if range != nil
      message(logs)
      pingsweep(session, range, dest)
    else
      print_error("Please add a range to scan: -r <value>")
    end
  elsif rvrslkp == 1
    if range != nil
      message(logs)
      reverselookup(session, range, dest)
    else
      print_error("Please add a range to scan: -r <value>")
    end
  elsif frdlkp == 1
    if dom != nil && hostlist!= nil &&
      message(logs)
      frwdlp(session, hostlist, dom, dest)
    elsif dom == nil
      print_error("Please add a domain name for DNS forward lookup: -d <value>")
    elsif hostlist == nil
      print_error("Please add a file with host list for DNS forward lookup: -hl <value>")
    else
      print_error("Something went wront")
    end
  elsif stdlkp == 1
    if dom != nil
      message(logs)
      stdlookup(session, dom, dest)
    else
      print_error("Please add a domain name for DNS forward lookup: -d <value>")
    end
  elsif srvrc == 1
    if dom != nil
      message(logs)
      srvreclkp(session, dom, dest)
    else
      print_error("Please add a domain name for DNS forward lookup: -d <value>")
    end
  else
    print("Network Enumerator Meterpreter Script\n" +
      "Usage:\n" +
      "\tnetenum -r <value> (-ps | -rl)\n" +
      "\tnetenum -d <value> (-st | -sr)\n" +
      "\tnetenum -d <value> -lh <value> -fl\n" +
      @@exec_opts.usage)
  end
else
  print_error("This version of Meterpreter is not supported with this script!")
  raise Rex::Script::Completed
end
