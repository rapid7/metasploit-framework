# -*- coding:binary -*-

require 'rex/parser/nmap_xml'

xml = '
<?xml version="1.0" ?>
<?xml-stylesheet href="/usr/share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 4.76 scan initiated Thu Nov 12 19:54:47 2009 as: nmap -p22,80 -A -oX nmap.xml -T5 192.168.0.1 -->
<nmaprun scanner="nmap" args="nmap -p22,80 -A -oX nmap.xml -T5 192.168.0.1" start="1258080887" startstr="Thu Nov 12 19:54:47 2009" version="4.76" xmloutputversion="1.02">
<scaninfo type="connect"  protocol="tcp" numservices="2" services="22,80" />
<verbose level="0" />
<debugging level="0" />
<host starttime="1258080887" endtime="1258080893"><status state="up" reason="syn-ack"/>
<address addr="192.168.0.1" addrtype="ipv4" />
<hostnames><hostname name="localhost" type="PTR" /></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" extrainfo="protocol 2.0" servicefp="SF-Port22-TCP:V=4.76%I=7%D=11/12%Time=4AFCCA7D%P=i686-pc-linux-gnu%r(NULL,&#xa;SF:27,&quot;SSH-2\.0-OpenSSH_5\.1p1\x20Debian-5ubuntu1\r\n&quot;);" method="probed" conf="10" /></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="Apache httpd" version="2.2.11" extrainfo="(Ubuntu) PHP/5.2.6-3ubuntu4.2 with Suhosin-Patch" method="probed" conf="10" /></port>
</ports>
<times srtt="119" rttvar="2882" to="50000" />
</host>
<runstats><finished time="1258080893" timestr="Thu Nov 12 19:54:53 2009"/><hosts up="1" down="0" total="1" />
<!-- Nmap done at Thu Nov 12 19:54:53 2009; 1 IP address (1 host up) scanned in 6.43 seconds -->
</runstats></nmaprun>
'

RSpec.describe Rex::Parser::NmapXMLStreamParser do
  parser = Rex::Parser::NmapXMLStreamParser.new
  total_hosts = 0
  parser.on_found_host = Proc.new { |host|
    total_hosts += 1
    it "should yield a host" do
      expect(host).not_to be_nil
    end
    it "should populate the host with proper keys" do
      expect(host).to have_key("status")
      expect(host).to have_key("ports")
      expect(host).to have_key("addrs")
      expect(host["ports"]).to be_a(Array)
      expect(host["addrs"]).to be_a(Hash)
    end
    it "should find the address" do
      expect(host["addrs"].keys.length).to eq 1
      expect(host["addrs"]).to have_key("ipv4")
      expect(host["addrs"]["ipv4"]).to eq "192.168.0.1"
    end
  }
  REXML::Document.parse_stream(StringIO.new(xml), parser)
  it "should have found exactly one host" do
    expect(total_hosts).to eq 1
  end
end

