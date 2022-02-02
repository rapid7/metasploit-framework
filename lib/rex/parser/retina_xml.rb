# -*- coding: binary -*-

module Rex
module Parser
# XXX - Retina XML does not include ANY service/port information export
class RetinaXMLStreamParser
  attr_accessor :on_found_host

  def initialize(on_found_host = nil)
    reset_state
    self.on_found_host = on_found_host if on_found_host
  end

  def reset_state
    @state = :generic_state
    @host  = { 'vulns' => [] }
    reset_audit_state
  end

  def reset_audit_state
    @audit = { 'refs' => [] }
  end

  def tag_start(name, attributes)
    @state = "in_#{name.downcase}".intern
  end

  def text(str)
    return if str.to_s.strip.empty?

    case @state
    when :in_ip
      @host["address"] = str
    when :in_dnsname
      @host["hostname"] = str.split(/\s+/).first
    when :in_netbiosname
      @host["netbios"] = str
    when :in_mac
      @host["mac"] = str.split(/\s+/).first
    when :in_os
      @host["os"] = str
    when :in_rthid
      @audit['refs'].push(['RETINA', str])
    when :in_cve
      str.split(",").each do |cve|
        cve = cve.to_s.strip
        next if cve.empty?
        pre,val = cve.split('-', 2)
        next if not val
        next if pre != "CVE"
        @audit['refs'].push( ['CVE', val] )
      end
    when :in_name
      @audit['name'] = str
    when :in_description
      @audit['description'] = str
    when :in_risk
      @audit['risk'] = str
    when :in_cce
      @audit['cce'] = str
    when :in_date
      @audit['data'] = str
    when :in_context
      @audit['proto'], @audit['port'] = str.split(/\s+/).first.split(':')
    end
  end

  def tag_end(name)
    case name
    when "host"
      on_found_host.call(@host) if on_found_host
      reset_state
    when "audit"
      @host['vulns'].push @audit
      reset_audit_state
    end
  end

  # We don't need these methods, but they're necessary to keep REXML happy
  def xmldecl(version, encoding, standalone); end
  def cdata; end
  def comment(str); end
  def instruction(name, instruction); end
  def attlist; end
end
end
end

=begin Old XML format
<scanJob>
  <hosts>
    <host>
      <ip>10.2.79.98</ip>
      <netBIOSName>bsmith-10156B07C</netBIOSName>
      <dnsName>bsmith-10156b07c.core.testcorp.com  random.testcorp.com</dnsName>
      <mac>00:02:29:0E:38:2B</mac>
      <os>Windows Server 2003 (X64), Service Pack 2</os>
      <audit>
        <rthID>7851</rthID>
        <cve>CVE-2009-0089,CVE-2009-0550,CVE-2009-0086</cve>
        <cce>N/A</cce>
        <name>Microsoft Windows HTTP Services Multiple Vulnerabilities (960803)</name>
        <description>Microsoft Windows HTTP Services contains multiple vulnerabilities when handling ..</description>
        <date>09/15/2010</date>
        <risk>Low</risk>
        <pciLevel>5 (Urgent)</pciLevel>
        <cvssScore>10 [AV:N/AC:L/Au:N/C:C/I:C/A:C]</cvssScore>
        <fixInformation>....</fixInformation>
      </audit>
    </host>
  </hosts>
</scanJob>
=end Old XML format

=begin New XML format
<?xml version="1.0" encoding="utf-8"?>
<scanJob>
  <hosts>
    <host>
      <ip>[redacted]</ip>
      <netBIOSName>[redacted]</netBIOSName>
      <dnsName>[redacted]</dnsName>
      <mac></mac>
      <os>[redacted]</os>
      <cpe>[redacted]</cpe>
      <audit>
        <cve>[redacted]</cve>
        <cce>N/A</cce>
        <name>TLS/SSL Weak Protocol Version Supported</name>
        <description>A targeted service that accepts connections for cryptographically weak SSL protocol versions (eg SSLv2, SSLv3, TLSv1.0) has been detected. Such protocols are known to have cryptographic weaknesses as well as other exploitable vulnerabilities.</description>
        <date>[redacted]</date>
        <risk>Medium</risk>
        <pciLevel>Medium</pciLevel>
        <pciReason>PCI DSS 4.1 - SSL Weakness</pciReason>
        <pciPassFail>Fail</pciPassFail>
        <cvssScore>4.3 [AV:N/AC:M/Au:N/C:P/I:N/A:N]</cvssScore>
        <cvssScoreV3>6.8 [AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N]</cvssScoreV3>
        <fixInformation>Ensure that applications or services are configured to reject SSLv3, SSLv2 and TLSv1.0 communications. Disabling weak protocols is a defense-in-depth measure against vulnerabilities that could allow SSL version downgrade attacks (e.g. CVE-2014-3566).</fixInformation>
        <exploit>No</exploit>
        <context>TCP:443 ([redacted]), SHA256[=][redacted], Serial[=][redacted]</context>
        <testedValue>Accepted SSL Method: (SSLv[23]|TLSv1(\.0)?)$</testedValue>
        <foundValue>[redacted]</foundValue>
        <cwe>CWE-310</cwe>
      </audit>
    </host>
  </hosts>
</scanJob>
=end New XML format
