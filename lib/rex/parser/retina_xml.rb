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
    return if str.strip.empty?

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

__END__
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

