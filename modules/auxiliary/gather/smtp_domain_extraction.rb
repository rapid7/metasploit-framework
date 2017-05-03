require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'SMTP Domain Extraction via NTLM',
      'Description'    => %q{
        Extract the name of the internal Windows domain by
        parsing the NTLM challenge sent by the SMTP server.
      },
      'Author'         => [ 'Rich Whitcroft <rwhitcroft@digitalboundary.net>' ],
      'References'     => [ [ 'URL', 'http://msdn.microsoft.com/en-us/library/cc246870.aspx' ] ]
    ))

    register_options(
      [
        Opt::RHOST(),
        Opt::RPORT(25)
      ], self.class)
  end

  def run
    begin
      connect

      # wait for banner
      banner = sock.get_once

      # send a EHLO
      sock.puts("EHLO localhost\r\n")

      # see if there are any NTLM extensions
      ntlm_exts = sock.get_once.split("\r\n")
      if ntlm_exts.empty?
        print_error("No NTLM extensions found")
        disconnect
        return
      end

      ntlm_exts.grep(/NTLM/) do |e|
        cmd = e[4..-1]
        sock.puts("#{cmd}\r\n")
        reply = sock.get_once

        if reply.include?("334")
          ntlm_blob = "TlRMTVNTUAABAAAAt4II4gAAAAAAAAAAAAAAAAAAAAAFAs4OAAAADw=="
          sock.puts(ntlm_blob + "\r\n")
          ntlm_challenge = sock.get_once.split.last

          if ntlm_challenge.nil? or ntlm_challenge.empty?
            print_error("Error receiving NTLM challenge")
            disconnect
            return
          else
            decoded = Base64.strict_decode64(ntlm_challenge)
            domain = ""
            for i in 56..(decoded.size)
              break if decoded[i].ord == 2
              domain += decoded[i].to_s
            end
            print_good("Found domain: #{domain}")
          end

        else
          print_error("Incorrect reply, expecting '334': #{reply}")
          disconnect
          return
        end

        disconnect
      end

    rescue ::Rex::ConnectionRefused
      print_error("Connection refused")
    rescue ::Rex::HostUnreachable
      print_error("Host unreachable")
    rescue ::Rex::ConnectionTimeout, Timeout::Error
      print_error("Connection timed out")
    end
  end

end
