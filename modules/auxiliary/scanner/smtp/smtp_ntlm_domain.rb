##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Smtp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'SMTP NTLM Domain Extraction',
      'Description' => 'Extract the Windows domain name given an NTLM challenge.',
      'References'  => [ ['URL', 'http://msdn.microsoft.com/en-us/library/cc246870.aspx' ] ],
      'Author'      => [ 'Rich Whitcroft <rwhitcroft@digitalboundary.net>' ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(25),
        OptString.new('EHLO_DOMAIN', [ true, 'The domain to send with the EHLO command', 'localhost' ]),
      ], self.class)

    deregister_options('MAILTO', 'MAILFROM')
  end

  def run_host(ip)
    begin
      domain = nil
      connect
      print_status("Connected to #{ip}:#{datastore['RPORT']}")

      # send a EHLO and parse the extensions returned
      sock.puts("EHLO " + datastore['EHLO_DOMAIN'] + "\r\n")
      exts = sock.get_once.split(/\n/)

      # loop through all returned extensions related to NTLM
      exts.grep(/NTLM/).each do |ext|

        # extract the reply minus the first 4 chars (response code + dash)
        e = ext[4..-1].chomp

        # try the usual AUTH NTLM approach if possible, otherwise echo the extension back to server
        if e =~ /AUTH.*NTLM/
          sock.puts("AUTH NTLM\r\n")
        else
          sock.puts(e + "\r\n")
        end

        # we expect a "334" code to go ahead with NTLM auth
        reply = sock.get_once
        if reply.include?("334")
          # send the NTLM AUTH blob to tell the server we're ready to auth
          blob = "TlRMTVNTUAABAAAAt4II4gAAAAAAAAAAAAAAAAAAAAAFAs4OAAAADw=="
          sock.puts(blob + "\r\n")

          # capture the challenge sent by server
          challenge = sock.get_once.split.last

          # and extract the domain out of it
          domain = Rex::Proto::NTLM::Message.parse(Rex::Text.decode_base64(challenge))[:target_name].value().gsub(/\0/, '')
          print_good("Domain: #{domain}")
        else
          print_error("Error in response: expected '334', aborting")
        end
      end

      print_error("#{ip}: No NTLM extensions found") if domain.nil? or domain.empty?

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue Timeout::Error => err
      print_error(err.message)
    ensure
      disconnect
    end
  end

end
