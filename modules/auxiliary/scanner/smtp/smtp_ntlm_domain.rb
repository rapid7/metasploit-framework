##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Smtp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'SMTP NTLM Domain Extraction',
      'Description' => 'Extract the Windows domain name from an SMTP NTLM challenge.',
      'References'  => [ ['URL', 'http://msdn.microsoft.com/en-us/library/cc246870.aspx' ] ],
      'Author'      => [ 'Rich Whitcroft <rwhitcroft[at]digitalboundary.net>' ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(25),
        OptString.new('EHLO_DOMAIN', [ true, 'The domain to send with the EHLO command', 'localhost' ]),
      ])

    deregister_options('MAILTO', 'MAILFROM')
  end

  def run_host(ip)
    begin
      domain = nil
      connect

      unless banner
        vprint_error("#{rhost}:#{rport} No banner received, aborting...")
        return
      end

      vprint_status("#{rhost}:#{rport} Connected: #{banner.strip.inspect}")

      # Report the last line of the banner as services information (typically the interesting one)
      report_service(host: rhost, port: rport, name: 'smtp', proto: 'tcp', info: banner.strip.split("\n").last)

      # Send a EHLO and parse the extensions returned
      sock.puts("EHLO " + datastore['EHLO_DOMAIN'] + "\r\n")

      # Find all NTLM references in the EHLO response
      exts = sock.get_once.to_s.split(/\n/).grep(/NTLM/)
      if exts.length == 0
        vprint_error("#{rhost}:#{rport} No NTLM extensions found")
        return
      end

      exts.each do |ext|

        # Extract the reply minus the first 4 chars (response code + dash)
        e = ext[4..-1].chomp

        # Try the usual AUTH NTLM approach if possible, otherwise echo the extension back to server
        if e =~ /AUTH.*NTLM/
          sock.puts("AUTH NTLM\r\n")
          vprint_status("#{rhost}:#{rport} Sending AUTH NTLM")
        else
          sock.puts(e + "\r\n")
          vprint_status("#{rhost}:#{rport} Sending #{e}")
        end

        # We expect a "334" code to go ahead with NTLM auth
        reply = sock.get_once.to_s
        if reply !~ /^334\s+/m
          vprint_status("#{rhost}:#{rport} Expected a 334 response, received #{reply.strip.inspect} aborting...")
          break
        else
          # Send the NTLM AUTH blob to tell the server we're ready to auth
          blob = "TlRMTVNTUAABAAAAt4II4gAAAAAAAAAAAAAAAAAAAAAFAs4OAAAADw=="
          sock.puts(blob + "\r\n")

          # Capture the challenge sent by server
          challenge = sock.get_once.to_s.split(/\s+/).last

          if challenge.length == 0
            vprint_status("#{rhost}:#{rport} Empty challenge response, aborting...")
            break
          end

          begin
            # Extract the domain out of the NTLM response
            ntlm_reply = Rex::Proto::NTLM::Message.parse(Rex::Text.decode_base64(challenge))
            if ! ntlm_reply && ntlm_reply.has_key?(:target_name)
              vprint_status("#{rhost}:#{rport} Invalid challenge response, aborting...")
              break
            end

            # TODO: Extract the server name from :target_info as well
            domain = ntlm_reply[:target_name].value.to_s.gsub(/\x00/, '')
            if domain.to_s.length == 0
              vprint_status("#{rhost}:#{rport} Invalid target name in challenge response, aborting...")
              break
            end

            print_good("#{rhost}:#{rport} Domain: #{domain}")
            report_note(host: rhost, port: rport, proto: 'tcp', type: 'smtp.ntlm_auth_info', data: { domain: domain })
            break

          rescue ::Rex::ArgumentError
            vprint_status("#{rhost}:#{rport} Invalid challenge response message, aborting...")
            break
          end
        end
      end

      if ! domain
        vprint_error("#{rhost}:#{rport} No NTLM domain found")
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Timeout::Error
      # Ignore common networking and response timeout errors
    ensure
      disconnect
    end
  end
end
