##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::WmapScanSSL
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  include Rex::Socket::Comm

  def initialize
    super(
      'Name'        => 'HTTP SSL Certificate Information',
      'Description' => 'Parse the server SSL certificate to obtain the common name and signature algorithm',
      'Author'      =>
        [
          'et', #original module
          'Chris John Riley', #additions
          'Veit Hailperin <hailperv[at]gmail.com>', # checks for public key size, valid time
        ],
      'License'     => MSF_LICENSE
    )
    register_options([
      Opt::RPORT(443)
    ], self.class)
  end

  # Fingerprint a single host
  def run_host(ip)

    begin

      connect(true, {"SSL" => true}) #Force SSL

      cert = OpenSSL::X509::Certificate.new(sock.peer_cert)

      disconnect

      if cert
        print_status("#{ip}:#{rport} Subject: #{cert.subject}")
        print_status("#{ip}:#{rport} Issuer: #{cert.issuer}")
        print_status("#{ip}:#{rport} Signature Alg: #{cert.signature_algorithm}")
        public_key_size = cert.public_key.n.num_bytes * 8
        print_status("#{ip}:#{rport} Public Key Size: #{public_key_size} bits")
        print_status("#{ip}:#{rport} Not Valid Before: #{cert.not_before}")
        print_status("#{ip}:#{rport} Not Valid After: #{cert.not_after}")

        # Checks for common properties of self signed certificates
        caissuer = (/CA Issuers - URI:(.*?),/i).match(cert.extensions.to_s)

        if caissuer.to_s.empty?
          print_good("#{ip}:#{rport} Certificate contains no CA Issuers extension... possible self signed certificate")
        else
          print_status("#{ip}:#{rport} " +caissuer.to_s[0..-2])
        end

        if cert.issuer.to_s == cert.subject.to_s
          print_good("#{ip}:#{rport} Certificate Subject and Issuer match... possible self signed certificate")
        end

        alg = cert.signature_algorithm

        if alg.downcase.include? "md5"
          print_status("#{ip}:#{rport} WARNING: Signature algorithm using MD5 (#{alg})")
        end

        vhostn = nil
        cert.subject.to_a.each do |n|
          vhostn = n[1] if n[0] == 'CN'
        end
        if public_key_size == 1024
          print_status("#{ip}:#{rport} WARNING: Public Key only 1024 bits")
        elsif public_key_size < 1024
          print_status("#{ip}:#{rport} WARNING: Weak Public Key: #{public_key_size} bits")
        end
        if cert.not_after < Time.now
          print_status("#{ip}:#{rport} WARNING: Certificate not valid anymore")
        end
        if cert.not_before > Time.now
          print_status("#{ip}:#{rport} WARNING: Certificate not valid yet")
        end

        if vhostn
          print_status("#{ip}:#{rport} has common name #{vhostn}")

          # Store the virtual hostname for HTTP
          report_note(
            :host	=> ip,
            :port	=> rport,
            :proto  => 'tcp',
            :type	=> 'http.vhost',
            :data	=> {:name => vhostn}
          )

          # Store the SSL certificate itself
          report_note(
            :host	=> ip,
            :proto  => 'tcp',
            :port	=> rport,
            :type	=> 'ssl.certificate',
            :data	=> {
              :cn        => vhostn,
              :subject   => cert.subject.to_a,
              :algorithm => alg,
              :valid_from => cert.not_before,
              :valid_after => cert.not_after,
              :key_size => public_key_size

            }
          )

          # Update the server hostname if necessary
          if vhostn !~ /localhost|snakeoil/i
            report_host(
              :host => ip,
              :name => vhostn
            )
          end

        end
      else
        print_status("#{ip}:#{rport}] No certificate subject or common name found")
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
