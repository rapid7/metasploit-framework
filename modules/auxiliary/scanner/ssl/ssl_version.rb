##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Module::Deprecated

  moved_from 'auxiliary/scanner/http/ssl'
  moved_from 'auxiliary/scanner/http/ssl_version'

  def initialize
    super(
      'Name' => 'SSL/TLS Version Detection',
      'Description' => %q{
        Check if a server supports a given version of SSL/TLS and cipher suites.

        The certificate is stored in loot, and any known vulnerabilities against that
        SSL version and cipher suite combination are checked. These checks include
        POODLE, deprecated protocols, expired/not valid certs, low key strength, null cipher suites,
        certificates signed with MD5, DROWN, RC4 ciphers, exportable ciphers, LOGJAM, and BEAST.
      },
      'Author' => [
        'todb', # original ssl scanner for poodle
        'et', # original ssl certificate module
        'Chris John Riley', # original ssl certificate additions
        'Veit Hailperin <hailperv[at]gmail.com>', # original ssl certificate checks for public key size, valid time
        'h00die' # combining, modernization
      ],
      'License' => MSF_LICENSE,
      'DefaultOptions' => {
        'SSL' => true,
        'RPORT' => 443
      },
      'References' => [
        # poodle
        [ 'URL', 'https://security.googleblog.com/2014/10/this-poodle-bites-exploiting-ssl-30.html' ],
        [ 'CVE', '2014-3566' ],
        [ 'URL', 'https://www.openssl.org/~bodo/ssl-poodle.pdf' ],
        # tls deprecation
        [ 'URL', 'https://datatracker.ietf.org/doc/rfc8996/' ],
        # md5 signed certs
        [ 'URL', 'https://www.win.tue.nl/hashclash/rogue-ca/' ],
        # DROWN attack
        [ 'URL', 'https://drownattack.com/' ],
        [ 'CVE', '2016-0800' ],
        # BEAST
        [ 'CVE', '2011-3389' ],
        # RC4
        [ 'URL', 'http://www.isg.rhul.ac.uk/tls/' ],
        [ 'CVE', '2013-2566' ],
        # LOGJAM
        [ 'CVE', '2015-4000' ],
      ],
      'DisclosureDate' => 'Oct 14 2014'
    )

    register_options(
      [
        OptEnum.new('SSLVersion', [ true, 'SSL versions to test', 'All', ['All'] + Array.new(OpenSSL::SSL::SSLContext.new.ciphers.length) { |i| (OpenSSL::SSL::SSLContext.new.ciphers[i][1]).to_s }.uniq.reverse]),
        OptEnum.new('SSLCipher', [ true, 'SSL ciphers to test', 'All', ['All'] + Array.new(OpenSSL::SSL::SSLContext.new.ciphers.length) { |i| (OpenSSL::SSL::SSLContext.new.ciphers[i][0]).to_s }.uniq]),
      ]
    )
  end

  def get_metasploit_ssl_versions
    # originally we used OpenSSL::SSL::SSLContext here, but it gives back ssl versions
    # with no cipher suites, and therefore we can't use them, or they are invalid.
    # this method only lists valid connectable ones. Original method from:
    # https://github.com/rapid7/rex-socket/blob/6ea0bb3b4e19c53d73e4337617be72c0ed351ceb/lib/rex/socket/ssl_tcp.rb#L46

    # If the user specified that we should use all available SSL versions, then get the list of the ciphers
    # that the Metasploit host supports using OpenSSL::SSL::SSLContext and grab the 2nd element, aka the
    # SSL version that the cipher can work with (can be multiple entries to combine a particular cipher with
    # a given SSL version. Then uniq the resulting array so that we only get unique entries before reversing
    # so that SSL versions come first, then TLS versions.
    if datastore['SSLVersion'] == 'All'
      return Array.new(OpenSSL::SSL::SSLContext.new.ciphers.length) { |i| (OpenSSL::SSL::SSLContext.new.ciphers[i][1]).to_s }.uniq.reverse
    end

    datastore['SSLVersion']
  end

  def get_metasploit_ssl_cipher_suites(ssl_version)
    # Originally this method used OpenSSL::Cipher.ciphers.
    # However that gives back ciphers that are invalid for a SSL version
    # which resulted in a lot of errors being thrown. This method 
    # is much more accurate.

    # First find all valid ciphers that the Metasploit host supports.
    # Also transform the SSL version to a standard format..
    ssl_version = ssl_version.to_s.gsub('_', '.')
    all_ciphers = OpenSSL::SSL::SSLContext.new.ciphers
    valid_ciphers = []

    # For each cipher that the Metasploit host supports, determine if that cipher 
    # is supported for use with the SSL version passed into this function.
    all_ciphers.each do |cipher|
      # cipher list has struct of [cipher, ssl_version, <int>, <int>]
      if cipher[1] == ssl_version
        valid_ciphers << cipher[0]
      end
    end

    # If the user wants to use all ciphers then return all valid ciphers.
    # Otherwise return only those that match the ones the user specified
    # in the SSLCipher datastore option.
    #
    # If no match is found for some reason then we will return an empty array.
    if datastore['SSLCipher'] == 'All'
      return valid_ciphers
    elsif valid_ciphers.contains? datastore['SSLCipher']
      return [datastore['SSLCipher']]
    end

    []
  end

  def public_key_size(cert)
    if cert.public_key.respond_to? :n
      return cert.public_key.n.num_bytes * 8
    end

    0
  end

  def print_cert(cert, ip)
    if cert
      print_status('Certificate Information:')
      print_status("\tSubject: #{cert.subject}")
      print_status("\tIssuer: #{cert.issuer}")
      print_status("\tSignature Alg: #{cert.signature_algorithm}")

      # If we use ECDSA rather than RSA, our metrics for key size are different
      print_status("\tPublic Key Size: #{public_key_size(cert)} bits")

      print_status("\tNot Valid Before: #{cert.not_before}")
      print_status("\tNot Valid After: #{cert.not_after}")

      # Checks for common properties of self signed certificates
      caissuer = nil
      cert.extensions.each do |e|
        e = e.to_s
        if /CA Issuers - URI:([^, \n]*)/i.match(e)
          caissuer = /CA Issuers - URI:([^, \n]*)/i.match(e)
          break
        end
      end

      if caissuer.nil?
        print_good("\tCertificate contains no CA Issuers extension... possible self signed certificate")
      else
        print_status("\t#{caissuer}")
      end

      if cert.issuer.to_s == cert.subject.to_s
        print_good("\tCertificate Subject and Issuer match... possible self signed certificate")
      end

      alg = cert.signature_algorithm

      if alg.downcase.include? 'md5'
        print_status("\tWARNING: Signature algorithm using MD5 (#{alg})")
      end

      vhostn = nil
      # Convert the certificate subject field into a series of arrays.
      # For each array, which will represent one subject, then
      # go ahead and check if the subject describes a CN entry.
      #
      # If it does, then assign the value of vhost name, aka the 
      # second entry in the array,to vhostn
      cert.subject.to_a.each do |n|
        vhostn = n[1] if n[0] == 'CN'
      end

      if vhostn
        print_status("\tHas common name #{vhostn}")

        # Store the virtual hostname for HTTP
        report_note(
          host: ip,
          port: rport,
          proto: 'tcp',
          type: 'http.vhost',
          data: { name: vhostn }
        )

        # Update the server hostname if necessary
        if vhostn !~ /localhost|snakeoil/i
          report_host(
            host: ip,
            name: vhostn
          )
        end

      end
    else
      print_status("\tNo certificate subject or common name found.")
    end
  end

  def check_vulnerabilities(ip, ssl_version, ssl_cipher, cert)
    # POODLE
    if ssl_version == 'SSLv3'
      print_good('Accepts SSLv3, vulnerable to POODLE')
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} confirmed SSLv3 is available. Vulenrable to POODLE, CVE-2014-3566.",
        refs: 'CVE-2014-3566',
        exploited_at: Time.now.utc
      )
    end

    # DROWN
    if ssl_version == 'SSLv2'
      print_good('Accepts SSLv2, vulnerable to DROWN')
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} confirmed SSLv2 is available. Vulenrable to DROWN, CVE-2016-0800.",
        refs: 'CVE-2016-0800',
        exploited_at: Time.now.utc
      )
    end

    # BEAST
    if ((ssl_version == 'SSLv3') || (ssl_version == 'TLSv1.0')) && ssl_cipher.include?('CBC')
      print_good('Accepts SSLv3/TLSv1 and a CBC cipher, vulnerable to BEAST')
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} confirmed SSLv3/TLSv1 and a CBC cipher. Vulenrable to BEAST, CVE-2011-3389.",
        refs: 'CVE-2011-3389',
        exploited_at: Time.now.utc
      )
    end

    # RC4 ciphers
    if ssl_cipher.upcase.include?('RC4')
      print_good('Accepts RC4 cipher.')
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} confirmed RC4 cipher. CVE-2013-2566.",
        refs: 'CVE-2013-2566',
        exploited_at: Time.now.utc
      )
    end

    # export ciphers
    if ssl_cipher.upcase.include?('EXPORT')
      print_good('Accepts EXPORT based cipher.')
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} confirmed EXPORT based cipher.",
        refs: references,
        exploited_at: Time.now.utc
      )
    end
    # LOGJAM
    if ssl_cipher.upcase.include?('DHE_EXPORT')
      print_good('Accepts DHE_EXPORT based cipher.')
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} confirmed DHE_EXPORT based cipher. Vulnerable to LOGJAM, CVE-2015-4000",
        refs: 'CVE-2015-4000',
        exploited_at: Time.now.utc
      )
    end

    # Null ciphers
    if ssl_cipher.upcase.include? 'NULL'
      print_good('Accepts Null cipher')
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} confirmed Null cipher.",
        refs: 'CVE-2011-3389',
        exploited_at: Time.now.utc
      )
    end

    # deprecation
    if ssl_version == 'SSLv2'
      print_good('Accepts Deprecated SSLv2')
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} confirmed SSLv2. Which was deprecated in 2011",
        refs: 'https://datatracker.ietf.org/doc/html/rfc6176',
        exploited_at: Time.now.utc
      )
    elsif ssl_version == 'SSLv3'
      print_good('Accepts Deprecated SSLv3')
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} confirmed SSLv3. Which was deprecated in 2015",
        refs: 'https://datatracker.ietf.org/doc/html/rfc7568',
        exploited_at: Time.now.utc
      )
    elsif ssl_version == 'TLSv1.0'
      print_good('Accepts Deprecated TLSv1.0')
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} confirmed TLSv1.0. Which was widely deprecated in 2020",
        refs: 'https://datatracker.ietf.org/doc/html/rfc7568',
        exploited_at: Time.now.utc
      )
    end

    return if cert.nil?

    key_size = public_key_size(cert)
    if key_size > 0
      if key_size == 1024
        print_good('Public Key only 1024 bits')
        report_vuln(
          host: ip,
          port: rport,
          proto: 'tcp',
          name: name,
          info: "Module #{fullname} confirmed certificate key size 1024 bits",
          refs: references,
          exploited_at: Time.now.utc
        )
      elsif key_size < 1024
        print_good('Public Key < 1024 bits')
        report_vuln(
          host: ip,
          port: rport,
          proto: 'tcp',
          name: name,
          info: "Module #{fullname} confirmed certificate key size < 1024 bits",
          refs: references,
          exploited_at: Time.now.utc
        )
      end
    end

    # certificate signed md5
    alg = cert.signature_algorithm

    if alg.downcase.include? 'md5'
      print_good('Certificate signed with MD5')
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} confirmed certificate signed with MD5 algo",
        refs: references,
        exploited_at: Time.now.utc
      )
    end

    # expired
    if cert.not_after <= DateTime.now
      print_good("Certificate expired: #{cert.not_after}")
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} confirmed certificate expired",
        refs: references,
        exploited_at: Time.now.utc
      )
    end

    # not yet valid
    if cert.not_before > DateTime.now
      print_good("Certificate not yet valid: #{cert.not_after}")
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} confirmed certificate not yet valid",
        refs: references,
        exploited_at: Time.now.utc
      )
    end
  end

  # Fingerprint a single host
  def run_host(ip)
    # Get the available SSL/TLS versions that that Metasploit host supports
    versions = get_metasploit_ssl_versions

    certs_found = {}
    skip_ssl_version = false
    vprint_status("Scanning #{ip} for: #{versions.map(&:to_s).join(', ')}")

    # For each SSL/TLS version...
    versions.each do |version|
      skip_ssl_version = false

      # Get the cipher suites that SSL/TLS can use on the Metasploit host
      # and print them out.
      ciphers = get_metasploit_ssl_cipher_suites(version)
      vprint_status("Scanning #{ip} #{version} with ciphers: #{ciphers.map(&:to_s).join(', ')}")

      # For each cipher attempt to connect to the server. If we could connect with the given SSL version,
      # then skip it and move onto the next one. If the cipher isn't supported, then note this.
      # If the server responds with a peer certificate, make a new certificate object from it and find
      # its fingerprint, then check it for vulnerabilities, before saving it to loot if it hasn't been
      # saved already (check done using the certificate's SHA1 hash).
      # 
      # In all cases the SSL version and cipher combination will also be checked for vulnerabilities 
      # using the check_vulnerabilities function.
      ciphers.each do |cipher|
        break if skip_ssl_version

        vprint_status("Attempting connection with SSL Version: #{version}, Cipher: #{cipher}")
        begin
          # setting the connect global to false means we can't see the socket, therefore the cert
          connect(true, { 'SSL' => true, 'SSLVersion' => version.sub('.', '_').to_sym, 'SSLCipher' => cipher }) # Force SSL
          print_good("Connected with SSL Version: #{version}, Cipher: #{cipher}")

          if sock.respond_to? :peer_cert
            cert = OpenSSL::X509::Certificate.new(sock.peer_cert)
            # https://stackoverflow.com/questions/16516555/ruby-code-for-openssl-to-generate-fingerprint
            cert_fingerprint = OpenSSL::Digest::SHA1.new(cert.to_der).to_s
            if certs_found.key? cert_fingerprint
              # dont check the cert more than once if its the same cert
              check_vulnerabilities(ip, version, cipher, nil)
            else
              loot_cert = store_loot('ssl.certificate', 'text/plain', ip, cert.to_text)
              print_good("Certificate saved to loot: #{loot_cert}")
              print_cert(cert, ip)
              check_vulnerabilities(ip, version, cipher, cert)
            end
            certs_found[cert_fingerprint] = cert
          end
        rescue ::OpenSSL::SSL::SSLError => e
          error_message = e.message.match(/ state=(.+)$/)

          if error_message.nil?
            vprint_error("\tSSL Connection Error: #{e}")
            next
          end

          # catch if the ssl_version/protocol isn't allowed and then we can skip out of it.
          if error_message[1].include? 'no protocols available'
            skip_ssl_version = true
            vprint_error("\tDoesn't accept #{version} connections, Skipping")
            break
          end
          vprint_error("\tDoes not accept #{version}, error message: #{error_message[1]}")
        rescue ArgumentError => e
          if e.message.match(%r{This version of Ruby does not support the requested SSL/TLS version})
            skip_ssl_version = true
            vprint_error("\t#{e.message}, Skipping")
            break
          end
          print_error("Exception encountered: #{e}")
        rescue StandardError => e
          if e.message.match(/connection was refused/) || e.message.match(/timed out/)
            print_error("\tPort closed or timeout occured.")
            return 'Port closed or timeout occured.'
          end
          print_error("\tException encountered: #{e}")
        ensure
          disconnect
        end
      end
    end
  end
end
