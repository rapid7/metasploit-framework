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
        # TLS v1.0 and v1.1 depreciation
        [ 'URL', 'https://datatracker.ietf.org/doc/rfc8996/' ],
        # SSLv2 deprecation
        [ 'URL', 'https://datatracker.ietf.org/doc/html/rfc6176' ],
        # SSLv3 deprecation
        [ 'URL', 'https://datatracker.ietf.org/doc/html/rfc7568' ],
        # MD5 signed certs
        [ 'URL', 'https://www.win.tue.nl/hashclash/rogue-ca/' ],
        [ 'CWE', '328' ],
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
        # NULL ciphers
        [ 'CVE', '2022-3358' ],
        [ 'CWE', '319'],
        # certificate expired
        [ 'CWE', '298' ],
        # certificate broken or risky crypto aglorithms
        [ 'CWE', '327' ],
        # certificate inadequate encryption strength
        [ 'CWE', '326' ]
      ],
      'DisclosureDate' => 'Oct 14 2014'
    )

    register_options(
      [
        OptEnum.new('SSLVersion', [ true, 'SSL version to test', 'All', ['All'] + Array.new(OpenSSL::SSL::SSLContext.new.ciphers.length) { |i| (OpenSSL::SSL::SSLContext.new.ciphers[i][1]).to_s }.uniq.reverse]),
        OptEnum.new('SSLCipher', [ true, 'SSL cipher to test', 'All', ['All'] + Array.new(OpenSSL::SSL::SSLContext.new.ciphers.length) { |i| (OpenSSL::SSL::SSLContext.new.ciphers[i][0]).to_s }.uniq]),
      ]
    )
  end

  def get_metasploit_ssl_versions
    # There are two ways to generate a list of valid SSL Versions (SSLv3, TLS1.1, etc) and cipher suites (AES256-GCM-SHA384,
    # ECDHE-RSA-CHACHA20-POLY1305, etc). The first would be to generate them independently. It's possible to
    # pull all SSLContext methods (SSL Versions) via OpenSSL::SSL::SSLContext::METHODS here, as referenced in
    # https://github.com/rapid7/rex-socket/blob/6ea0bb3b4e19c53d73e4337617be72c0ed351ceb/lib/rex/socket/ssl_tcp.rb#L46
    # then pull all ciphers with OpenSSL::Cipher.ciphers. Now in theory you have a nice easy loop:
    #
    # OpenSSL::SSL::SSLContext::METHODS.each do |ssl_version|
    #    OpenSSL::Cipher.ciphers.each do |cipher_suite|
    #      # do something
    #    end
    # end
    #
    # However, in practice we find that OpenSSL::SSL::SSLContext::METHODS includes '_client' and '_server' variants
    # such as :TLSv1, :TLSv1_client, :TLSv1_server. In this case, we only need :TLSv1, so we need to remove ~2/3 of the list.
    #
    # Next, we'll find that many ciphers in OpenSSL::Cipher.ciphers are not applicable for various SSL versions.
    # The loop we previously looked at has (at the time of writing on Kali Rollin, msf 6.2.23) 3060 rounds.
    # This is a lot of iterations when we already know there are many combinations that will not be applicable for our
    # use. Luckily there is a 2nd way which is much more efficent.
    #
    # The OpenSSL library includes https://docs.ruby-lang.org/en/2.4.0/OpenSSL/SSL/SSLContext.html#method-i-ciphers
    # which we can use to generate a list of all ciphers, and SSL versions they work with. The structure is:
    #
    # [[name, version, bits, alg_bits], ...]
    #
    # which makes it very easy to just pull the 2nd element (version, or SSL version) from each list item, and unique it.
    # This gives us the list of all SSL versions which also have at least one working cipher on our system.
    # Using this method we produce no unusable SSL versions or matching cipher suites and the list is 60 items long, so 1/51 the size.
    # Later in get_metasploit_ssl_cipher_suites, we can grab all cipher suites to a SSL version easily by simply filtering
    # the 2nd element (version, or SSL version) from each list item.

    if datastore['SSLVersion'] == 'All'
      return Array.new(OpenSSL::SSL::SSLContext.new.ciphers.length) { |i| (OpenSSL::SSL::SSLContext.new.ciphers[i][1]).to_s }.uniq.reverse
    end

    [datastore['SSLVersion']]
  end

  def get_metasploit_ssl_cipher_suites(ssl_version)
    # See comments in get_metasploit_ssl_versions for details on the use of
    # OpenSSL::SSL::SSLContext.new.ciphers vs other methods to generate
    # valid ciphers for a given SSL version

    # First find all valid ciphers that the Metasploit host supports.
    # Also transform the SSL version to a standard format.
    ssl_version = ssl_version.to_s.gsub('_', '.')
    all_ciphers = OpenSSL::SSL::SSLContext.new.ciphers
    valid_ciphers = []

    # For each cipher that the Metasploit host supports, determine if that cipher
    # is supported for use with the SSL version passed into this function. If it is,
    # then add it to the valid_ciphers list.
    all_ciphers.each do |cipher|
      # cipher list has struct of [cipher, ssl_version, <int>, <int>]
      if cipher[1] == ssl_version
        valid_ciphers << cipher[0]
      end
    end

    # If the user wants to use all ciphers then return all valid ciphers.
    # Otherwise return only the one that matches the one the user specified
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
    if cert && cert.instance_of?(OpenSSL::X509::Certificate)
      print_status('Certificate Information:')
      print_status("\tSubject: #{cert.subject}")
      print_status("\tIssuer: #{cert.issuer}")
      print_status("\tSignature Alg: #{cert.signature_algorithm}")

      # If we use ECDSA rather than RSA, our metrics for key size are different
      print_status("\tPublic Key Size: #{public_key_size(cert)} bits")

      print_status("\tNot Valid Before: #{cert.not_before}")
      print_status("\tNot Valid After: #{cert.not_after}")

      # Checks for common properties of self signed certificates
      # regex tried against a bunch of alexa top 100 and others.
      # https://rubular.com/r/Yj6vyy1VqGWCL8
      caissuer = nil
      cert.extensions.each do |e|
        next unless /CA Issuers - URI:([^, \n]*)/i =~ e.to_s

        caissuer = ::Regexp.last_match(1)
        break
      end

      if caissuer.blank?
        print_good("\tCertificate contains no CA Issuers extension... possible self signed certificate")
      else
        print_status("\tCA Issuer: #{caissuer}")
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
        # https://github.com/rapid7/metasploit-framework/pull/17149#discussion_r1000675472
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
        info: "Module #{fullname} confirmed SSLv3 is available. Vulnerable to POODLE, CVE-2014-3566.",
        refs: ['CVE-2014-3566']
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
        info: "Module #{fullname} confirmed SSLv2 is available. Vulnerable to DROWN, CVE-2016-0800.",
        refs: ['CVE-2016-0800']
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
        info: "Module #{fullname} confirmed SSLv3/TLSv1 and a CBC cipher. Vulnerable to BEAST, CVE-2011-3389.",
        refs: ['CVE-2011-3389']
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
        info: "Module #{fullname} confirmed RC4 cipher.",
        refs: ['CVE-2013-2566']
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
        refs: ['CWE-327']
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
        refs: ['CVE-2015-4000']
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
        refs: ['CVE-2022-3358']
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
        info: "Module #{fullname} confirmed SSLv2, which was deprecated in 2011.",
        refs: ['https://datatracker.ietf.org/doc/html/rfc6176']
      )
    elsif ssl_version == 'SSLv3'
      print_good('Accepts Deprecated SSLv3')
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} confirmed SSLv3, which was deprecated in 2015.",
        refs: ['https://datatracker.ietf.org/doc/html/rfc7568']
      )
    elsif ssl_version == 'TLSv1.0'
      print_good('Accepts Deprecated TLSv1.0')
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} confirmed TLSv1.0, which was widely deprecated in 2020.",
        refs: ['https://datatracker.ietf.org/doc/rfc8996/']
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
          refs: ['CWE-326']
        )
      elsif key_size < 1024
        print_good('Public Key < 1024 bits')
        report_vuln(
          host: ip,
          port: rport,
          proto: 'tcp',
          name: name,
          info: "Module #{fullname} confirmed certificate key size < 1024 bits",
          refs: ['CWE-326']
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
        refs: ['CWE-328']
      )
    end

    # expired
    if cert.not_after < DateTime.now
      print_good("Certificate expired: #{cert.not_after}")
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} confirmed certificate expired",
        refs: ['CWE-298']
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
        refs: []
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
          vprint_error("\tDoes not accept #{version} using cipher #{cipher}, error message: #{error_message[1]}")
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
