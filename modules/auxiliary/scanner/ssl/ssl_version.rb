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
        [ 'URL', 'http://web.archive.org/web/20240319071045/https://www.openssl.org/~bodo/ssl-poodle.pdf' ],
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
        [ 'URL', 'http://web.archive.org/web/20240607160328/https://www.isg.rhul.ac.uk/tls/' ],
        [ 'CVE', '2013-2566' ],
        # LOGJAM
        [ 'CVE', '2015-4000' ],
        # NULL ciphers
        [ 'CVE', '2022-3358' ],
        [ 'CWE', '319'],
        # certificate expired
        [ 'CWE', '298' ],
        # certificate broken or risky crypto algorithms
        [ 'CWE', '327' ],
        # certificate inadequate encryption strength
        [ 'CWE', '326' ]
      ],
      'DisclosureDate' => 'Oct 14 2014'
    )

    register_options(
      [
        OptString.new('SSLServerNameIndication', [ false, 'SSL/TLS Server Name Indication (SNI)', nil]),
        OptEnum.new('SSLVersion', [ true, 'SSL version to test', 'All', ['All'] + Array.new(OpenSSL::SSL::SSLContext.new.ciphers.length) { |i| (OpenSSL::SSL::SSLContext.new.ciphers[i][1]).to_s }.uniq.reverse]),
        OptEnum.new('SSLCipher', [ true, 'SSL cipher to test', 'All', ['All'] + Array.new(OpenSSL::SSL::SSLContext.new.ciphers.length) { |i| (OpenSSL::SSL::SSLContext.new.ciphers[i][0]).to_s }.uniq]),
      ]
    )
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

  # Process certificate with enhanced analysis
  def process_certificate(ip, cert)
    print_cert(cert, ip)

    # Store certificate in loot with rex-sslscan metadata
    loot_cert = store_loot(
      'ssl.certificate.rex_sslscan',
      'application/x-pem-file',
      ip,
      cert.to_pem,
      "ssl_cert_#{ip}_#{rport}.pem",
      "SSL Certificate from #{ip}:#{rport}"
    )
    print_good("Certificate saved to loot: #{loot_cert}")
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

  # Enhanced vulnerability checking leveraging rex-sslscan data
  def check_vulnerabilities_enhanced(ip, ssl_version, cipher_name, cert, is_weak_cipher)
    check_vulnerabilities(ip, ssl_version, cipher_name, cert)

    if is_weak_cipher
      print_good("#{ip}:#{rport} - Weak cipher detected: #{cipher_name}")
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: "Module #{fullname} detected weak cipher: #{cipher_name}",
        refs: ['CWE-327']
      )
    end
  end

  # Store comprehensive rex-sslscan results
  def store_rex_sslscan_results(ip, scan_result)
    # Create detailed report
    report_data = {
      host: ip,
      port: rport,
      scan_timestamp: Time.now.utc,
      ssl_versions: {
        sslv2_supported: scan_result.supports_sslv2?,
        sslv3_supported: scan_result.supports_sslv3?,
        tlsv1_supported: scan_result.supports_tlsv1?,
        tlsv1_1_supported: scan_result.supports_tlsv1_1?,
        tlsv1_2_supported: scan_result.supports_tlsv1_2?
      },
      cipher_summary: {
        total_accepted: scan_result.accepted.length,
        total_rejected: scan_result.rejected.length,
        weak_ciphers: scan_result.weak_ciphers.length,
        strong_ciphers: scan_result.strong_ciphers.length
      },
      detailed_ciphers: scan_result.ciphers.to_a
    }

    # Store as JSON loot
    loot_file = store_loot(
      'ssl.scan.rex_sslscan',
      'application/json',
      ip,
      report_data.to_json,
      "ssl_scan_#{ip}_#{rport}.json",
      "Rex::SSLScan results for #{ip}:#{rport}"
    )
    print_good("Detailed scan results saved to loot: #{loot_file}")
  end

  # Process rex-sslscan results
  def process_rex_sslscan_results(ip, scan_result)
    # Report certificate if available
    if scan_result.cert
      process_certificate(ip, scan_result.cert)
    end

    # Process accepted ciphers by version
    %i[SSLv2 SSLv3 TLSv1 TLSv1_1 TLSv1_2].each do |version|
      accepted_ciphers = scan_result.accepted(version)
      next if accepted_ciphers.empty?

      print_good("#{ip}:#{rport} - #{version} supported with #{accepted_ciphers.length} cipher(s)")

      key_size = public_key_size(scan_result.cert)
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

      accepted_ciphers.each do |cipher_info|
        cipher_name = cipher_info[:cipher]
        key_length = cipher_info[:key_length]
        is_weak = cipher_info[:weak]

        # Report the cipher
        print_status("  #{version}: #{cipher_name} (#{key_length} bits)#{is_weak ? ' - WEAK' : ''}")

        # Check for vulnerabilities using existing logic
        check_vulnerabilities_enhanced(ip, version.to_s, cipher_name, scan_result.cert, is_weak)
      end
    end

    # Report weak ciphers summary
    weak_ciphers = scan_result.weak_ciphers
    if weak_ciphers.any?
      print_bad("#{ip}:#{rport} - #{weak_ciphers.length} weak cipher(s) detected")
    end

    # Store comprehensive scan results in loot
    store_rex_sslscan_results(ip, scan_result)
  end

  # Fingerprint a single host
  def run_host(ip)
    print_status("Starting enhanced SSL/TLS scan of #{ip}:#{rport}")

    begin
      ctx = { 'Msf' => framework, 'MsfExploit' => self }
      tls_server_name_indication = nil
      tls_server_name_indication = datastore['SSLServerNameIndication'] if datastore['SSLServerNameIndication'].present?
      tls_server_name_indication = datastore['RHOSTNAME'] if tls_server_name_indication.nil? && datastore['RHOSTNAME'].present?
      # Initialize rex-sslscan scanner
      scanner = Rex::SSLScan::Scanner.new(ip, rport, ctx, tls_server_name_indication: tls_server_name_indication)

      # Perform the scan
      scan_result = scanner.scan

      # Check if SSL/TLS is supported
      unless scan_result.supports_ssl?
        print_error("#{ip}:#{rport} - Server does not appear to support SSL/TLS")
        return
      end

      # Process and report results
      process_rex_sslscan_results(ip, scan_result)
    rescue StandardError => e
      print_error("#{ip}:#{rport} - Scan error: #{e.message}")
      vprint_error("#{ip}:#{rport} - Backtrace: #{e.backtrace}")
    end
  end
end
