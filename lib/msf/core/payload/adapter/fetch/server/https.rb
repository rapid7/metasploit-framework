# Provides HTTPS fetch listener options and certificate configuration validation.
module Msf::Payload::Adapter::Fetch::Server::Https
  include Msf::Payload::Adapter::Fetch::Server::HTTP

  # This mixin supports both HTTP and HTTPS fetch handlers.  If you only want
  # HTTP, use the HTTP mixin that imports this, but removes the HTTPS options
  def initialize(*args)
    super
    register_options(
      [
        Msf::OptBool.new('FETCH_CHECK_CERT', [true, 'Require the fetch client to validate the HTTPS certificate', false])
      ]
    )
    register_advanced_options(
      [
        Msf::OptPath.new('FetchSSLCert', [ false, 'Path to a custom SSL certificate and matching private key in PEM format; required for the built-in server when FETCH_CHECK_CERT is true', '']),
        Msf::OptBool.new('FetchSSLCompression', [ false, 'Enable SSL/TLS-level compression', false ]),
        Msf::OptString.new('FetchSSLCipher', [ false, 'String for SSL cipher spec - "DHE-RSA-AES256-SHA" or "ADH"']),
        Msf::OptEnum.new('FetchSSLVersion',
                         'Specify the version of SSL/TLS to be used (Auto, TLS and SSL23 are auto-negotiate)',
                         enums: Rex::Socket::SslTcp.supported_ssl_methods)
      ]
    )
  end

  def fetch_protocol
    'HTTPS'
  end

  def ssl_cert
    datastore['FetchSSLCert']
  end

  def ssl_compression
    datastore['FetchSSLCompression']
  end

  def ssl_cipher
    datastore['FetchSSLCipher']
  end

  def ssl_version
    datastore['FetchSSLVersion']
  end

  # Ensures the built-in server can present the configured certificate and key.
  # Target trust and hostname verification must still be satisfied by the operator.
  #
  # @return [void]
  def validate_fetch_certificate
    # External HTTPS servers manage their own certificates.
    return if datastore['FetchHandlerDisable'] || !datastore['FETCH_CHECK_CERT']

    unless ssl_cert.present? && ::File.file?(ssl_cert) && ::File.readable?(ssl_cert)
      fail_with(Msf::Module::Failure::BadConfig, 'Set FetchSSLCert to a readable PEM file containing a private key and a certificate trusted by the target when FETCH_CHECK_CERT is true')
    end

    key, cert, = Rex::Socket::X509Certificate.parse_pem_file(ssl_cert)
    unless key && cert && cert.check_private_key(key)
      fail_with(Msf::Module::Failure::BadConfig, 'FetchSSLCert must contain a certificate and its matching private key')
    end
  rescue SystemCallError, IOError, OpenSSL::OpenSSLError, ArgumentError => e
    elog('Failed to validate FetchSSLCert', error: e)
    fail_with(Msf::Module::Failure::BadConfig, 'Failed to read or parse FetchSSLCert; supply a PEM file containing a certificate and its matching private key')
  end

  def start_https_fetch_handler(srvname)
    start_http_fetch_handler(srvname, true, ssl_cert, ssl_compression, ssl_cipher, ssl_version)
  end
end
