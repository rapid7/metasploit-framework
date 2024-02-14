module Msf::Payload::Adapter::Fetch::Server::Https
  include Msf::Payload::Adapter::Fetch::Server::HTTP

  # This mixin supports both HTTP and HTTPS fetch handlers.  If you only want
  # HTTP, use the HTTP mixin that imports this, but removes the HTTPS options
  def initialize(*args)
    super
    register_options(
      [
        Msf::OptBool.new('FETCH_CHECK_CERT', [true, 'Check SSL certificate', false])
      ]
    )
    register_advanced_options(
      [
        Msf::OptPath.new('FetchSSLCert', [ false, 'Path to a custom SSL certificate (default is randomly generated)', '']),
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

  def start_https_fetch_handler(srvname, srvexe)
    start_http_fetch_handler(srvname, srvexe, true, ssl_cert, ssl_compression, ssl_cipher, ssl_version)
  end
end
