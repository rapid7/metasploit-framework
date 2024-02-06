module Msf::Payload::Adapter::Fetch::Server::HTTP
  include Msf::Payload::Adapter::Fetch::Server::Https

  # This mixin supports only HTTP fetch handlers but still imports the HTTPS mixin.
  # We just remove the HTTPS Options so the user does not see them.
  #

  def initialize(*args)
    super
    deregister_options('FETCH_SSL',
                       'FETCH_CHECK_CERT',
                       'FetchSSLCert',
                       'FetchSSLCompression',
                       'FetchSSLCipher',
                       'FetchSSLCipher',
                       'FetchSSLVersion'
    )
  end

  def fetch_protocol
    'HTTP'
  end

end
