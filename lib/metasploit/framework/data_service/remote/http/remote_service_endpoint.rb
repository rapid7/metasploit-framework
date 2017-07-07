module Metasploit
module Framework
module DataService
class RemoteServiceEndpoint

  attr_reader :host
  attr_reader :port
  attr_reader :use_ssl
  attr_reader :ssl_version

  def initialize (host, port = 80, use_ssl = false, ssl_version = 'TLS1')
    raise 'host cannot be null' if host.nil?

    @host = host
    @port = port
    @use_ssl = use_ssl
    @ssl_version = use_ssl ? ssl_version : nil
  end

  def to_s
    "host: #{@host}, port: #{@port}"
  end
end
end
end
end
