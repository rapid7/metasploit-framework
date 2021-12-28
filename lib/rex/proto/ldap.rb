require 'net/ldap'
require 'rex/socket'

# Monkeypatch upstream library, for now
# TODO: write a real LDAP client in Rex and migrate all consumers
class Net::LDAP::Connection # :nodoc:

  def initialize(server)
    begin
      @conn = Rex::Socket::Tcp.create(
        'PeerHost' => server[:host],
        'PeerPort' => server[:port],
        'Proxies' => server[:proxies]
      )
    rescue SocketError
      raise Net::LDAP::LdapError, 'No such address or other socket error.'
    rescue Errno::ECONNREFUSED
      raise Net::LDAP::LdapError, "Server #{server[:host]} refused connection on port #{server[:port]}."
    end

    if server[:encryption]
      setup_encryption server[:encryption]
    end

    yield self if block_given?
  end
end

module Rex
  module Proto
    module LDAP
    end
  end
end
