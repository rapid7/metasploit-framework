# -*- coding: binary -*-

require 'bindata'
require 'ipaddr'

require 'rex/proto/kerberos/credential_cache/primitive/krb5_ccache_data'

module Rex::Proto::Kerberos::CredentialCache::Primitive
  class Krb5CcacheAddress < Krb5CcacheData
    FAMILY = ::Socket::AF_INET

    def get
      v = IPAddr.new_ntoh(super)
      if self.class::FAMILY != ::Socket::AF_UNSPEC && self.class::FAMILY != v.family
        raise IPAddr::AddressFamilyError, 'address family mismatch'
      end

      v
    end

    def set(v)
      if v.is_a?(IPAddr)
        if self.class::FAMILY != ::Socket::AF_UNSPEC && self.class::FAMILY != v.family
          raise IPAddr::AddressFamilyError, 'address family mismatch'
        end

        v = v.hton
      end

      super
    end
  end

  class Krb5CcacheAddress4 < Krb5CcacheAddress
    FAMILY = ::Socket::AF_INET
    default_parameter initial_value: "\x00".b * 4
  end

  class Krb5CcacheAddress6 < Krb5CcacheAddress
    FAMILY = ::Socket::AF_INET6
    default_parameter initial_value: "\x00".b * 16
  end
end
