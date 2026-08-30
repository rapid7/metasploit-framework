# -*- coding: binary -*-

require 'bindata'

require 'rex/proto/kerberos/model/address_type'
require 'rex/proto/kerberos/credential_cache/primitive'

module Rex::Proto::Kerberos::CredentialCache
  class Krb5CcacheCredentialAddress < BinData::Record
    endian :big
    search_prefix :krb5_ccache

    uint16        :addrtype, initial_value: :get_address_type
    choice        :data, selection: :addrtype do
      address4    Rex::Proto::Kerberos::Model::AddressType::IPV4
      address6    Rex::Proto::Kerberos::Model::AddressType::IPV6
      data        :default
    end

    private

    def get_address_type
      if data.is_a?(IPAddr) && data.ipv4?
        Rex::Proto::Kerberos::Model::AddressType::IPV4
      elsif data.is_a?(IPAddr) && data.ipv6?
        Rex::Proto::Kerberos::Model::AddressType::IPV6
      else
        0
      end
    end
  end
end
