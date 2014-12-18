# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module CredentialCache
        VERSION = 0x0504
      end
    end
  end
end

require 'rex/proto/kerberos/credential_cache/element'
require 'rex/proto/kerberos/credential_cache/key_block'
require 'rex/proto/kerberos/credential_cache/principal'
require 'rex/proto/kerberos/credential_cache/time'
require 'rex/proto/kerberos/credential_cache/credential'
require 'rex/proto/kerberos/credential_cache/cache'