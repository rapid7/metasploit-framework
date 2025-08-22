# -*- coding: binary -*-

module Msf
  ###
  #
  # Pkcs12 cert that can either exist on disk, or as a database core ID
  #
  ###
  class OptKerberosCredentialCache < OptDatabaseRefOrPath
    def type
      'kerberos_credential_cache'
    end
  end
end
