# -*- coding: binary -*-

module Msf
  ###
  #
  # Pkcs12 cert that can either exist on disk, or as a database core ID
  #
  ###
  class OptPkcs12Cert < OptDatabaseRefOrPath
    def type
      'pkcs12_cert'
    end
  end
end
