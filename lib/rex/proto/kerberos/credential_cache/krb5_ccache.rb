# -*- coding: binary -*-

require 'bindata'

require 'rex/proto/kerberos/credential_cache/primitive'
require 'rex/proto/kerberos/credential_cache/krb5_ccache_credential'
require 'rex/proto/kerberos/credential_cache/krb5_ccache_principal'

module Rex::Proto::Kerberos::CredentialCache
  # see: https://web.mit.edu/kerberos/krb5-devel/doc/formats/ccache_file_format.html
  class Krb5Ccache < BinData::Record
    endian :big
    search_prefix :krb5_ccache
    unregister_self

    uint8      :magic,   asserted_value: 5
    uint8      :version, asserted_value: 4

    struct :header, onlyif: -> { version == 4 } do
      endian :big

      uint16     :header_length, initial_length: -> { header_fields.num_bytes }
      buffer     :header_fields, length: :header_length do
        array    read_until: :eof do
          uint16 :field_type
          uint16 :field_length, initial_value: -> { field_value.num_bytes }
          choice :field_value, selection: :field_type do
            struct 1 do # time offset of the KDC relative to the client
              int32 :seconds
              int32 :microseconds
            end
            string :default, read_length: :field_length
          end
        end
      end
    end

    principal  :default_principal
    array      :credentials, type: :credential, read_until: :eof

    # the other kerberos models use #encode so alias that for simplicity
    alias_method :encode, :to_binary_s
  end
end
