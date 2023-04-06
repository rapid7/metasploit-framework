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

    # @param [Rex::Proto::Kerberos::Model::KdcResponse] res The KDC response
    # @param [Rex::Proto::Kerberos::Model::EncKdcResponse] enc_res The encrypted KDC response
    # @return [Rex::Proto::Kerberos::CredentialCache::Krb5Ccache]
    def self.from_responses(res, enc_res)
      self.new(
        default_principal: {
          name_type: res.cname.name_type, # NT_PRINCIPAL
          realm: res.crealm,
          components: res.cname.name_string
        },
        credentials: [
          {
            client: {
              name_type: res.cname.name_type,
              realm: res.crealm,
              components: res.cname.name_string
            },
            server: {
              name_type: enc_res.sname.name_type,
              realm: enc_res.srealm,
              components: enc_res.sname.name_string
            },
            keyblock: {
              enctype: enc_res.key.type,
              data: enc_res.key.value
            },
            authtime: enc_res.auth_time,
            starttime: enc_res.start_time,
            endtime: enc_res.end_time,
            renew_till: enc_res.renew_till,
            ticket_flags: enc_res.flags.to_i,
            ticket: res.ticket.encode
          }
        ]
      )
    end
  end
end
