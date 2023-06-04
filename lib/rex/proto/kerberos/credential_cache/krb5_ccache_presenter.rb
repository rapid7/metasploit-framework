# frozen_string_literal: true

require 'base64'
require 'rex/proto/kerberos/pac/krb5_pac'

module Rex::Proto::Kerberos::CredentialCache
  class Krb5CcachePresenter

    ADDRESS_TYPE_MAP = {
      Rex::Proto::Kerberos::Model::AddressType::IPV4 => 'IPV4',
      Rex::Proto::Kerberos::Model::AddressType::DIRECTIONAL => 'DIRECTIONAL',
      Rex::Proto::Kerberos::Model::AddressType::CHAOS_NET => 'CHAOS NET',
      Rex::Proto::Kerberos::Model::AddressType::XNS => 'XNS',
      Rex::Proto::Kerberos::Model::AddressType::ISO => 'ISO',
      Rex::Proto::Kerberos::Model::AddressType::DECNET_PHASE_IV => 'DECNET PHASE IV',
      Rex::Proto::Kerberos::Model::AddressType::APPLE_TALK_DDP => 'APPLE TALK DDP',
      Rex::Proto::Kerberos::Model::AddressType::NET_BIOS => 'NET BIOS',
      Rex::Proto::Kerberos::Model::AddressType::IPV6 => 'IPV6'
    }.freeze
    private_constant :ADDRESS_TYPE_MAP

    AD_TYPE_MAP = {
      Rex::Proto::Kerberos::Model::AuthorizationDataType::AD_IF_RELEVANT => 'IF_RELEVANT',
      Rex::Proto::Kerberos::Model::AuthorizationDataType::KDC_ISSUED => 'KDC_ISSUED',
      Rex::Proto::Kerberos::Model::AuthorizationDataType::AND_OR => 'AND_OR',
      Rex::Proto::Kerberos::Model::AuthorizationDataType::MANDATORY_FOR_KDC => 'MANDATORY_FOR_KDC',
      Rex::Proto::Kerberos::Model::AuthorizationDataType::INITIAL_VERIFIED_CAS => 'INITIAL_VERIFIED_CAS',
      Rex::Proto::Kerberos::Model::AuthorizationDataType::OSF_DCE => 'OSF_DCE',
      Rex::Proto::Kerberos::Model::AuthorizationDataType::SESAME => 'SESAME'
    }.freeze
    private_constant :AD_TYPE_MAP

    # Tracks the currently supported BinData types that can be formatted by the
    # Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter#print_bin_data_model method.
    BIN_DATA_BIT_LENGTHS = {
      ::BinData::Bit1 => 1
    }.freeze
    private_constant :BIN_DATA_BIT_LENGTHS

    # @param [Rex::Proto::Kerberos::CredentialCache::Krb5Ccache] ccache
    def initialize(ccache)
      @ccache = ccache
    end

    # @param [String,nil] key Decryption key for the encrypted part
    # @return [String] A human readable representation of a ccache object
    def present(key: nil)
      output = []
      output << "Primary Principal: #{ccache.default_principal}"
      output << "Ccache version: #{ccache.version}"
      output << ''
      output << "Creds: #{ccache.credentials.length}"
      output << ccache.credentials.map.with_index do |cred, index|
        "Credential[#{index}]:\n#{present_cred(cred, key: key).indent(2)}".indent(2)
      end.join("\n")
      output.join("\n")
    end

    # @return [Rex::Proto::Kerberos::CredentialCache::Krb5Ccache]
    attr_reader :ccache

    # @param [Rex::Proto::Kerberos::CredentialCache::Krb5CcacheCredential] cred
    # @param [String,nil] key Decryption key for the encrypted part
    # @return [String] A human readable representation of a ccache credential
    def present_cred(cred, key: nil)
      output = []
      output << "Server: #{cred.server}"
      output << "Client: #{cred.client}"
      output << "Ticket etype: #{cred.keyblock.enctype} (#{Rex::Proto::Kerberos::Crypto::Encryption.const_name(cred.keyblock.enctype)})"
      output << "Key: #{cred.keyblock.data.unpack1('H*')}"
      output << "Subkey: #{cred.is_skey == 1}"
      output << "Ticket Length: #{cred.ticket.length}"
      output << "Ticket Flags: 0x#{cred.ticket_flags.to_i.to_s(16).rjust(8, '0')} (#{Rex::Proto::Kerberos::Model::KdcOptionFlags.new(cred.ticket_flags.to_i).enabled_flag_names.join(', ')})"
      ticket = Rex::Proto::Kerberos::Model::Ticket.decode(cred.ticket.value)

      output << "Addresses: #{cred.address_count}"

      unless cred.address_count == 0
        output << cred.addresses.map do |address|
          "#{ADDRESS_TYPE_MAP.fetch(address.addrtype, address.addrtype)}: #{address.data}".indent(2)
        end.join("\n")
      end

      output << "Authdatas: #{cred.authdata_count}"
      unless cred.authdata_count == 0
        output << cred.authdatas.map do |authdata|
          "#{AD_TYPE_MAP.fetch(authdata.adtype, authdata.adtype)}: #{authdata.data}".indent(2)
        end.join("\n")
      end

      output << 'Times:'
      output << "Auth time: #{present_time(cred.authtime)}".indent(2)
      output << "Start time: #{present_time(cred.starttime)}".indent(2)
      output << "End time: #{present_time(cred.endtime)}".indent(2)
      output << "Renew Till: #{present_time(cred.renew_till)}".indent(2)

      output << 'Ticket:'
      output << "Ticket Version Number: #{ticket.tkt_vno}".indent(2)
      output << "Realm: #{ticket.realm}".indent(2)
      output << "Server Name: #{ticket.sname}".indent(2)
      output << 'Encrypted Ticket Part:'.indent(2)
      output << "Ticket etype: #{ticket.enc_part.etype} (#{Rex::Proto::Kerberos::Crypto::Encryption.const_name(ticket.enc_part.etype)})".indent(4)
      output << "Key Version Number: #{ticket.enc_part.kvno}".indent(4)

      if key.blank?
        output << 'Cipher:'.indent(4)
        output << Base64.strict_encode64(ticket.enc_part.cipher).indent(6)
      else
        output << "Decrypted (with key: #{key.bytes.map { |x| x.to_s(16).rjust(2, '0').to_s }.join}):".indent(4)
        output << present_encrypted_ticket_part(ticket, key).indent(6)
      end

      output.join("\n")
    end

    # This method takes a BinData object and parses it to create a formatted output
    # that help users visualise what each flag means as well as if it is set or not
    #
    # Note: For now we only support bit1 flags from BinData, this could be extended in the future
    #
    # Example output
    # .... .... .... .... .... .... .... .0.. Flag 29: The flag 29 is NOT SET
    # .... .... .... .... .... .... .... ..1. Flag 30: The flag 30 is SET
    # .... .... .... .... .... .... .... ...1 Flag 31: The flag 31 is SET
    #
    # @param model The BinData object
    # @param [Integer, Nil] bit_length The length of desired byte output - number of dots in example above
    # @return [String] Formatted output
    def print_bin_data_model(model, bit_length: nil)
      rows = []

      # i.e. [[:field_name_1,  1], [:field_name_2, 0]]
      fields_and_values = model.to_enum(:each_pair).to_a
      fields = fields_and_values.map { |field, _value| field }
      values = fields_and_values.map { |_field, value| value }

      # For now we only support bit1 flags from BinData, this could be extended in the future
      fields_and_values.each do |field, value|
        unless BIN_DATA_BIT_LENGTHS.keys.include?(value.class)
          raise TypeError, "Unsupported field type #{value.class} for field #{field.inspect} - expected one of #{BIN_DATA_BIT_LENGTHS.keys.join(',')}"
        end
      end

      # calculate the bit length; we can't rely on BinData's `num_bytes` in the senario of the model being 4 bits wide.
      calculated_bit_length = values.sum { |value| BIN_DATA_BIT_LENGTHS.fetch(value.class) }
      bit_length ||= calculated_bit_length

      if bit_length != calculated_bit_length
        raise ArgumentError, "Not implemented. Bit length(#{bit_length}) should equal the bit length of the model #{calculated_bit_length}"
      end

      padding = Array.new(bit_length - fields.length, :_reserved_)
      flag_keys = padding + fields
      binary_value = values.join

      bit_length.times do |i|
        next if flag_keys[i].start_with?('_reserved_')

        dot_formatting = Array.new(bit_length, '.')
        dot_formatting[(i - 1) - (bit_length - 1)] = binary_value[i]
        buckets = dot_formatting.in_groups_of(4) # Issue if we don't received a multiple of 4
        dot_formatting = buckets.map(&:join).join(' ')

        human_readable_flag_name = flag_keys[i].to_s.split('_').map(&:capitalize).join(' ')
        description = "#{human_readable_flag_name}: The #{flag_keys[i].to_s.upcase} bit is #{binary_value.chars[i] == '1' ? 'SET' : 'NOT SET'}"
        rows << "#{dot_formatting} #{description}"
      end

      rows.join("\n")
    end

    # @param [RubySMB::Dcerpc::Samr::PgroupMembershipArray] group_memberships
    # @return [Array] Formatted human readable representation of the group memberships
    def print_group_memberships(group_memberships)
      output = []
      if group_memberships.any?
        group_memberships.map do |group|
          group_attributes = Rex::Proto::Kerberos::Pac::GroupAttributes.read([group.attributes].pack('N'))
          output << "Relative ID: #{group.relative_id}\nAttributes: #{group.attributes}".indent(4)
          output << print_bin_data_model(group_attributes, bit_length: 32).to_s.indent(6)
        end
        output
      end
    end

    # @param [RubySMB::Dcerpc::Ndr::NdrUint32] user_flags
    # @return [Array] Formatted human readable representation of the user flags
    def print_user_flags(user_flags)
      output = []
      user_attributes = Rex::Proto::Kerberos::Pac::UserFlagAttributes.read([user_flags].pack('N'))
      output << "User Flags: #{user_flags}".indent(2)
      output << print_bin_data_model(user_attributes, bit_length: 32).to_s.indent(4)
    end

    # @param [RubySMB::Dcerpc::Ndr::NdrUint32] user_account_flags
    # @return [Array] Formatted human readable representation of the user account flags
    def print_user_account_flags(user_account_flags)
      output = []
      user_account_attributes = Rex::Proto::Kerberos::Pac::UserAccountAttributes.read([user_account_flags].pack('N'))
      output << "User Account Control: #{user_account_flags}".indent(2)
      output << print_bin_data_model(user_account_attributes, bit_length: 32).to_s.indent(4)
    end

    # @param [Rex::Proto::Kerberos::Pac::Krb5LogonInformation] logon_info
    # @return [String] A human readable representation of a Logon Information
    def present_logon_info(logon_info)
      validation_info = logon_info.data
      output = []
      output << 'Validation Info:'

      output << "Logon Time: #{present_ndr_file_time(validation_info.logon_time)}".indent(2)
      output << "Logoff Time: #{present_ndr_file_time(validation_info.logoff_time)}".indent(2)
      output << "Kick Off Time: #{present_ndr_file_time(validation_info.kick_off_time)}".indent(2)
      output << "Password Last Set: #{present_ndr_file_time(validation_info.password_last_set)}".indent(2)
      output << "Password Can Change: #{present_ndr_file_time(validation_info.password_can_change)}".indent(2)
      output << "Password Must Change: #{present_ndr_file_time(validation_info.password_must_change)}".indent(2)

      output << "Logon Count: #{validation_info.logon_count}".indent(2)
      output << "Bad Password Count: #{validation_info.bad_password_count}".indent(2)
      output << "User ID: #{validation_info.user_id}".indent(2)
      output << "Primary Group ID: #{validation_info.primary_group_id}".indent(2)
      output << print_user_flags(validation_info.user_flags)
      output << "User Session Key: #{present_user_session_key(validation_info.user_session_key)}".indent(2)
      output << print_user_account_flags(validation_info.user_account_control)
      output << "Sub Auth Status: #{validation_info.sub_auth_status}".indent(2)

      output << "Last Successful Interactive Logon: #{present_ndr_file_time(validation_info.last_successful_i_logon)}".indent(2)
      output << "Last Failed Interactive Logon: #{present_ndr_file_time(validation_info.last_failed_i_logon)}".indent(2)
      output << "Failed Interactive Logon Count: #{validation_info.failed_i_logon_count}".indent(2)

      output << "Extra SID Count: #{validation_info.sid_count}".indent(2)
      output << validation_info.extra_sids.map { |extra_sid| "SID: #{extra_sid.sid}, Attributes: #{extra_sid.attributes}".indent(4) } if validation_info.extra_sids.any?
      output << "Resource Group Count: #{validation_info.resource_group_count}".indent(2)

      output << "Group Count: #{validation_info.group_count}".indent(2)
      output << 'Group IDs:'.indent(2)
      output << print_group_memberships(validation_info.group_memberships)

      output << "Logon Domain ID: #{validation_info.logon_domain_id}".indent(2)

      output << "Effective Name: #{present_rpc_unicode_string(validation_info.effective_name)}".indent(2)
      output << "Full Name: #{present_rpc_unicode_string(validation_info.full_name)}".indent(2)
      output << "Logon Script: #{present_rpc_unicode_string(validation_info.logon_script)}".indent(2)
      output << "Profile Path: #{present_rpc_unicode_string(validation_info.profile_path)}".indent(2)
      output << "Home Directory: #{present_rpc_unicode_string(validation_info.home_directory)}".indent(2)
      output << "Home Directory Drive: #{present_rpc_unicode_string(validation_info.home_directory_drive)}".indent(2)
      output << "Logon Server: #{present_rpc_unicode_string(validation_info.logon_server)}".indent(2)
      output << "Logon Domain Name: #{present_rpc_unicode_string(validation_info.logon_domain_name)}".indent(2)

      output.join("\n")
    end

    # @param [Rex::Proto::Kerberos::Pac::Krb5ClientInfo] client_info
    # @return [String] A human readable representation of a Client Info
    def present_client_info(client_info)
      output = []
      output << 'Client Info:'
      output << "Name: '#{client_info.name.encode('utf-8')}'".indent(2)
      output << "Client ID: #{present_ndr_file_time(client_info.client_id)}".indent(2)
      output.join("\n")
    end

    # @param [String] header
    # @param [String] signature
    # @return [String] A human readable representation of a Checksum
    def present_checksum(header:, signature:)
      sig = signature.bytes.map { |x| x.to_s(16).rjust(2, '0').to_s }.join
      "#{header}\n" +
        "Signature: #{sig}".indent(2)
    end

    # @param [Rex::Proto::Kerberos::Pac::Krb5PacServerChecksum] server_checksum
    # @return [String] A human readable representation of a Server Checksum
    def present_server_checksum(server_checksum)
      signature = server_checksum.signature
      header = 'Pac Server Checksum:'

      present_checksum(header: header, signature: signature)
    end

    # @param [Rex::Proto::Kerberos::Pac::Krb5PacPrivServerChecksum] priv_server_checksum
    # @return [String] A human readable representation of a Privilege Server Checksum
    def present_priv_server_checksum(priv_server_checksum)
      signature = priv_server_checksum.signature
      header = 'Pac Privilege Server Checksum:'

      present_checksum(header: header, signature: signature)
    end

    # @param [Rex::Proto::Kerberos::Pac::Krb5TicketChecksum] ticket_checksum
    # @return [String] A human readable representation of a Ticket Checksum
    def present_ticket_checksum(ticket_checksum)
      signature = ticket_checksum.signature
      header = 'Ticket Checksum:'

      present_checksum(header: header, signature: signature)
    end

    # @param [Rex::Proto::Kerberos::Pac::Krb5FullPacChecksum] full_pac_checksum
    # @return [String] A human readable representation of a Full Pac Checksum
    def present_full_pac_checksum(full_pac_checksum)
      signature = full_pac_checksum.signature
      header = 'Full Pac Checksum:'

      present_checksum(header: header, signature: signature)
    end

    # @param [Rex::Proto::Kerberos::Pac::Krb5UpnDnsInfo] upn_and_dns_info
    # @return [String] A human readable representation of a UPN and DNS information element
    def present_upn_and_dns_information(upn_and_dns_info)
      output = []
      output << 'UPN and DNS Information:'
      output << "UPN: #{upn_and_dns_info.upn.encode('utf-8')}".indent(2)
      output << "DNS Domain Name: #{upn_and_dns_info.dns_domain_name.encode('utf-8')}".indent(2)

      output << "Flags: #{upn_and_dns_info.flags}".indent(2)
      upn_and_dns_info_attributes = Rex::Proto::Kerberos::Pac::UpnDnsInfoAttributes.read([upn_and_dns_info.flags].pack('N'))
      output << print_bin_data_model(upn_and_dns_info_attributes, bit_length: 32).to_s.indent(4)

      if upn_and_dns_info.has_s_flag?
        output << "SAM Name: #{upn_and_dns_info.sam_name.encode('utf-8')}".indent(2)
        output << "SID: #{upn_and_dns_info.sid}".indent(2)
      end
      output.join("\n")
    end

    # @param [Rex::Proto::Kerberos::Pac::Krb5PacInfoBuffer] info_buffer
    # @return [String] A human readable representation of a Pac Info Buffer
    def present_pac_info_buffer(info_buffer)
      ul_type = info_buffer.ul_type.to_i
      pac_element = info_buffer.buffer.pac_element
      case ul_type
      when Rex::Proto::Kerberos::Pac::Krb5PacElementType::LOGON_INFORMATION
        present_logon_info(pac_element)
      when Rex::Proto::Kerberos::Pac::Krb5PacElementType::CLIENT_INFORMATION
        present_client_info(pac_element)
      when Rex::Proto::Kerberos::Pac::Krb5PacElementType::SERVER_CHECKSUM
        present_server_checksum(pac_element)
      when Rex::Proto::Kerberos::Pac::Krb5PacElementType::PRIVILEGE_SERVER_CHECKSUM
        present_priv_server_checksum(pac_element)
      when Rex::Proto::Kerberos::Pac::Krb5PacElementType::USER_PRINCIPAL_NAME_AND_DNS_INFORMATION
        present_upn_and_dns_information(pac_element)
      when Rex::Proto::Kerberos::Pac::Krb5PacElementType::TICKET_CHECKSUM
        present_ticket_checksum(pac_element)
      when Rex::Proto::Kerberos::Pac::Krb5PacElementType::FULL_PAC_CHECKSUM
        present_full_pac_checksum(pac_element)
      else
        ul_type_name = Rex::Proto::Kerberos::Pac::Krb5PacElementType.const_name(ul_type)
        ul_type_name = ul_type_name.gsub('_', ' ').capitalize if ul_type_name
        "#{ul_type_name || "Unknown ul type #{ul_type}"}:\n" +
          info_buffer.to_s.indent(2)
      end
    end

    # @param [Rex::Proto::Kerberos::Model::Ticket] ticket
    # @param [String] key Decryption key for the encrypted part
    # @return [String] A human readable representation of an Encrypted Ticket Part
    def present_encrypted_ticket_part(ticket, key)
      enc_class = Rex::Proto::Kerberos::Crypto::Encryption.from_etype(ticket.enc_part.etype)

      decrypted_part = enc_class.decrypt(ticket.enc_part.cipher, key, 2)
      ticket_enc_part = Rex::Proto::Kerberos::Model::TicketEncPart.decode(decrypted_part)
      output = []
      output << 'Times:'
      output << "Auth time: #{present_time(ticket_enc_part.authtime)}".indent(2)
      output << "Start time: #{present_time(ticket_enc_part.starttime)}".indent(2)
      output << "End time: #{present_time(ticket_enc_part.endtime)}".indent(2)
      output << "Renew Till: #{present_time(ticket_enc_part.renew_till)}".indent(2)

      output << "Client Addresses: #{ticket_enc_part.caddr.to_a.length}"
      unless ticket_enc_part.caddr.to_a.empty?
        output << ticket_enc_part.caddr.to_a.map do |address|
          "#{ADDRESS_TYPE_MAP.fetch(address.type, address.type)}: #{address.address}".indent(2)
        end.join("\n")
      end

      output << "Transited: tr_type: #{ticket_enc_part.transited.tr_type}, Contents: #{ticket_enc_part.transited.contents.inspect}"

      output << "Client Name: '#{ticket_enc_part.cname}'"
      output << "Client Realm: '#{ticket_enc_part.crealm}'"
      output << "Ticket etype: #{ticket_enc_part.key.type} (#{Rex::Proto::Kerberos::Crypto::Encryption.const_name(ticket_enc_part.key.type)})"
      output << "Session Key: #{ticket_enc_part.key.value.unpack1('H*')}"
      output << "Flags: 0x#{ticket_enc_part.flags.to_i.to_s(16).rjust(8, '0')} (#{ticket_enc_part.flags.enabled_flag_names.join(', ')})"

      auth_data_data = ticket_enc_part.authorization_data.elements.first[:data]

      pac_string = OpenSSL::ASN1.decode(auth_data_data).value[0].value[1].value[0].value

      pac = Rex::Proto::Kerberos::Pac::Krb5Pac.read(pac_string)
      output << 'PAC:'
      output << pac.pac_info_buffers.map do |pac_info_buffer|
        present_pac_info_buffer(pac_info_buffer).indent(2)
      end
      output.join("\n")
    end

    # @param [RubySMB::Dcerpc::RpcUnicodeString] rpc_unicode_string
    # @return [String (frozen)]
    def present_rpc_unicode_string(rpc_unicode_string)
      if rpc_unicode_string.buffer.is_null_ptr?
        'nil'
      else
        "'#{rpc_unicode_string.buffer.encode('UTF-8')}'"
      end
    end

    # @param [Rex::Proto::Kerberos::Pac::UserSessionKey] user_session_key
    # @return [String] A human readable representation of a User Session Key
    def present_user_session_key(user_session_key)
      user_session_key.session_key.flat_map(&:data).map { |x| x.to_i.to_s(16).rjust(2, '0').to_s }.join
    end

    # @param [RubySMB::Dcerpc::Ndr::NdrFileTime] time
    # @return [String] A human readable representation of the time
    def present_ndr_file_time(time)
      if time.get == Rex::Proto::Kerberos::Pac::NEVER_EXPIRE
        'Never Expires (inf)'
      elsif time.get == 0
        'No Time Set (0)'
      else
        present_time(time.to_time)
      end
    end


    # @param [Time] time
    # @return [String] A human readable representation of the time in the users timezone
    def present_time(time)
      time.localtime.to_s
    end
  end
end
