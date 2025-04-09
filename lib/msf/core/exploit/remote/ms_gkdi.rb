###
#
# This mixin provides methods for interacting with Microsoft Active Directory
# Group Key Distribution Service
#
# -*- coding: binary -*-

require 'ruby_smb'
require 'ruby_smb/error'
require 'ruby_smb/dcerpc/client'

module Msf

module Exploit::Remote::MsGkdi

  KDS_SERVICE_LABEL = "KDS service\0".encode('UTF-16LE').force_encoding('ASCII-8BIT')
  KDS_PUBLIC_KEY_LABEL = "KDS public key\0".encode('UTF-16LE').force_encoding('ASCII-8BIT')

  class GkdiGroupKeyIdentifier < BinData::Record
    endian :little

    uint32      :version
    uint8_array :magic, initial_length: 4, initial_value: [ 0x4b, 0x44, 0x53, 0x5b ]
    uint32      :dw_flags
    uint32      :l0_index
    uint32      :l1_index
    uint32      :l2_index
    uuid        :root_key_identifier

    uint32      :cb_context
    uint32      :cb_domain_name
    uint32      :cb_forest_name

    uint8_array :context, initial_length: :cb_context
    stringz16   :domain_name
    stringz16   :forest_name
  end

  def gkdi_get_kek(opts = {})
    gkdi = opts.fetch(:client) { connect_gkdi(opts) }

    key_identifier = opts.fetch(:key_identifier)
    gke = gkdi.gkdi_get_key(
      opts.fetch(:security_descriptor),
      key_identifier[:root_key_identifier].to_s,
      key_identifier[:l0_index],
      key_identifier[:l1_index],
      key_identifier[:l2_index]
    )

    gkdi_compute_kek(gke, key_identifier)
  end

  def connect_gkdi(opts = {})
    vprint_status('Connecting to Group Key Distribution (GKDI) Protocol')
    dcerpc_client = RubySMB::Dcerpc::Client.new(
      opts.fetch(:rhost) { rhost },
      RubySMB::Dcerpc::Gkdi,
      username: opts.fetch(:username) { datastore['USERNAME'] },
      password: opts.fetch(:password) { datastore['PASSWORD'] }
    )
    bind_gkdi(dcerpc_client)

    dcerpc_client
  end

  def bind_gkdi(dcerpc_client)
    tower = gkdi_get_endpoints.first
    dcerpc_client.connect(port: tower[:port])
    vprint_status("Binding to GKDI via #{tower[:endpoint]}...")
    dcerpc_client.bind(
      auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
      auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
    )
    vprint_status('Bound to GKDI')
  end

  def gkdi_get_endpoints(opts = {})
    vprint_status('Mapping GKDI endpoints...')
    dcerpc_client = RubySMB::Dcerpc::Client.new(
      opts.fetch(:rhost) { rhost },
      RubySMB::Dcerpc::Epm
    )
    dcerpc_client.connect
    dcerpc_client.bind
    # This works around an odd error where if the target has just booted, then no towers (endpoint connection infos)
    # will be returned if max_towers is set to 1. Here we map it our self and set max_towers to a higher number to work
    # around the behavior. Subsequent mapping attempts will work with max_towers set to 1, but 4 will always work.
    towers = dcerpc_client.ept_map_endpoint(RubySMB::Dcerpc::Gkdi, max_towers: 4)
    dcerpc_client.close
    towers
  end

  def gkdi_compute_kek(gke, key_identifier)
    l2_key = gkdi_compute_l2_key(gke, key_identifier)

    if (key_identifier.dw_flags & 1) == 0
      raise NotImplementedError.new("only public-private key pairs are supported")
    end

    secret = gkdi_compute_kek_pkey(gke, key_identifier, l2_key)
    Rex::Crypto::KeyDerivation::NIST_SP_800_108.counter_hmac(
      secret,
      32,
      gke.kdf_parameters.hash_algorithm_name.encode,
      label: KDS_SERVICE_LABEL,
      context: KDS_PUBLIC_KEY_LABEL
    ).first
  end

  def gkdi_compute_kek_pkey(gke, key_identifier, l2_key)
    private_key = Rex::Crypto::KeyDerivation::NIST_SP_800_108.counter_hmac(
      l2_key,
      (gke.private_key_length / 8.0).ceil,
      gke.kdf_parameters.hash_algorithm_name.encode,
      context: gke.secret_agreement_algorithm.to_binary_s,
      label: KDS_SERVICE_LABEL
    ).first

    unless (algorithm = gke.secret_agreement_algorithm.encode) == 'DH'
      raise NotImplementedError.new("unsupported secret agreement algorithm: #{algorithm}")
    end

    ffc_dh_key = RubySMB::Dcerpc::Gkdi::GkdiFfcDhKey.read(key_identifier.context.pack('C*'))
    base = Rex::Crypto.bytes_to_int(ffc_dh_key.public_key.pack('C*'))
    exp = Rex::Crypto.bytes_to_int(private_key)
    mod = Rex::Crypto.bytes_to_int(ffc_dh_key.field_order.pack('C*'))

    key_material = Rex::Crypto.int_to_bytes(base.pow(exp, mod))
    gkdi_kdf_counter(32, key_material, "SHA512\0".encode('UTF-16LE').force_encoding('ASCII-8BIT') + KDS_PUBLIC_KEY_LABEL + KDS_SERVICE_LABEL)
  end

  def gkdi_compute_l2_key(gke, key_identifier)
    unless (algorithm = gke.kdf_algorithm.encode) == 'SP800_108_CTR_HMAC'
      # see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/5d373568-dd68-499b-bd06-a3ce16ca7117
      raise NotImplementedError.new("unsupported key derivation function algorithm: #{algorithm}")
    end

    l1 = gke.l1_index.to_i
    l1_key = gke.l1_key.pack('C*')
    l2 = gke.l2_index.to_i
    l2_key = gke.l2_key.pack('C*')

    reseed_l2 = (l2 == 31 || l1 != key_identifier.l1_index)

    l1 -= 1 if l2 != 31 && l1 != key_identifier.l1_index

    while l1 != key_identifier.l1_index
      reseed_l2 = true
      l1 -= 1

      l1_key = Rex::Crypto::KeyDerivation::NIST_SP_800_108.counter_hmac(
        l1_key,
        64,
        gke.kdf_parameters.hash_algorithm_name.encode,
        context: gke.root_key_identifier.to_binary_s + [ gke.l0_index, l1, -1 ].pack('l<l<l<'),
        label: KDS_SERVICE_LABEL
      ).first
    end

    if reseed_l2
      l2 = 31

      l2_key = Rex::Crypto::KeyDerivation::NIST_SP_800_108.counter_hmac(
        l1_key,
        64,
        gke.kdf_parameters.hash_algorithm_name.encode,
        context: gke.root_key_identifier.to_binary_s + [ gke.l0_index, l1, l2 ].pack('l<l<l<'),
        label: KDS_SERVICE_LABEL
      ).first
    end

    while l2 != key_identifier.l2_index
      l2 -= 1

      l2_key = Rex::Crypto::KeyDerivation::NIST_SP_800_108.counter_hmac(
        l2_key,
        64,
        gke.kdf_parameters.hash_algorithm_name.encode,
        context: gke.root_key_identifier.to_binary_s + [ gke.l0_index, l1, l2 ].pack('l<l<l<'),
        label: KDS_SERVICE_LABEL
      ).first
    end

    l2_key
  end

  # this is mostly a variation on NIST SP 800-108
  def gkdi_kdf_counter(length, key_material, other_info)
    prf = -> (data) { OpenSSL::Digest.new('SHA256', data).digest }
    key_block = ''

    counter = 0
    while key_block.length < length
      counter += 1
      raise RangeError.new('counter overflow') if counter > 0xffffffff

      info = [ counter ].pack('L>') + key_material + other_info
      key_block << prf.call(info)
    end

    key_block[...length]
  end
end

end
