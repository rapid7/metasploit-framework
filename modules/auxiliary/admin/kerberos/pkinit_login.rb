##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Auxiliary::Report
  include Msf::Exploit::Remote::Kerberos::Client

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kerberos Authentication Check Scanner',
        'Description' => %q{
          This module uses a pfx certificate file to acquire a TGT using
          the PKINIT protocol. A successful login will store the TGT for
          use with other modules.
        },
        'Author' => [
          'smashery',
        ],
        'References' => [
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options([
      OptPath.new('CERT_FILE', [ true, 'File containing a certificate (*.pfx) to authenticate with' ]),
      OptString.new('CERT_PASS', [ false, 'Password for the Certificate file' ]),
      OptString.new('USERNAME', [ false, 'Override username in certificate file' ]),
      OptString.new('DOMAIN', [ false, 'Override domain in certificate file' ]),
    ])
  end

  def run
    certificate = File.read(datastore['CERT_FILE'])
    cert_pass = datastore['CERT_PASS']
    cert_pass = '' if cert_pass.nil?
    pfx = OpenSSL::PKCS12.new(certificate, cert_pass)
    if datastore['USERNAME'].nil? && !datastore['DOMAIN'].nil?
      print_error('Username override provided but no domain override provided (must provide both or neither)')
      return
    elsif datastore['DOMAIN'].nil? && !datastore['USERNAME'].nil?
      print_error('Domain override provided but no username override provided (must provide both or neither)')
      return
    end
    username, realm = extract_user_and_realm(pfx.certificate, datastore['USERNAME'], datastore['DOMAIN'])
    print_status("Attempting PKINIT login for #{username}@#{realm}")
    begin
      server_name = "krbtgt/#{realm}"
      tgt_result, key = send_request_tgt_pkinit(pfx: pfx,
                                                username: username,
                                                realm: realm,
                                                server_name: server_name)
      print_good("Successfully authenticated with certificate")
      enc_part = decrypt_kdc_as_rep_enc_part(tgt_result.as_rep, key)

      info = []
      info << "realm: #{realm.upcase}"
      info << "serviceName: #{server_name.downcase}"
      info << "username: #{username.downcase}"

      ccache = Rex::Proto::Kerberos::CredentialCache::Krb5Ccache.from_responses(tgt_result.as_rep, enc_part)
      path = store_loot('mit.kerberos.ccache', 'application/octet-stream', rhost, ccache.encode, nil, info.join(', '))
      print_status("#{peer} - TGT MIT Credential Cache saved to #{path}")
    rescue Rex::Proto::Kerberos::Model::Error::KerberosError => e
      print_error("Failed: #{e.message}")
    end
  end
end
