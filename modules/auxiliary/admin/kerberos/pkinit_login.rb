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
    tgt_result, key = send_request_tgt_pkinit(pfx: pfx,
                                              username: datastore['USERNAME'],
                                              realm: datastore['DOMAIN'])
    enc_part = decrypt_kdc_as_rep_enc_part(tgt_result.as_rep, key)
    ccache = Rex::Proto::Kerberos::CredentialCache::Krb5Ccache.from_responses(tgt_result.as_rep, enc_part)
    path = store_loot('mit.kerberos.ccache', 'application/octet-stream', rhost, ccache.encode, nil)
    print_status("#{peer} - TGT MIT Credential Cache saved to #{path}")
  end
end
