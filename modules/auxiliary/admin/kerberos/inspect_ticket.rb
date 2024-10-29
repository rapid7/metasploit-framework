##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Kerberos::Client
  include Msf::Exploit::Remote::Kerberos::Ticket

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kerberos Ticket Inspecting',
        'Description' => %q{
          This module outputs the contents of a ccache/kirbi file and optionally (when provided with the appropriate key)
          decrypts and displays the encrypted content too.
          Can be used for inspecting tickets that aren't working as intended in an effort to debug them.
        },
        'Author' => [
          'Dean Welch' # Metasploit Module
        ],
        'References' => [],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [],
          'SideEffects' => [],
          'Reliability' => [],
          'AKA' => ['klist']
        }
      )
    )

    register_options(
      [
        OptString.new('NTHASH', [ false, 'The krbtgt/service nthash' ]),
        OptString.new('AES_KEY', [ false, 'The krbtgt/service AES key' ]),
        OptString.new('TICKET_PATH', [true, 'Path to the ticket (ccache/kirbi format) you wish to inspect'])
      ]
    )
    deregister_options('RHOSTS', 'RPORT', 'Timeout')
  end

  SECS_IN_DAY = 86400 # 60 * 60 * 24

  def run
    enc_key = get_enc_key
    print_contents(datastore['TICKET_PATH'], key: enc_key)
  rescue Rex::Proto::Kerberos::Model::Error::KerberosError => e
    fail_with(Msf::Exploit::Failure::Unknown, "Could not print ticket contents (#{e})")
  end

  private

  def get_enc_key
    key = validate_key
    key.nil? ? nil : [key].pack('H*')
  end

  def validate_key
    if datastore['NTHASH'].present? && datastore['AES_KEY'].present?
      fail_with(Msf::Exploit::Failure::BadConfig, 'NTHASH and AES_KEY may not both be set for inspecting a ticket')
    end

    if datastore['NTHASH'].present?
      key_type = :nthash
    elsif datastore['AES_KEY'].present?
      key_type = :aes_key
    else
      key_type = nil
    end

    case key_type
    when :nthash
      key = validate_nthash(datastore['NTHASH'])
    when :aes_key
      key = validate_aes_key(datastore['AES_KEY'])
    else
      print_status('No decryption key provided proceeding without decryption.')
      key = nil
    end

    key
  end

  def validate_nthash(nthash)
    if nthash.size != 32
      fail_with(Msf::Exploit::Failure::BadConfig, "NTHASH length was #{nthash.size}. It should be 32")
    else
      nthash
    end
  end

  def validate_aes_key(aes_key)
    if aes_key.size != 32 && aes_key.size != 64
      fail_with(Msf::Exploit::Failure::BadConfig, "AES key length was #{aes_key.size}. It should be 32 or 64")
    else
      aes_key
    end
  end
end
