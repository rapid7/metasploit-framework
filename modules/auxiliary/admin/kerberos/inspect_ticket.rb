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
          This module outputs the contents of a ccache/kirbi file
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
          'AKA' => ['Klist']
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

  SECS_IN_DAY = 60 * 60 * 24

  def run
    enc_key = get_enc_key
    print_contents(datastore['TICKET_PATH'], key: enc_key)
  end

  private

  def get_enc_key
    key = validate_key
    key.nil? ? nil : [key].pack('H*')
  end

  def validate_key
    if datastore['NTHASH'].blank? && datastore['AES_KEY'].blank?
      return nil
    elsif datastore['NTHASH'].present? && datastore['AES_KEY'].present?
      fail_with(Msf::Exploit::Failure::BadConfig, 'NTHASH and AES_KEY may not both be set for inspecting a ticket')
    end

    if datastore['NTHASH'].present? && datastore['NTHASH'].size != 32
      fail_with(Msf::Exploit::Failure::BadConfig, "NTHASH length was #{datastore['NTHASH'].size} should be 32")
    else
      return datastore['NTHASH']
    end

    if datastore['AES_KEY'].present? && (datastore['AES_KEY'].size != 32 && datastore['AES_KEY'].size != 64)
      fail_with(Msf::Exploit::Failure::BadConfig, "AES key length was #{datastore['AES_KEY'].size} should be 32 or 64")
    else
      return datastore['AES_KEY']
    end
  end
end
