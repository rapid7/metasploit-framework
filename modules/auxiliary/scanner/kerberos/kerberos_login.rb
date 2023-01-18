##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Kerberos::AuthBrute

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kerberos Authentication Check Scanner',
        'Description' => %q{
          This module will test Kerberos logins on a range of machines and
          report successful logins.  If you have loaded a database plugin
          and connected to a database this module will record successful
          logins and hosts so you can track your access.

          Kerberos accounts which do not require pre-authentication will
          have the TGT logged for offline cracking, this technique is known as AS-REP Roasting.

          It is also able to identify whether user accounts are enabled or
          disabled/locked out.
        },
        'Author' => [
          'alanfoster',
        ],
        'References' => [
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
end
