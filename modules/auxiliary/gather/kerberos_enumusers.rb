##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/kerberos'
require 'ostruct'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Kerberos::AuthBrute

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kerberos Domain User Enumeration',
        'Description' => %q{
          This module will enumerate valid Domain Users via Kerberos from an unauthenticated perspective. It utilizes
          the different responses returned by the service for valid and invalid users. This module can also detect accounts
          that are vulnerable to ASREPRoast attacks.
        },
        'Author' => [
          'Matt Byrne <attackdebris[at]gmail.com>', # Original Metasploit module
          'alanfoster', # Enhancements
          'sjanusz-r7' # Enhancements
        ],
        'References' => [
          ['URL', 'https://nmap.org/nsedoc/scripts/krb5-enum-users.html'],
          ['ATT&CK', Mitre::Attack::Technique::T1087_002_DOMAIN_ACCOUNT],
          ['ATT&CK', Mitre::Attack::Technique::T1589_001_CREDENTIALS]
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => UNKNOWN_STABILITY,
          'SideEffects' => UNKNOWN_SIDE_EFFECTS
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
  
    # Converted result into trace-compatible structure
    response = OpenStruct.new(
      as_rep: result.proof,
      decrypted_part: nil
    )
  
    # Used trace system (important)
    if defined?(Msf::Trace::KerberosTicketTrace)
      Msf::Trace::KerberosTicketTrace.print_metadata(response, self)
    end
end
end