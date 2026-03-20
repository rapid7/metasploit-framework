##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::LDAP
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'LDAP Signing Requirement Check',
        'Description' => %q{
          This module checks whether an LDAP server enforces LDAP signing.

          The module attempts an authenticated LDAP bind while forcing
          LDAP signing to be disabled. If the server requires signing,
          the bind will fail indicating that stronger authentication is required.

          This behavior is commonly observed on Microsoft Active Directory
          Domain Controllers where the policy "Domain controller: LDAP
          server signing requirements" is set to "Require signing".
        },
        'Author' => [
          'Bhaskar Bhar',
          'Spencer McIntyre'
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://github.com/rapid7/metasploit-framework/pull/19127'],
          ['URL', 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-signing-in-windows-server']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(389)
      ]
    )

    register_advanced_options(
      [
        OptEnum.new(
          'LDAP::Signing',
          [true, 'LDAP signing behavior', 'disabled', ['auto', 'disabled', 'required']]
        )
      ]
    )
  end

  def run_host(_ip)
    print_status("#{ip}:#{rport} - Checking LDAP signing enforcement")

    begin
      ldap_connect do |ldap|
        if ldap.bind
          print_good("#{ip}:#{rport} - LDAP signing NOT required")
        else
          print_good("#{ip}:#{rport} - LDAP signing is required or enforced")
        end
      end
    rescue StandardError => e
      if e.message.downcase.include?('stronger authentication')
        print_good("#{ip}:#{rport} - LDAP signing is required")
      else
        print_error("#{ip}:#{rport} - LDAP error: #{e.message}")
      end
    end
  end
end
