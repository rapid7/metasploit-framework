##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::LDAP

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'LDAP Update Object',
        'Description' => %q{
          This module allows updating attributes of LDAP objects.
          Users can specify the object to update and the attribute to modify.
        },
        'Author' => ['jheysel'],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        OptString.new('OBJECT', [true, 'The target LDAP object']),
        OptString.new('ATTRIBUTE', [true, 'The LDAP attribute to update (e.g., userPrincipalName)']),
        OptString.new('NEW_VALUE', [true, 'The new value for the specified attribute'])
      ]
    )
  end

  # Converts a domain name to a base DN
  def domain_to_base_dn(domain)
    domain.split('.').map { |dc| "DC=#{dc}" }.join(',')
  end

  # Updates the specified attribute of a target LDAP object
  def update_object_attribute
    search_filter = datastore['OBJECT']
    attribute = datastore['ATTRIBUTE']
    new_value = datastore['NEW_VALUE']

    print_status("Connecting to LDAP on #{peer}...")


    ldap_connect do |ldap|
      print_status("Searching for target object: #{search_filter}...")

      treebase = domain_to_base_dn(datastore['LDAPDomain'])
      filter = Net::LDAP::Filter.eq('sAMAccountName', datastore['OBJECT'])

      result = []
      ldap.search(base: treebase, filter: filter, attributes: ['distinguishedName']) do |entry|
        result << entry
      end

      if result.empty?
        fail_with(Failure::NotFound, "Could not find any object matching the filter: #{search_filter}")
      end

      target_dn = result.first.dn
      print_good("Found target object DN: #{target_dn}")


      if new_value.present?
        ops = [
          [:replace, attribute.to_sym, new_value]
        ]
      else
        #TODO replacing with empty string / nil causes errors :delete is no what we want. Needed to reset empty UPN
      end

      print_status("Attempting to update #{attribute} for #{target_dn} to #{new_value}...")

      require 'pry-byebug'
      binding.pry

      if ldap.modify(dn: target_dn, operations: ops)
        print_good("Successfully updated #{target_dn}'s #{attribute} to #{new_value}")
      else
        fail_with(Failure::UnexpectedReply, "Failed to update #{attribute}: #{ldap.get_operation_result.message}")
      end
    end
  end


  def run
    update_object_attribute
  end
end
