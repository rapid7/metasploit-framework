##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::LDAP
  include Msf::OptionalSession::LDAP

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'LDAP Update Object',
        'Description' => %q{
          This module allows creating, reading, updating and deleting attributes of LDAP objects.
          Users can specify the object and must specify a corresponding attribute.
        },
        'Author' => ['jheysel'],
        'License' => MSF_LICENSE,
        'Actions' => [
          ['CREATE', { 'Description' => 'Create an LDAP object' }],
          ['READ', { 'Description' => 'Read the the LDAP object' }],
          ['UPDATE', { 'Description' => 'Modify the LDAP object' }],
          ['DELETE', { 'Description' => 'Delete the LDAP object' }]
        ],
        'DefaultAction' => 'READ',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES]
        }
      )
    )

    register_options(
      [
        OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it']),
        OptEnum.new('OBJECT_LOOKUP', [true, 'How to look up the target LDAP object', 'dN', ['dN', 'sAMAccountName']]),
        OptString.new('OBJECT', [true, 'The target LDAP object']),
        OptString.new('ATTRIBUTE', [true, 'The LDAP attribute to update (e.g., userPrincipalName)']),
        OptString.new('VALUE', [false, 'The value for the specified LDAP object attribute'], conditions: ['ACTION', 'in', %w[Create Update] ])
      ]
    )
  end

  def find_target_object
    search_filter = "(&(#{ldap_escape_filter(datastore['OBJECT_LOOKUP'])}=#{ldap_escape_filter(datastore['OBJECT'])}))"
    result = []

    @ldap.search(base: @base_dn, filter: search_filter, attributes: ['distinguishedName', datastore['ATTRIBUTE']]) do |entry|
      result << entry
    end

    if result.empty?
      fail_with(Failure::NotFound, "Could not find any object matching the filter: #{search_filter}")
    elsif result.size > 1
      fail_with(Failure::UnexpectedReply, "Found multiple objects matching the filter: #{search_filter}. This should not happen.")
    end

    result.first
  end

  def action_read
    target_object = find_target_object
    target_dn = target_object['dN'].first
    attribute_value = target_object[datastore['ATTRIBUTE'].to_sym]&.first

    if attribute_value.blank?
      fail_with(Failure::NotFound, "Attribute #{datastore['ATTRIBUTE']} is not set for #{target_dn}")
    end

    print_good("Found #{target_dn} with #{datastore['ATTRIBUTE']} set to #{attribute_value}")
    attribute_value
  end

  def action_create
    target_object = find_target_object
    target_dn = target_object['dN'].first
    attribute = datastore['ATTRIBUTE'].to_sym
    value = datastore['VALUE']

    print_status("Attempting to add attribute #{datastore['ATTRIBUTE']} with value #{value} to #{target_dn}...")

    ops = [[:add, attribute, value]]
    @ldap.modify(dn: target_dn, operations: ops)
    validate_query_result!(@ldap.get_operation_result.table)

    print_good("Successfully added attribute #{datastore['ATTRIBUTE']} with value #{value} to #{target_dn}")
  end

  def action_update
    target_object = find_target_object
    target_dn = target_object['dN'].first
    attribute = datastore['ATTRIBUTE'].to_sym
    original_value = target_object[attribute]&.first
    print_status("Current value of #{datastore['OBJECT']}'s #{datastore['ATTRIBUTE']}: #{original_value}")

    ops = [[:replace, attribute, datastore['VALUE']]]

    print_status("Attempting to update #{datastore['ATTRIBUTE']} for #{target_dn} to #{datastore['VALUE']}...")
    @ldap.modify(dn: target_dn, operations: ops)
    validate_query_result!(@ldap.get_operation_result.table)

    print_good("Successfully updated #{target_dn}'s #{datastore['ATTRIBUTE']} to #{datastore['VALUE']}")
    original_value
  end

  def action_delete
    target_object = find_target_object
    target_dn = target_object['dN'].first
    attribute = datastore['ATTRIBUTE'].to_sym

    print_status("Attempting to delete attribute #{datastore['ATTRIBUTE']} from #{target_dn}...")

    ops = [[:delete, attribute]]
    @ldap.modify(dn: target_dn, operations: ops)
    validate_query_result!(@ldap.get_operation_result.table)

    print_good("Successfully deleted attribute #{datastore['ATTRIBUTE']} from #{target_dn}")
  end

  def run
    if (datastore['ACTION'].downcase == 'update' || datastore['ACTION'].downcase == 'create') && datastore['VALUE'].blank?
      fail_with(Failure::BadConfig, 'The VALUE option must be set for CREATE and UPDATE actions.')
    end

    ldap_connect do |ldap|
      validate_bind_success!(ldap)

      if (@base_dn = datastore['BASE_DN'])
        vprint_status("User-specified base DN: #{@base_dn}")
      else
        vprint_status('Discovering base DN automatically')

        unless (@base_dn = ldap.base_dn)
          fail_with(Failure::NotFound, "Couldn't discover base DN!")
        end
      end
      @ldap = ldap

      result = send("action_#{action.name.downcase}")
      print_good('The operation completed successfully!')
      result
    end
  rescue Errno::ECONNRESET
    fail_with(Failure::Disconnected, 'The connection was reset.')
  rescue Rex::ConnectionError => e
    fail_with(Failure::Unreachable, e.message)
  rescue Net::LDAP::Error => e
    fail_with(Failure::Unknown, "#{e.class}: #{e.message}")
  end
end
