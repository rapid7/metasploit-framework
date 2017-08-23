# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Extended API ADSI management user interface.
#
###
class Console::CommandDispatcher::Extapi::Adsi

  Klass = Console::CommandDispatcher::Extapi::Adsi

  include Console::CommandDispatcher

  # Zero indicates "no limit"
  DEFAULT_MAX_RESULTS = 0
  DEFAULT_PAGE_SIZE   = 0

  #
  # List of supported commands.
  #
  def commands
    all = {
      'adsi_user_enum'              => 'Enumerate all users on the specified domain.',
      'adsi_group_enum'             => 'Enumerate all groups on the specified domain.',
      'adsi_nested_group_user_enum' => 'Recursively enumerate users who are effectively members of the group specified.',
      'adsi_computer_enum'          => 'Enumerate all computers on the specified domain.',
      'adsi_dc_enum'                => 'Enumerate all domain controllers on the specified domain.',
      'adsi_domain_query'           => 'Enumerate all objects on the specified domain that match a filter.'
    }
    reqs = {
      "adsi_user_enum"              => [ "extapi_adsi_domain_query" ],
      "adsi_group_enum"             => [ "extapi_adsi_domain_query" ],
      "adsi_nested_group_user_enum" => [ "extapi_adsi_domain_query" ],
      "adsi_computer_enum"          => [ "extapi_adsi_domain_query" ],
      "adsi_dc_enum"                => [ "extapi_adsi_domain_query" ],
      "adsi_domain_query"           => [ "extapi_adsi_domain_query" ],
    }
    filter_commands(all, reqs)
  end

  #
  # Name for this dispatcher
  #
  def name
    'Extapi: ADSI Management'
  end

  #
  # Options for the adsi_nested_group_user_enum command.
  #
  @@adsi_nested_group_user_enum_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner'],
    '-o' => [true,  'Path to output file.'],
    '-m' => [true,  'Maximum results to return.'],
    '-p' => [true,  'Result set page size.']
  )

  def adsi_nested_group_user_enum_usage
    print_line('USAGE:')
    print_line(' adsi_nested_group_user_enum <domain> <Group DN> [-h] [-m maxresults] [-p pagesize] [-o file]')
    print_line
    print_line('DESCRIPTION:')
    print_line(' Enumerate the users who are members of the named group, taking nested groups into account.')
    print_line(' For example, specifying the "Domain Admins" group DN will list all users who are effectively')
    print_line(' members of the Domain Admins group, even if they are in practice members of intermediary groups.')
    print_line
    print_line('EXAMPLE:')
    print_line(' The example below will list all members of the "Domain Admins" group on the STUFUS domain:')
    print_line('  adsi_nested_group_user_enum STUFUS "CN=Domain Admins,CN=Users,DC=mwrinfosecurity,DC=com"')
    print_line(@@adsi_nested_group_user_enum_opts.usage)
  end

  #
  # Enumerate domain groups.
  #
  def cmd_adsi_nested_group_user_enum(*args)
    args.unshift('-h') if args.length == 0
    if args.include?('-h') || args.length < 2
      adsi_nested_group_user_enum_usage
      return true
    end

    domain = args.shift
    groupdn = args.shift
    # This OID (canonical name = LDAP_MATCHING_RULE_IN_CHAIN) will recursively search each 'memberof' parent
    # https://support.microsoft.com/en-us/kb/275523 for more information -stufus
    filter = "(&(objectClass=user)(memberof:1.2.840.113556.1.4.1941:=#{groupdn}))"
    fields = ['samaccountname', 'name', 'distinguishedname', 'description', 'comment']
    args = [domain, filter] + fields + args
    return cmd_adsi_domain_query(*args)
  end

  #
  # Options for the adsi_user_enum command.
  #
  @@adsi_user_enum_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner.'],
    '-o' => [true,  'Path to output file.'],
    '-m' => [true,  'Maximum results to return.'],
    '-p' => [true,  'Result set page size.']
  )

  def adsi_user_enum_usage
    print_line('USAGE:')
    print_line(' adsi_user_enum <domain> [-h] [-m maxresults] [-p pagesize] [-o file]')
    print_line
    print_line('DESCRIPTION:')
    print_line(' Enumerate all users on the target domain.')
    print_line(' Enumeration returns information such as the user name, SAM account name, status, comments etc')
    print_line(@@adsi_user_enum_opts.usage)
  end

  #
  # Enumerate domain users.
  #
  def cmd_adsi_user_enum(*args)
    args.unshift('-h') if args.length == 0
    if args.include?('-h')
      adsi_user_enum_usage
      return true
    end

    domain = args.shift
    filter = '(objectClass=user)'
    fields = ['samaccountname', 'name', 'distinguishedname', 'description', 'comment']
    args = [domain, filter] + fields + args
    return cmd_adsi_domain_query(*args)
  end

  #
  # Options for the adsi_group_enum command.
  #
  @@adsi_group_enum_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner.'],
    '-o' => [true,  'Path to output file.'],
    '-m' => [true,  'Maximum results to return.'],
    '-p' => [true,  'Result set page size.']
  )

  def adsi_group_enum_usage
    print_line('USAGE:')
    print_line(' adsi_nested_group_user_enum <domain> [-h] [-m maxresults] [-p pagesize] [-o file]')
    print_line
    print_line('DESCRIPTION:')
    print_line(' Enumerate all groups on the target domain.')
    print_line
    print_line('EXAMPLE:')
    print_line(' The example below will list all groups on the STUFUS domain.')
    print_line('  adsi_group_enum STUFUS')
    print_line(@@adsi_group_enum_opts.usage)
  end

  #
  # Enumerate domain groups.
  #
  def cmd_adsi_group_enum(*args)
    args.unshift('-h') if args.length == 0
    if args.include?('-h')
      adsi_group_enum_usage
      return true
    end

    domain = args.shift
    filter = '(objectClass=group)'
    fields = ['name', 'distinguishedname', 'description',]
    args = [domain, filter] + fields + args
    return cmd_adsi_domain_query(*args)
  end

  #
  # Options for the adsi_computer_enum command.
  #
  @@adsi_computer_enum_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner.'],
    '-o' => [true,  'Path to output file.'],
    '-m' => [true,  'Maximum results to return.'],
    '-p' => [true,  'Result set page size.']
  )

  def adsi_computer_enum_usage
    print_line('USAGE:')
    print_line(' adsi_computer_enum <domain> [-h] [-m maxresults] [-p pagesize] [-o file]')
    print_line
    print_line('DESCRIPTION:')
    print_line(' Enumerate all computers on the target domain.')
    print_line(@@adsi_computer_enum_opts.usage)
  end

  #
  # Enumerate domain computers.
  #
  def cmd_adsi_computer_enum(*args)
    args.unshift('-h') if args.length == 0
    if args.include?('-h')
      adsi_computer_enum_usage
      return true
    end

    domain = args.shift
    filter = '(objectClass=computer)'
    fields = ['name', 'dnshostname', 'distinguishedname', 'operatingsystem',
              'operatingsystemversion', 'operatingsystemservicepack', 'description',
              'comment' ]
    args = [domain, filter] + fields + args
    return cmd_adsi_domain_query(*args)
  end

  #
  # Options for the adsi_dc_enum command.
  #
  @@adsi_dc_enum_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner.'],
    '-o' => [true,  'Path to output file.'],
    '-m' => [true,  'Maximum results to return.'],
    '-p' => [true,  'Result set page size.']
  )

  def adsi_dc_enum_usage
    print_line('USAGE:')
    print_line(' adsi_dc_enum <domain> [-h] [-m maxresults] [-p pagesize] [-o file]')
    print_line
    print_line('DESCRIPTION:')
    print_line(' Enumerate the domain controllers on the target domain.')
    print_line(@@adsi_dc_enum_opts.usage)
  end

  #
  # Enumerate domain dcs.
  #
  def cmd_adsi_dc_enum(*args)
    args.unshift('-h') if args.length == 0
    if args.include?('-h')
      adsi_dc_enum_usage
      return true
    end

    domain = args.shift
    # This LDAP filter will pull out domain controllers
    filter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
    fields = ['name', 'dnshostname', 'distinguishedname', 'operatingsystem',
              'operatingsystemversion', 'operatingsystemservicepack', 'description', 'comment' ]
    args = [domain, filter] + fields + args
    return cmd_adsi_domain_query(*args)
  end

  #
  # Options for the adsi_domain_query command.
  #
  @@adsi_domain_query_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner.'],
    '-o' => [true,  'Path to output file.'],
    '-m' => [true,  'Maximum results to return.'],
    '-p' => [true,  'Result set page size.']
  )

  def adsi_domain_query_usage
    print_line('USAGE:')
    print_line(' adsi_domain_query <domain> <filter> <field 1> [field 2 [field ..]] [-h] [-m maxresults] [-p pagesize] [-o file]')
    print_line
    print_line('DESCRIPTION:')
    print_line(' Enumerates the objects on the target domain, returning the set of fields that are specified.')
    print_line(@@adsi_domain_query_opts.usage)
  end

  #
  # Enumerate domain objects.
  #
  def cmd_adsi_domain_query(*args)
    page_size = DEFAULT_PAGE_SIZE
    max_results = DEFAULT_MAX_RESULTS

    args.unshift('-h') if args.length < 3
    output_file = nil

    @@adsi_domain_query_opts.parse(args) { |opt, idx, val|
      case opt
      when '-p'
        page_size = val.to_i
      when '-o'
        output_file = val
      when '-m'
        max_results = val.to_i
      when '-h'
        adsi_domain_query_usage
        return true
      end
    }

    # Assume that the flags are passed in at the end. Safe?
    switch_index = args.index { |a| a.start_with?('-') }
    if switch_index
      args = args.first(switch_index)
    end

    domain = args.shift
    filter = args.shift

    objects = client.extapi.adsi.domain_query(domain, filter, max_results, page_size, args)

    table = Rex::Text::Table.new(
      'Header'    => "#{domain} Objects",
      'Indent'    => 0,
      'SortIndex' => 0,
      'Columns'   => objects[:fields]
    )

    objects[:results].each do |c|
      table << to_table_row(c)
    end

    print_line
    print_line(table.to_s)
    print_line("Total objects: #{objects[:results].length}")
    print_line

    if output_file
      ::File.open(output_file, 'w') do |f|
        f.write("#{table.to_s}\n")
        f.write("\nTotal objects: #{objects[:results].length}\n")
      end
    end

    return true
  end

protected

  #
  # Convert an ADSI result row to a table row so that it can
  #   be rendered to screen appropriately.
  #
  # @param result [Array[Hash]] Array of type/value pairs.
  #
  # @return [Array[String]] Renderable view of the value.
  #
  def to_table_row(result)
    values = []

    result.each do |v|
      case v[:type]
      when :string, :number, :bool
        values << v[:value].to_s
      when :raw
        # for UI level stuff, rendering raw as hex is really the only option
        values << Rex::Text.to_hex(v[:value], '')
      when :array
        val = "#{to_table_row(v[:value]).join(', ')}"

        # we'll truncate the output of the array because it could be excessive if we
        # don't. Users who want the detail of this stuff should probably script it.
        if val.length > 50
          val = "<#{val[0,50]}..."
        end

        values << val
      when :dn
        values << "#{value[:label]}: #{value[:string] || Rex::Text.to_hex(value[:raw], '')}"
      when :path
        values << "Vol: #{v[:volume]}, Path: #{v[:path]}, Type: #{v[:vol_type]}"
      when :unknown
        values << '(unknown)'
      end
    end

    values
  end

end

end
end
end
end

