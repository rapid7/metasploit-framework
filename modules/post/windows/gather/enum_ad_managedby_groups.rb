##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP

  USER_FIELDS = ['cn',
                 'distinguishedname',
                 'managedBy',
                 'description'].freeze

  def initialize(info = {})
    super(update_info(
      info,
      'Name'         => 'Windows Gather Active Directory Managed Groups',
      'Description'  => %{
        This module will enumerate AD groups on the specified domain which are specifically managed.
        It cannot at the moment identify whether the 'Manager can update membership list' option
        option set; if so, it would allow that member to update the contents of that group. This
        could either be used as a persistence mechanism (for example, set your user as the 'Domain
        Admins' group manager) or could be used to detect privilege escalation opportunities
        without having domain admin privileges.
      },
      'License'      => MSF_LICENSE,
      'Author'       => [
        'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>'
      ],
      'Platform'     => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ]
    ))

    register_options([
      OptString.new('ADDITIONAL_FIELDS', [false, 'Additional group fields to retrieve, comma separated.', nil]),
      OptBool.new('RESOLVE_MANAGERS', [true, 'Query LDAP to get the account name of group managers.', true]),
      OptBool.new('SECURITY_GROUPS_ONLY', [true, 'Only include security groups.', true])
    ])
  end

  def run
    @user_fields = USER_FIELDS.dup

    if datastore['ADDITIONAL_FIELDS']
      additional_fields = datastore['ADDITIONAL_FIELDS'].gsub(/\s+/, "").split(',')
      @user_fields.push(*additional_fields)
    end

    max_search = datastore['MAX_SEARCH']

    begin
      qs = '(&(objectClass=group)(managedBy=*))'
      if datastore['SECURITY_GROUPS_ONLY']
        qs = '(&(objectClass=group)(managedBy=*)(groupType:1.2.840.113556.1.4.803:=2147483648))'
      end
      q = query(qs, max_search, @user_fields)
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      # Can't bind or in a network w/ limited accounts
      print_error(e.message)
      return
    end

    if q.nil? || q[:results].empty?
      print_status('No results returned.')
    else
      @user_fields << 'Manager Account Name' if datastore['RESOLVE_MANAGERS']
      results_table = parse_results(q[:results])
      print_line results_table.to_s
    end
  end

  # Takes the results of LDAP query, parses them into a table
  def parse_results(results)
    results_table = Rex::Text::Table.new(
      'Header'     => "Groups with Managers",
      'Indent'     => 1,
      'SortIndex'  => -1,
      'Columns'    => @user_fields
    )

    results.each do |result|
      row = []

      result.each do |field|
        if field.nil?
          row << ""
        else
          row << field[:value]
        end
      end
      if datastore['RESOLVE_MANAGERS']
        begin
          m = query("(distinguishedName=#{result[2][:value]})", 1, ['sAMAccountName'])
          if !m.nil? && !m[:results].empty?
            row << m[:results][0][0][:value]
          else
            row << ""
          end
        rescue
          row << ""
        end
      end
      results_table << row
    end
    results_table
  end
end
