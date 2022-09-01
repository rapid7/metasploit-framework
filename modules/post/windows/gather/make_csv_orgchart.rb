##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP

  def initialize(info = {})
    super(update_info(
      info,
      'Name'         => 'Generate CSV Organizational Chart Data Using Manager Information',
      'Description'  => %(
        This module will generate a CSV file containing all users and their managers, which can be
        imported into Visio which will render it.
            ),
      'License'      => MSF_LICENSE,
      'Author'       => [
        'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>'
      ],
      'Platform'     => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ]
    ))

    register_options([
      OptBool.new('WITH_MANAGERS_ONLY', [true, 'Only users with managers', false]),
      OptBool.new('ACTIVE_USERS_ONLY', [true, 'Only include active users (i.e. not disabled ones)', true]),
      OptBool.new('STORE_LOOT', [true, 'Store the organizational chart information in CSV format in loot', true]),
      OptString.new('FILTER', [false, 'Additional LDAP filter to use when searching for users', ''])
    ])
  end

  def run
    max_search = datastore['MAX_SEARCH']
    user_fields = ['cn', 'manager', 'description', 'title', 'telephoneNumber', 'department', 'division', 'userPrincipalName', 'company']

    begin
      qs = []
      qs << '(objectCategory=person)'
      qs << '(objectClass=user)'
      qs << '(!userAccountControl:1.2.840.113556.1.4.803:=2)' if datastore['ACTIVE_USERS_ONLY']
      qs << '(manager=*)' if datastore['WITH_MANAGERS_ONLY']
      qs << "(#{datastore['FILTER']})" if datastore['FILTER'] != ""

      query_string = "(&(#{qs.join('')}))"
      vprint_status("Executing #{query_string}")
      q = query(query_string, max_search, user_fields)
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      # Can't bind or in a network w/ limited accounts
      print_error(e.message)
      return
    end

    if q.nil? || q[:results].empty?
      print_status('No results returned.')
    else
      user_fields << 'reports_to'
      results_table = parse_results(q[:results])
      print_line results_table.to_s
      if datastore['STORE_LOOT']
        stored_path = store_loot('ad.orgchart', 'text/csv', session, results_table.to_csv)
        print_good("CSV Organisational Chart Information saved to: #{stored_path}")
      end
    end
  end

  # Takes the results of LDAP query, parses them into a table
  def parse_results(results)
    results_table = Rex::Text::Table.new(
      'Header'     => "Users & Managers",
      'Indent'     => 1,
      'SortIndex'  => -1,
      'Columns'    => ['cn', 'description', 'title', 'phone', 'department', 'division', 'e-mail', 'company', 'reports_to']
    )

    results.each do |result|
      row = []

      result.each_with_index do |field, idx|
        next if idx == 1 # Don't include the manager DN

        if field.nil?
          row << ""
        else
          row << field[:value]
        end
      end

      # Parse the manager CN string to grab the CN= field only.
      # Note that it needs the negative lookbehind to avoid escaped characters.
      reports_to = /^CN=(?<cn>.+?),(?<!\\,)/.match(result[1][:value])
      if reports_to.nil?
        row << ""
      else
        row << reports_to['cn'].gsub('\,', ',')
      end

      results_table << row
    end
    results_table
  end
end
