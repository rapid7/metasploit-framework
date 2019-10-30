##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP
  #  include Msf::Post::Windows::Accounts

  USER_FIELDS = ['name',
                 'distinguishedname',
                 'description'].freeze

  def initialize(info = {})
    super(update_info(
      info,
      'Name'         => 'Windows Gather Active Directory Groups',
      'Description'  => %(
        This module will enumerate AD groups on the specified domain.
            ),
      'License'      => MSF_LICENSE,
      'Author'       => [
        'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>'
      ],
      'Platform'     => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ]
    ))

    register_options([
      OptString.new('ADDITIONAL_FIELDS', [false, 'Additional fields to retrieve, comma separated', nil]),
      OptString.new('FILTER', [false, 'Customised LDAP filter', nil])
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
      f = ""
      f = "(#{datastore['FILTER']})" if datastore['FILTER']
      q = query("(&(objectClass=group)#{f})", max_search, @user_fields)
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      # Can't bind or in a network w/ limited accounts
      print_error(e.message)
      return
    end

    if q.nil? || q[:results].empty?
      print_status('No results returned.')
    else
      results_table = parse_results(q[:results])
      print_line results_table.to_s
    end
  end

  # Takes the results of LDAP query, parses them into a table
  # and records and usernames as {Metasploit::Credential::Core}s in
  # the database.
  #
  # @param [Array<Array<Hash>>] the LDAP query results to parse
  # @return [Rex::Text::Table] the table containing all the result data
  def parse_results(results)
    # Results table holds raw string data
    results_table = Rex::Text::Table.new(
      'Header'     => "Domain Groups",
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

      results_table << row
    end
    results_table
  end
end
