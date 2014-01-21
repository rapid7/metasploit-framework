##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'
require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP

  def initialize(info={})
    super( update_info( info,
        'Name'	       => 'Windows Gather Active Directory Service Principal Names',
        'Description'  => %Q{
            This module will enumerate servicePrincipalName in the default AD directory
            where the user is a member of the Domain Admins group.
        },
        'License'      => MSF_LICENSE,
        'Author'       => [
          'Ben Campbell <ben.campbell[at]mwrinfosecurity.com>', #Metasploit Module
          'Scott Sutherland' #Original Powershell Code
        ],
        'Platform'     => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'References'	=>
        [
          ['URL', 'https://www.netspi.com/blog/entryid/214/faster-domain-escalation-using-ldap'],
        ]
      ))

    register_options([
      OptInt.new('MAX_SEARCH', [true, 'Maximum values to retrieve, 0 for all.', 50]),
      OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
      OptString.new('FIELDS', [true, 'FIELDS to retrieve.', 'cn,servicePrincipalName']),
      OptString.new('FILTER', [true, 'Search filter, DOM_REPL will be automatically replaced', '(&(objectCategory=user)(memberOf=CN=Domain Admins,CN=Users,DOM_REPL))'])
    ], self.class)
  end

  def run
    fields = datastore['FIELDS'].gsub(/\s+/,"").split(',')
    fields << "Server"
    fields << "Service"
    search_filter = datastore['FILTER']
    max_search = datastore['MAX_SEARCH']
    domain = get_default_naming_context
    search_filter.gsub!('DOM_REPL',domain)

    q = query(search_filter, max_search, fields)

    if q.nil? or q[:results].empty?
      return
    end

    # Results table holds raw string data
    results_table = Rex::Ui::Text::Table.new(
        'Header'     => "Service Principal Names",
        'Indent'     => 1,
        'SortIndex'  => -1,
        'Columns'    => fields
      )

    q[:results].each do |result|
      row = []

      0.upto(fields.length-3) do |i|
        if result[i].nil?
          field = ""
        else
          field = result[i]
        end

        row << field

       case fields[i]
       when "servicePrincipalName"
         split = field.split('/')
         if split.length == 2
           row << split[0]
           row << split[1]
         end
       end 

      end

      results_table << row
    end

    print_line results_table.to_s
    if datastore['STORE_LOOT']
      stored_path = store_loot('ad.computers', 'text/plain', session, results_table.to_csv)
      print_status("Results saved to: #{stored_path}")
    end
  end

end

