##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'
require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Enumerate Active Directory Trusts From Current Domain',
      'Description'  => %q{
        This module will enumerate AD trusts from the current domain, including decoding 
        of the remote SIDs. This could be particularly useful when creating golden tickets
        with a SID history, or just to immediately map the available trusts.
      },
      'License'      => MSF_LICENSE,
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter'],
      'Author'       => ['Stuart Morgan <ben.campbell[at]mwrinfosecurity.com>'],
    ))

    register_options([
      OptInt.new('MAX_SEARCH', [true, 'Maximum number of items.', '500'])
    ], self.class)
  end

  def run
    ldap_fields = ['flatname','cn','instanceType','securityIdentifier','trustAttributes','trustDirection','trustType','whenCreated','whenChanged']
    ldap_names = ['Name','Domain','Type','SID','Attributes','Direction','Trust Type','Created','Changed']
    search_filter = '(objectClass=trustedDomain)'
    max_search = datastore['MAX_SEARCH']

    begin
      trust_results = query(search_filter, max_search, fields)
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      print_error(e.message)
      return
    end

    if trust_results.nil? || trust_results[:results].empty?
      print_error('No trusts found')
      return
    end

    # Results table holds raw string data
    results_table = Rex::Ui::Text::Table.new(
      'Header'     => 'Domain Trusts',
      'Indent'     => 1,
      'SortIndex'  => -1,
      'Columns'    => ldap_names
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

  end
end
