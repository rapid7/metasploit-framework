##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'pp'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::UserProfiles


  SYNC_ENGINES_KEYS = ["LibraryType","LastModifiedTime","MountPoint","UrlNamespace"]
  ONEDRIVE_ACCOUNT_KEYS = ["Business", "ServiceEndpointUri", "SPOResourceId", "UserEmail", "UserFolder", "UserName"]

  def initialize(info = {})
    super(update_info(info,
                      'Name'            => "OneDrive Sync Provider Enumeration Module",
                      'Description'     => %q{
                        This module will identify the Office 365 OneDrive endpoints for both business and personal accounts
                        across all users (providing access is permitted). It is useful for identifying document libraries
                        that may otherwise not be obvious which could contain sensitive or useful information.
                       },
                      'License'         => MSF_LICENSE,
                      'Platform'        => ['win'],
                      'SessionTypes'    => ['meterpreter'],
                      'Author'          => ['Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>']
                     ))
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

  def get_syncengine_data(master,syncengines)
    all_syncengines = {}
    syncengines.each do |ses|
      newses = {}
      SYNC_ENGINES_KEYS.each do |key|
        newses[key] = registry_getvaldata("#{master}\\#{ses}", key).to_s
      end
      all_syncengines[ses] = newses
    end
    all_syncengines
  end

  def get_onedrive_accounts(reg,accounts,syncdata)
    all_oda = {}
    reg.each do |ses|
      newses = {}
      ONEDRIVE_ACCOUNT_KEYS.each do |key|
        newses[key] = registry_getvaldata("#{accounts}\\#{ses}", key).to_s

        scopeids = registry_enumvals("#{accounts}\\#{ses}\\ScopeIdToMountPointPathCache")
        scopeids.each do |sid|
          newses["ScopeIdToMountPointPathCache"] = []
          target = syncdata[sid]
          if newses['Business'] != "1"
            target = syncdata["Personal"]
          end
          newses["ScopeIdToMountPointPathCache"].push(target)
        end
      end
      all_oda[ses] = newses
    end
    all_oda
  end

  # Entry point
  def run

    # Obtain all user hives
    userhives=load_missing_hives()

    # Loop through each of the hives
    userhives.each do |hive|
      next if hive['HKU'] == nil
      master_key = "#{hive['HKU']}\\Software\\SyncEngines\\Providers\\OneDrive"
      saved_syncengines = registry_enumkeys(master_key)
      next if saved_syncengines.nil? || saved_syncengines.empty?
      # Obtain the sync endpoints from the above subkey
      all_syncengines = get_syncengine_data(master_key, saved_syncengines)

      str_onedrive_accounts = "#{hive['HKU']}\\Software\\Microsoft\\OneDrive\\Accounts"
      reg_onedrive_accounts = registry_enumkeys(str_onedrive_accounts)
      all_odaccounts = get_onedrive_accounts(reg_onedrive_accounts, str_onedrive_accounts, all_syncengines)

      # Now enumerate each of the accounts
      pp all_syncengines
      pp all_odaccounts
    end

    # Clean up
    unload_our_hives(userhives)

#    # Look for saved sessions, break out if not.
#    print_status("Looking for saved PuTTY sessions")
#    saved_sessions = registry_enumkeys("#{PAGEANT_REGISTRY_KEY}\\Sessions")
#    if saved_sessions.nil? || saved_sessions.empty?
#      print_error('No saved sessions found')
#    else
#
#      # Tell the user how many sessions have been found (with correct English)
#      print_status("Found #{saved_sessions.count} session#{saved_sessions.count > 1 ? 's' : ''}")
#
#      # Retrieve the saved session details & print them to the screen in a report
#      all_saved_sessions = get_saved_session_details(saved_sessions)
#      display_saved_sessions_report(all_saved_sessions)
#
#      # If the private key file has been configured, retrieve it and save it to loot
#      print_status("Downloading private keys...")
#      private_key_info = grab_private_keys(all_saved_sessions)
#      if !private_key_info.nil? && !private_key_info.empty?
#        print_line
#        display_private_key_analysis(private_key_info)
#      end
#    end
#
#    print_line # Just for readability
#
#    # Now search for SSH stored keys. These could be useful because it shows hosts that the user
#    # has previously connected to and accepted a key from.
#    print_status("Looking for previously stored SSH host key fingerprints")
#    stored_ssh_host_keys = registry_enumvals("#{PAGEANT_REGISTRY_KEY}\\SshHostKeys")
#    if stored_ssh_host_keys.nil? || stored_ssh_host_keys.empty?
#      print_error('No stored SSH host keys found')
#    else
#      # Tell the user how many sessions have been found (with correct English)
#      print_status("Found #{stored_ssh_host_keys.count} stored key fingerprint#{stored_ssh_host_keys.count > 1 ? 's' : ''}")
#
#      # Retrieve the saved session details & print them to the screen in a report
#      print_status("Downloading stored key fingerprints...")
#      all_stored_keys = get_stored_host_key_details(stored_ssh_host_keys)
#      if all_stored_keys.nil? || all_stored_keys.empty?
#        print_error("No stored key fingerprints found")
#      else
#        display_stored_host_keys_report(all_stored_keys)
#      end
#    end
#
#    print_line # Just for readability
#
#    print_status("Looking for Pageant...")
#    hwnd = client.railgun.user32.FindWindowW("Pageant", "Pageant")
#    if hwnd['return']
#      print_good("Pageant is running (Handle 0x#{sprintf('%x', hwnd['return'])})")
#    else
#      print_error("Pageant is not running")
#    end
  end
end
