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
  PERSONAL_ONEDRIVE_KEYS = ["UserEmail", "UserFolder"]

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

  def display_report(info)
    info.each do |key, result|
      row = []
      print_line "  #{key}"
      print_line "  " + "=" * key.length
      print_line
      ONEDRIVE_ACCOUNT_KEYS.each do |col|
        if result["Business"] == "1" || PERSONAL_ONEDRIVE_KEYS.include?(col) 
          print_line "    #{col}: #{result[col].to_s}"
        end
      end
      result["ScopeIdToMountPointPathCache"].each do |scopes|
        print_line
        SYNC_ENGINES_KEYS.each do |sync|
          print_line "    | #{sync}: #{scopes[sync].to_s}"
        end
      print_line
      end
    end
    #stored_path = store_loot('putty.storedfingerprints.csv', 'text/csv', session, results_table.to_csv, nil, "PuTTY Stored SSH Host Keys List")
    #print_good("PuTTY stored host keys list saved to #{stored_path} in CSV format & available in notes (use 'notes -t putty.storedfingerprint' to view).")
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

  def run
    # Obtain all user hives
    userhives=load_missing_hives()

    # Loop through each of the hives
    userhives.each do |hive|
      next if hive['HKU'] == nil

      print_status("Looking for OneDrive sync information for #{hive['SID']}")
      master_key = "#{hive['HKU']}\\Software\\SyncEngines\\Providers\\OneDrive"
      saved_syncengines = registry_enumkeys(master_key)
      next if saved_syncengines.nil? || saved_syncengines.empty?
      # Obtain the sync endpoints from the above subkey
      all_syncengines = get_syncengine_data(master_key, saved_syncengines)

      str_onedrive_accounts = "#{hive['HKU']}\\Software\\Microsoft\\OneDrive\\Accounts"
      reg_onedrive_accounts = registry_enumkeys(str_onedrive_accounts)
      all_odaccounts = get_onedrive_accounts(reg_onedrive_accounts, str_onedrive_accounts, all_syncengines)

      if not (all_odaccounts.nil? || all_odaccounts.empty?)
        print_good "OneDrive sync information for #{hive['SID']}"
        print_line
        display_report(all_odaccounts)
      end
    end

    # Clean up
    unload_our_hives(userhives)

  end
end
