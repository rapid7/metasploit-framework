##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::UserProfiles

  SYNC_ENGINES_KEYS = ['LibraryType', 'LastModifiedTime', 'MountPoint', 'UrlNamespace'].freeze
  ONEDRIVE_ACCOUNT_KEYS = ['Business', 'ServiceEndpointUri', 'SPOResourceId', 'UserEmail', 'UserFolder', 'UserName'].freeze
  PERSONAL_ONEDRIVE_KEYS = ['UserEmail', 'UserFolder'].freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'OneDrive Sync Provider Enumeration Module',
        'Description' => %q{
          This module will identify the Office 365 OneDrive endpoints for both business and personal accounts
          across all users (providing access is permitted). It is useful for identifying document libraries
          that may otherwise not be obvious which could contain sensitive or useful information.
        },
        'License' => MSF_LICENSE,
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'Author' => ['Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>']
      )
    )
  end

  def display_report(sid, info, sync_used, sync_all, results_table)
    info.each do |key, result|
      next if result['ScopeIdToMountPointPathCache'].nil? || result['ScopeIdToMountPointPathCache'].empty?

      row = []
      print_line
      print_line "  #{key}"
      print_line "  #{'=' * key.length}"
      print_line
      row << sid
      row << key
      ONEDRIVE_ACCOUNT_KEYS.each do |col|
        row << result[col].to_s
        if result['Business'] == '1' || PERSONAL_ONEDRIVE_KEYS.include?(col)
          print_line "    #{col}: #{result[col]}"
        end
      end
      result['ScopeIdToMountPointPathCache'].each do |scopes|
        subrow = row.clone
        print_line
        SYNC_ENGINES_KEYS.each do |sync|
          subrow << scopes[sync].to_s
          print_line "    | #{sync}: #{scopes[sync]}"
        end
        results_table << subrow
      end
    end

    sync_all_list = []
    sync_all.each do |key, _result|
      sync_all_list.push(key)
    end

    diff = sync_all_list - sync_used
    if !(diff.nil? || diff.empty?)
      print_line
      print_line '  ORPHANED'
      print_line '  ========'
      diff.each do |scopeid|
        csvrow = []
        print_line
        # Augment the CSV
        csvrow << sid
        csvrow << ''
        ONEDRIVE_ACCOUNT_KEYS.each do |_od|
          csvrow << ''
        end
        SYNC_ENGINES_KEYS.each do |sync|
          csvrow << sync_all[scopeid][sync]
          print_line "  #{sync}: #{sync_all[scopeid][sync]}"
        end
        results_table << csvrow
      end
    end
  end

  def get_syncengine_data(master, syncengines)
    all_syncengines = {}
    syncengines.each do |sync_provider| # Sync provider names are normally Personal for personal accounts
      # or a hash value that is unique to each business account.
      tmp_sync_provider_info = {}
      SYNC_ENGINES_KEYS.each do |key|
        tmp_sync_provider_info[key] = registry_getvaldata("#{master}\\#{sync_provider}", key).to_s
      end
      all_syncengines[sync_provider] = tmp_sync_provider_info
    end
    all_syncengines
  end

  def get_onedrive_accounts(reg, accounts, syncdata)
    all_oda = {}
    synctargets_used = []
    ret = {}
    reg.each do |ses|
      newses = {}
      scopeids = registry_enumvals("#{accounts}\\#{ses}\\ScopeIdToMountPointPathCache")
      next if scopeids.nil? || scopeids.empty?

      ONEDRIVE_ACCOUNT_KEYS.each do |key|
        newses[key] = registry_getvaldata("#{accounts}\\#{ses}", key).to_s
      end

      newses['ScopeIdToMountPointPathCache'] = []
      scopeids.each do |sid|
        target = syncdata[sid]
        if newses['Business'] != '1'
          target = syncdata['Personal']
          synctargets_used.push('Personal')
        else
          synctargets_used.push(sid)
        end
        newses['ScopeIdToMountPointPathCache'].push(target)
      end
      all_oda[ses] = newses
    end
    ret['oda'] = all_oda
    ret['synctargets_used'] = synctargets_used
    ret
  end

  def run
    # Obtain all user hives
    userhives = load_missing_hives
    got_results = false

    # Prepare the results table
    results_table = Rex::Text::Table.new(
      'Header' => 'OneDrive Sync Information',
      'Indent' => 1,
      'SortIndex' => -1,
      'Columns' => ['SID', 'Name'] + ONEDRIVE_ACCOUNT_KEYS + SYNC_ENGINES_KEYS
    )

    if userhives.nil? || userhives.empty?
      fail_with(Failure::UnexpectedReply, 'Unable to load the missing hives needed to enumerate the target!')
    end
    # Loop through each of the hives
    userhives.each do |hive|
      next if hive['HKU'].nil?

      print_status("Looking for OneDrive sync information for #{hive['SID']}")
      master_key = "#{hive['HKU']}\\Software\\SyncEngines\\Providers\\OneDrive"
      saved_syncengines = registry_enumkeys(master_key)
      if saved_syncengines.nil? || saved_syncengines.empty?
        print_error("(#{hive['HKU']}) No OneDrive accounts found.")
        next
      end

      # Obtain the sync endpoints from the above subkey
      all_syncengines = get_syncengine_data(master_key, saved_syncengines)

      str_onedrive_accounts = "#{hive['HKU']}\\Software\\Microsoft\\OneDrive\\Accounts"
      reg_onedrive_accounts = registry_enumkeys(str_onedrive_accounts)
      if reg_onedrive_accounts.nil? || reg_onedrive_accounts.empty?
        print_error("(#{hive['HKU']}) No OneDrive accounts found.")
        next
      end

      result = get_onedrive_accounts(reg_onedrive_accounts, str_onedrive_accounts, all_syncengines)

      if result['oda'].nil? || result['oda'].empty?
        print_error("(#{hive['HKU']}) No OneDrive accounts found.")
        next
      end

      got_results = true
      print_good("OneDrive sync information for #{hive['SID']}")
      display_report(hive['SID'], result['oda'], result['synctargets_used'], all_syncengines, results_table)
    end

    print_line

    if got_results
      stored_path = store_loot('onedrive.syncinformation', 'text/csv', session, results_table.to_csv, 'onedrive_syncinformation.csv', 'OneDrive sync endpoints')
      print_good("OneDrive sync information saved to #{stored_path} in CSV format.")
    end

    # Clean up
    unload_our_hives(userhives)
  end
end
