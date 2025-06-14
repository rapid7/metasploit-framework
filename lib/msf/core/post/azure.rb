# -*- coding: binary -*-

module Msf::Post::Azure
  def process_tokens_file(content)
    table_data = []

    dic = {}
    content.each do |item|
      if dic.key?(item['userId'])
        dic[item['userId']] = dic[item['userId']] + 1
      else
        dic[item['userId']] = 1
      end
    end
    dic.each do |key, value|
      table_data << [file_path, key, value]
    end

    table_data
  end

  #
  # Processes a hashtable (json) from azureProfile.json
  #
  # @param content [Hash] contents of a json file to process
  # @return [Array]
  def process_profile_file(content)
    table_data = []

    # make sure we have keys we expect to
    return table_data unless content.key? 'subscriptions'

    content['subscriptions'].each do |item|
      table_data << [item['name'], item.dig('user', 'name'), item['environmentName']]
    end
    table_data
  end

  #
  # Processes a hashtable (json) generated via Save-AzContext or automatically
  # generated in AzureRmContext.json
  #
  # @param content [Hash] contents of a json file to process
  # @return [Array]
  def process_context_contents(content)
    table_data = []

    # make sure we have keys we expect to
    return table_data unless content.key? 'Contexts'

    content['Contexts'].each_value do |account|
      username = account.dig('Account', 'Id')
      type = account.dig('Account', 'Type')
      principal_secret = account.dig('Account', 'ExtendedProperties', 'ServicePrincipalSecret') # only in 'ServicePrincipal' types
      access_token = account.dig('Account', 'ExtendedProperties', 'AccessToken')
      graph_access_token = account.dig('Account', 'ExtendedProperties', 'GraphAccessToken')
      # example of parsing these out to get an expiration for the token
      # unless graph_access_token.nil? || graph_access_token.empty?
      #   decoded_token = Msf::Exploit::Remote::HTTP::JWT.decode(graph_access_token)
      #   graph_access_token_exp = Time.at(decoded_token.payload['exp']).to_datetime
      # end
      ms_graph_access_token = account.dig('Account', 'ExtendedProperties', 'MicrosoftGraphAccessToken')
      key_vault_token = account.dig('Account', 'ExtendedProperties', 'KeyVault')
      table_data.append([username, type, access_token, graph_access_token, ms_graph_access_token, key_vault_token, principal_secret])
    end
    table_data
  end

  #
  # Print any lines from a ConsoleHost_history.txt file that may have
  # important information
  #
  # @param content [Str] contents of a ConsoleHost_history.txt file
  # @return Array of strings to print to notify the user about
  def print_consolehost_history(content)
    # a list of strings which may contain secrets or other important information
    commands_of_value = [
      'System.Management.Automation.PSCredential', # for creating new credentials, may contain username/password
      'ConvertTo-SecureString', # often used with passwords
      'Connect-AzAccount', # may contain an access token in line or near it
      'New-PSSession', # may indicate lateral movement to a new host
      'commandToExecute', # when used with Set-AzVMExtension and a CustomScriptExtension, may show code execution
      '-ScriptBlock' # when used with Invoke-Command, may show code execution
    ]

    output = []

    content.each_line.with_index do |line, index|
      commands_of_value.each do |command|
        if line.downcase.include? command.downcase
          output.append("Line #{index + 1} may contain sensitive information. Manual search recommended, keyword hit: #{command}")
        end
      end
    end
    output
  end
end
