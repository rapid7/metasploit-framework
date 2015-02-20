# -*- coding: binary -*-

module Rex
module Parser

# This is a parser for the Windows Unattended Answer File
# format. It's used by modules/post/windows/gather/enum_unattend.rb
# and uses REXML (as opposed to Nokogiri) for its XML parsing.
# See: http://technet.microsoft.com/en-us/library/ff715801
#      http://technet.microsoft.com/en-us/library/cc749415(v=ws.10).aspx
# Samples: http://technet.microsoft.com/en-us/library/cc732280%28v=ws.10%29.aspx
class Unattend
  
  require 'rex/text'

  def self.parse(xml)
    return [] if xml.nil?
    results = []
    unattend = xml.elements['unattend']
    return [] if unattend.nil?
    unattend.each_element do |settings|
        next if settings.class != REXML::Element
        settings.get_elements('component').each do |c|
          next if c.class != REXML::Element
          results << extract_useraccounts(c.elements['UserAccounts'])
          results << extract_autologon(c.elements['AutoLogon'])
          results << extract_deployment(c.elements['WindowsDeploymentServices'])
          results << extract_domain_join(c.elements['Identification/Credentials'])
        end
      end
    return results.flatten
  end

  #
  # Extract sensitive data from Deployment Services.
  # We can only seem to add one <Login> with Windows System Image Manager, so
  # we'll only enum one.
  #
  def self.extract_deployment(deployment)
    return [] if deployment.nil?
    domain    = deployment.elements['Login/Credentials/Domain'].get_text.value rescue ''
    username  = deployment.elements['Login/Credentials/Username'].get_text.value rescue ''
    password  = deployment.elements['Login/Credentials/Password'].get_text.value rescue ''
    plaintext = deployment.elements['Login/Credentials/Password/PlainText'].get_text.value rescue 'true'

    if plaintext == 'false'
      password = Rex::Text.decode_base64(password)
      password = password.gsub(/#{Rex::Text.to_unicode('Password')}$/, '')
    end

    return {'type' => 'wds', 'domain' => domain, 'username' => username, 'password' => password }
  end

  #
  # Extract sensitive data from 'Secure' Domain Join
  #
  def self.extract_domain_join(credentials)
    return [] if credentials.nil?
    domain    = credentials.elements['Domain'].get_text.value rescue ''
    username  = credentials.elements['Username'].get_text.value rescue ''
    password  = credentials.elements['Password'].get_text.value rescue ''

    return {'type' => 'domain_join', 'domain' => domain, 'username' => username, 'password' => password }
  end

  #
  # Extract sensitive data from AutoLogon
  #
  def self.extract_autologon(auto_logon)
    return [] if auto_logon.nil?

    domain    = auto_logon.elements['Domain'].get_text.value rescue ''
    username  = auto_logon.elements['Username'].get_text.value rescue ''
    password  = auto_logon.elements['Password/Value'].get_text.value rescue ''
    plaintext = auto_logon.elements['Password/PlainText'].get_text.value rescue 'true'

    if plaintext == 'false'
      password = Rex::Text.decode_base64(password)
      password = password.gsub(/#{Rex::Text.to_unicode('Password')}$/, '')
    end

    return {'type' => 'auto', 'domain' => domain, 'username' => username, 'password' => password }
  end

  #
  # Extract sensitive data from UserAccounts
  #
  def self.extract_useraccounts(user_accounts)
    return[] if user_accounts.nil?

    results = []
    account_types = ['AdministratorPassword', 'DomainAccounts', 'LocalAccounts']
    account_types.each do |t|
      element = user_accounts.elements[t]
      next if element.nil?

      case t
      #
      # Extract the password from AdministratorPasswords
      #
      when account_types[0]
        password = element.elements['Value'].get_text.value rescue ''
        plaintext = element.elements['PlainText'].get_text.value rescue 'true'

        if plaintext == 'false'
          password = Rex::Text.decode_base64(password)
          password = password.gsub(/#{Rex::Text.to_unicode('AdministratorPassword')}$/, '')
        end

        unless password.empty?
          results << {'type' => 'admin', 'username' => 'Administrator', 'password' => password}
        end

      #
      # Extract the sensitive data from DomainAccounts.
      # According to MSDN, unattend.xml doesn't seem to store passwords for domain accounts
      #
      when account_types[1]  #DomainAccounts
        element.elements.each do |account_list|
          name = account_list.elements['DomainAccount/Name'].get_text.value rescue ''
          group = account_list.elements['DomainAccount/Group'].get_text.value rescue 'true'

          results << {'type' => 'domain', 'username' => name, 'group' => group}
        end
      #
      # Extract the username/password from LocalAccounts
      #
      when account_types[2]  #LocalAccounts
        element.elements.each do |local|
          password = local.elements['Password/Value'].get_text.value rescue ''
          plaintext = local.elements['Password/PlainText'].get_text.value rescue 'true'

          if plaintext == 'false'
            password = Rex::Text.decode_base64(password)
            password = password.gsub(/#{Rex::Text.to_unicode('Password')}$/, '')
          end

          username = local.elements['Name'].get_text.value rescue ''
          results << {'type' => 'local', 'username' => username, 'password' => password}
        end
      end
    end

    return results
  end

  def self.create_table(results)
    return nil if results.nil? or results.empty?
    table = Rex::Ui::Text::Table.new({
      'Header' => 'Unattend Credentials',
      'Indent' => 1,
      'Columns' => ['Type', 'Domain', 'Username', 'Password', 'Groups']
    })

    results.each do |result|
      case result['type']
        when 'wds', 'auto', 'domain_join'
          table << [result['type'], result['domain'], result['username'], result['password'], ""]
        when 'admin', 'local'
          table << [result['type'], "", result['username'], result['password'], ""]
        when 'domain'
          table << [result['type'], "", result['username'], "", result['group']]
      end
    end

    return table
  end
end
end
end

