# -*- coding: binary -*-
#

module Rex
module Parser
class Unattend

	def self.parse(xml)
                       tables = []
                       unattend = xml.elements['unattend']
                       return if unattend.nil?

                        unattend.each_element do |settings|
                                next if settings.class != REXML::Element
                                settings.get_elements('component').each do |c|
                                        next if c.class != REXML::Element
                                        tables << extract_useraccounts(c.elements['UserAccounts'])
                                        tables << extract_autologon(c.elements['AutoLogon'])
                                        tables << extract_deployment(c.elements['WindowsDeploymentServices'])
                                end
                        end
		
		return tables
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

                table = Rex::Ui::Text::Table.new({
                        'Header' => 'WindowsDeploymentServices',
                        'Indent' => 1,
                        'Columns' => ['Domain', 'Username', 'Password']
                })

                table << [domain, username, password]
                
		return [table]
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

                table = Rex::Ui::Text::Table.new({
                        'Header' => 'AutoLogon',
                        'Indent' => 1,
                        'Columns' => ['Domain', 'Username', 'Password']
                })

                table << [domain, username, password]

                return [table]
        end

        #
        # Extract sensitive data from UserAccounts
        #
        def self.extract_useraccounts(user_accounts)
                return[] if user_accounts.nil?

                cred_tables = []
                account_types = ['AdministratorPassword', 'DomainAccounts', 'LocalAccounts']
                account_types.each do |t|
                        element = user_accounts.elements[t]
                        next if element.nil?

                        case t
                        #
                        # Extract the password from AdministratorPasswords
                        #
                        when account_types[0]
                                table = Rex::Ui::Text::Table.new({
                                        'Header'  => 'AdministratorPasswords',
                                        'Indent'  => 1,
                                        'Columns' => ['Username', 'Password']
                                })

                                password = element.elements['Value'].get_text.value rescue ''
                                plaintext = element.elements['PlainText'].get_text.value rescue 'true'

                                if plaintext == 'false'
                                        password = Rex::Text.decode_base64(password)
                                        password = password.gsub(/#{Rex::Text.to_unicode('AdministratorPassword')}$/, '')
                                end

                                if not password.empty?
                                        table << ['Administrator', password]
                                        cred_tables << table
                                end

                        #
                        # Extract the sensitive data from DomainAccounts.
                        # According to MSDN, unattend.xml doesn't seem to store passwords for domain accounts
                        #
                        when account_types[1]  #DomainAccounts
                                table = Rex::Ui::Text::Table.new({
                                        'Header'  => 'DomainAccounts',
                                        'Indent'  => 1,
                                        'Columns' => ['Username', 'Group']
                                })
                                element.elements.each do |account_list|
                                        name = account_list.elements['DomainAccount/Name'].get_text.value rescue ''
                                        group = account_list.elements['DomainAccount/Group'].get_text.value rescue 'true'

                                        table << [name, group]
                                end

                                cred_tables << table if not table.rows.empty?

                        #
                        # Extract the username/password from LocalAccounts
                        #
                        when account_types[2]  #LocalAccounts
                                table = Rex::Ui::Text::Table.new({
                                        'Header'  => 'LocalAccounts',
                                        'Indent'  => 1,
                                        'Columns' => ['Username', 'Password']
                                })

                                element.elements.each do |local|
                                        password = local.elements['Password/Value'].get_text.value rescue ''
                                        plaintext = local.elements['Password/PlainText'].get_text.value rescue 'true'

                                        if plaintext == 'false'
                                                password = Rex::Text.decode_base64(password)
                                                password = password.gsub(/#{Rex::Text.to_unicode('Password')}$/, '')
                                        end

                                        username = local.elements['Name'].get_text.value rescue ''
                                        table << [username, password]
                                end

                                cred_tables << table if not table.rows.empty?
                        end
                end

                return cred_tables
        end

end


end
end
