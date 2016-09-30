require 'metasploit/framework/database/cucumber'

Given /^the project "database.yml" does not exist$/ do
  Metasploit::Framework::Database::Cucumber.backup_project_configurations
end

Given /^the project "database.yml" exists with:$/ do |file_content|
  Metasploit::Framework::Database::Cucumber.backup_project_configurations
  File.open(Metasploit::Framework::Database::Cucumber.project_configurations_path, 'wb') { |file| file.write(file_content) }
end

After do
  Metasploit::Framework::Database::Cucumber.restore_project_configurations
end