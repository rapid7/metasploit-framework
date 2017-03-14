require 'metasploit/framework/database'

module Metasploit::Framework::Database::Cucumber
  def self.project_configurations_path
    Rails.root.join('config', 'database.yml').to_path
  end

  def self.backup_project_configurations
    if File.exist?(project_configurations_path)
      # assume that the backup file is from a previously aborted run and it contains the real database.yml data, so
      # just delete the fake database.yml and the After hook will restore the real database.yml from the backup location
      if File.exist?(backup_project_configurations_path)
        File.delete(project_configurations_path)
      else
        # project contains the real database.yml and there was no previous, aborted run.
        File.rename(project_configurations_path, backup_project_configurations_path)
      end
    end
  end

  def self.backup_project_configurations_path
    "#{project_configurations_path}.cucumber.bak"
  end

  def self.restore_project_configurations
    if File.exist?(backup_project_configurations_path)
      if File.exist?(project_configurations_path)
        # Remove fake, leftover database.yml
        File.delete(project_configurations_path)
      end

      File.rename(backup_project_configurations_path, project_configurations_path)
    end
  end
end

