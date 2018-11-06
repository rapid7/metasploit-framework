class AddLoginsCounterCacheToCores < ActiveRecord::Migration
  def self.up
    add_column :metasploit_credential_cores, :logins_count, :integer, :default => 0

    Metasploit::Credential::Core.reset_column_information
    Metasploit::Credential::Core.all.each do |c|
      Metasploit::Credential::Core.reset_counters c.id, :logins
    end
  end

  def self.down
    remove_column :metasploit_credential_cores, :logins_count
  end
end
