class UniqueMetasploitCredentialRealms < ActiveRecord::Migration
  def change
    change_table :metasploit_credential_realms do |t|
      t.index [:key, :value], unique: true
    end
  end
end
