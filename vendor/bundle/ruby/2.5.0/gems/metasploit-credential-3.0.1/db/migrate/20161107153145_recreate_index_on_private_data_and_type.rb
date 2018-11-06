class RecreateIndexOnPrivateDataAndType < ActiveRecord::Migration
  def change
    remove_index :metasploit_credential_privates, [:type, :data]
    
    change_table :metasploit_credential_privates do |t|
      t.index [:type, :data],
              unique: true,
              where: "NOT (type = 'Metasploit::Credential::SSHKey')"
    end
  end
end
