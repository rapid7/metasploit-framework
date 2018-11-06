class CreateMetasploitCredentialRealms < ActiveRecord::Migration
  def change
    create_table :metasploit_credential_realms do |t|
      t.string :key, null: false
      t.string :value, null: false

      t.timestamps null: false
    end
  end
end
