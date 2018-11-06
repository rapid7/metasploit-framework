class CreateMetasploitCredentialPublics < ActiveRecord::Migration
  def change
    create_table :metasploit_credential_publics do |t|
      #
      # Columns
      #

      t.string :username, null: false

      #
      # Timestamps
      #

      t.timestamps null: false
    end

    change_table :metasploit_credential_publics do |t|
      t.index :username,
              unique: true
    end
  end
end
