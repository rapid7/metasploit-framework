class CreateMetasploitCredentialLogins < ActiveRecord::Migration
  def change
    create_table :metasploit_credential_logins do |t|
      #
      # Foreign Keys
      #

      t.references :core, null: false
      t.references :service, null: false

      #
      # Columns
      #

      t.string :access_level, null: true
      t.string :status, null: false

      #
      # Timestamps
      #

      t.datetime :last_attempted_at, null: true
      t.timestamps null: false
    end

    change_table :metasploit_credential_logins do |t|
      t.index [:core_id, :service_id], unique: true
      t.index [:service_id, :core_id], unique: true
    end
  end
end
