class CreateMetasploitCredentialPrivates < ActiveRecord::Migration
  def change
    create_table :metasploit_credential_privates do |t|
      #
      # Single Table Inheritance
      #

      t.string :type, null: false

      #
      # Columns
      #

      t.text :data, null: false

      #
      # Timestamps
      #

      t.timestamps null: false
    end

    change_table :metasploit_credential_privates do |t|
      t.index [:type, :data],
              unique: true
    end
  end
end
