class CreateMetasploitCredentialOriginCrackedPasswords < ActiveRecord::Migration
  def change
    create_table :metasploit_credential_origin_cracked_passwords do |t|


      #
      # Foreign Keys
      #

      t.references :metasploit_credential_core , null: false

      #
      # Timestamps
      #

      t.timestamps null: false
    end

    #
    # Foreign Key Indices
    #

    add_index :metasploit_credential_origin_cracked_passwords,
              :metasploit_credential_core_id,
              name: :originating_credential_cores

  end
end
