class CreateMetasploitCredentialOriginManuals < ActiveRecord::Migration
  def change
    create_table :metasploit_credential_origin_manuals do |t|
      #
      # Foreign Keys
      #

      t.references :user, null: false

      #
      # Timestamps
      #

      t.timestamps null: false
    end

    #
    # Foreign Key Indices
    #

    add_index :metasploit_credential_origin_manuals, :user_id
  end
end
