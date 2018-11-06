class CreateMetasploitCredentialOriginServices < ActiveRecord::Migration
  def change
    create_table :metasploit_credential_origin_services do |t|
      #
      # Foreign Keys
      #

      t.references :service, null: false

      #
      # Columns
      #

      t.text :module_full_name, null: false

      #
      # Timestamps
      #

      t.timestamps null: false
    end

    #
    # Indices
    #

    # Index name 'index_metasploit_credential_origin_services_on_service_id_and_module_full_name' on table
    # 'metasploit_credential_origin_services' is too long; the limit is 63
    add_index :metasploit_credential_origin_services,
              [:service_id, :module_full_name],
              name: :unique_metasploit_credential_origin_services,
              unique: true
  end
end
