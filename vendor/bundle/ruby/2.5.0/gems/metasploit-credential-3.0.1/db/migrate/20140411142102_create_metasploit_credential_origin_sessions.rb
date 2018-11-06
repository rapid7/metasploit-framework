class CreateMetasploitCredentialOriginSessions < ActiveRecord::Migration
  def change
    create_table :metasploit_credential_origin_sessions do |t|
      #
      # Columns
      #

      t.text :post_reference_name, null: false

      #
      # Foreign Keys
      #

      t.references :session, null: false

      #
      # Timestamps
      #

      t.timestamps null: false
    end

    #
    # Indices
    #

    # Index name 'index_metasploit_credential_origin_sessions_on_session_id_and_post_reference_name' on table
    # 'metasploit_credential_origin_sessions' is too long; the limit is 63
    add_index :metasploit_credential_origin_sessions,
              [:session_id, :post_reference_name],
              name: :unique_metasploit_credential_origin_sessions,
              unique: true
  end
end
