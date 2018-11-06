class UniqueMetasploitCredentialCores < ActiveRecord::Migration
  def down
    execute 'DROP INDEX unique_complete_metasploit_credential_cores'
    execute 'DROP INDEX unique_private_metasploit_credential_cores'
    execute 'DROP INDEX unique_public_metasploit_credential_cores'
  end

  def up
    execute 'CREATE UNIQUE INDEX unique_complete_metasploit_credential_cores ' \
            'ON metasploit_credential_cores (workspace_id, private_id, public_id) ' \
            'WHERE private_id IS NOT NULL AND ' \
                  'public_id IS NOT NULL'

    execute 'CREATE UNIQUE INDEX unique_private_metasploit_credential_cores ' \
            'ON metasploit_credential_cores (workspace_id, private_id) ' \
            'WHERE private_id IS NOT NULL AND ' \
                  'public_id IS NULL'

    execute 'CREATE UNIQUE INDEX unique_public_metasploit_credential_cores ' \
            'ON metasploit_credential_cores (workspace_id, public_id) ' \
            'WHERE private_id IS NULL AND ' \
                  'public_id IS NOT NULL'
  end
end
