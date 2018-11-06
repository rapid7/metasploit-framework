class UniqueMetasploitCredentialCoresWithRealmId < ActiveRecord::Migration
  #
  # CONSTANTS
  #

  FIELDS = %w{realm_id public_id private_id}

  #
  # Instance Methods
  #

  def down
    # Drop UniqueMetasploitCredentialCoresWithRealmId migration
    %w{private public realmless publicless privateless complete}.each do |name|
      execute "DROP INDEX #{unique_index_name(name)}"
    end


    # Restore UniqueMetasploitCredentialCores migration

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

  # Table in scope-order
  #
  # | workspace_id | realm_id | public_id | private_id | index                                          |
  # | ------------ | -------- | --------- | ---------- | ---------------------------------------------- |
  # | 1            | 0        | 0         | 0          | -                                              |
  # | 1            | 0        | 0         | 1          | unique_private_metasploit_credential_cores     |
  # | 1            | 0        | 1         | 0          | unique_public_metasploit_credential_cores      |
  # | 1            | 0        | 1         | 1          | unique_realmless_metasploit_credential_cores   |
  # | 1            | 1        | 0         | 0          | -                                              |
  # | 1            | 1        | 0         | 1          | unique_publicless_metasploit_credential_cores  |
  # | 1            | 1        | 1         | 0          | unique_privateless_metasploit_credential_cores |
  # | 1            | 1        | 1         | 1          | unique_complete_metasploit_credential_cores    |
  def up
    #
    # Drop UniqueMetasploitCredentialCores migrations
    #

    execute 'DROP INDEX unique_complete_metasploit_credential_cores'
    execute 'DROP INDEX unique_private_metasploit_credential_cores'
    execute 'DROP INDEX unique_public_metasploit_credential_cores'

    #
    # Replace with unique indices that include realm_id
    #

    create_unique_index('private', %w{private_id})
    create_unique_index('public', %w{public_id})
    create_unique_index('realmless', %w{public_id private_id})
    create_unique_index('publicless', %w{realm_id private_id})
    create_unique_index('privateless', %w{realm_id public_id})
    create_unique_index('complete', %w{realm_id public_id private_id})
  end

  private

  def create_unique_index(name, non_null_fields)
    unless Set.new(non_null_fields).subset?(Set.new(FIELDS))
      raise ArgumentError, "#{non_null_fields} is not a subset of #{FIELDS}"
    end

    where_clauses = FIELDS.map { |where_field|
      modifier = ''

      if non_null_fields.include? where_field
        modifier = 'NOT '
      end

      "#{where_field} IS #{modifier}NULL"
    }
    where_clause = where_clauses.join(' AND ')

    execute "CREATE UNIQUE INDEX #{unique_index_name(name)} " \
            "ON metasploit_credential_cores (workspace_id, #{non_null_fields.join(', ')}) " \
            "WHERE #{where_clause}"
  end

  def unique_index_name(name)
    "unique_#{name}_metasploit_credential_cores"
  end
end
