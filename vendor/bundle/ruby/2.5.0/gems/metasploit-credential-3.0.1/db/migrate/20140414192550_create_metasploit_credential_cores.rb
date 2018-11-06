class CreateMetasploitCredentialCores < ActiveRecord::Migration
  def change
    create_table :metasploit_credential_cores do |t|
      #
      # Foreign keys
      #

      t.references :origin,
                   null: false,
                   polymorphic: true
      t.references :private,
                   null: true
      t.references :public,
                   null: true
      t.references :realm,
                   null: true
      t.references :workspace,
                   null: false

      #
      # Timestamps
      #

      t.timestamps null: false
    end

    change_table :metasploit_credential_cores do |t|
      #
      # Foreign Key Indices
      #

      t.index [:origin_type, :origin_id]
      t.index :private_id
      t.index :public_id
      t.index :realm_id
      t.index :workspace_id
    end
  end
end
