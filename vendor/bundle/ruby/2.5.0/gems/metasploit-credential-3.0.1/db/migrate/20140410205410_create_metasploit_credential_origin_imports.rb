class CreateMetasploitCredentialOriginImports < ActiveRecord::Migration
  def change
    create_table :metasploit_credential_origin_imports do |t|
      #
      # Columns
      #

      t.text :filename, null: false

      #
      # Foreign Keys
      #

      t.references :task

      #
      # Timestamps
      #

      t.timestamps null: false
    end

    #
    # Foreign Key Indices
    #

    add_index :metasploit_credential_origin_imports, :task_id
  end
end
