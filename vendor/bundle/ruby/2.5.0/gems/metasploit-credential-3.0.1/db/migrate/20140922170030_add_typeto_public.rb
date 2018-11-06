class AddTypetoPublic < ActiveRecord::Migration
  def change
    change_table :metasploit_credential_publics do |t|
      #
      # Single Table Inheritance
      #

      t.string :type, null: true
      execute "UPDATE metasploit_credential_publics SET type = 'Metasploit::Credential::Username'"

      change_column :metasploit_credential_publics, :type, :string, null: false

    end
  end

end
