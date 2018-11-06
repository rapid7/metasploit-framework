class AddJtrFormatToMetasploitCredentialPrivates < ActiveRecord::Migration
  def change
    add_column :metasploit_credential_privates, :jtr_format, :string
  end
end
