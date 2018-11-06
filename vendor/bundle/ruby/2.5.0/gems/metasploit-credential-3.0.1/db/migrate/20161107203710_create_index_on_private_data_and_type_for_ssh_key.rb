class CreateIndexOnPrivateDataAndTypeForSshKey < ActiveRecord::Migration
  def up
    sql =<<ENDL
CREATE UNIQUE INDEX "index_metasploit_credential_privates_on_type_and_data_sshkey" ON
"metasploit_credential_privates" ("type", decode(md5(data), 'hex'))
WHERE type in ('Metasploit::Credential::SSHKey')
ENDL
    execute(sql)
  end
  def down
    execute("DROP INDEX index_metasploit_credential_privates_on_type_and_data_sshkey")
  end
end
