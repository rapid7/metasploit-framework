# Implements a one-time migration of `Mdm::Cred` objects to
# appropriate objects from {Metasploit::Credential}
class OldCredsToNewCreds < ActiveRecord::Migration
  def up
    Metasploit::Credential::Migrator.new.migrate!
  end
end
