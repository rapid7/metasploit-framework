# Implements a one-time migration of `Mdm::Cred` objects to
# appropriate objects from {Metasploit::Credential}
# This second run is due to the refactor of #report_auth_info
# that means we should no longer be creating old creds anywhere.
class OldCredsToNewCreds2 < ActiveRecord::Migration
  def up
    Metasploit::Credential::Migrator.new.migrate!
  end
end
