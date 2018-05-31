module Msf::DBManager::Login
  def logins(opts)
    ::ActiveRecord::Base.connection_pool.with_connection {
      Metasploit::Credential::Login.where(opts)
    }
  end
end
