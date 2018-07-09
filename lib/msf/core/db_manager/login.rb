module Msf::DBManager::Login
  def logins(opts)
    ::ActiveRecord::Base.connection_pool.with_connection {
      Metasploit::Credential::Login.where(opts)
    }
  end

  def update_login(opts)
    ::ActiveRecord::Base.connection_pool.with_connection {
      wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework, false)
      opts[:workspace] = wspace if wspace
      id = opts.delete(:id)
      Metasploit::Credential::Login.update(id, opts)
    }
  end
end
