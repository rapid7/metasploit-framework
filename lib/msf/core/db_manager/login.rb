module Msf::DBManager::Login
  def logins(opts)
    ::ActiveRecord::Base.connection_pool.with_connection {
      Metasploit::Credential::Login.where(opts)
    }
  end

  def update_login(opts)
    ::ActiveRecord::Base.connection_pool.with_connection {
      wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework, false)
      opts = opts.clone()
      opts[:workspace] = wspace if wspace
      id = opts.delete(:id)
      login = Metasploit::Credential::Login.find(id)
      login.update!(opts)
      return login
    }
  end

  def delete_logins(opts)
    raise ArgumentError.new("The following options are required: :ids") if opts[:ids].nil?

    ::ActiveRecord::Base.connection_pool.with_connection {
      deleted = []
      opts[:ids].each do |login_id|
        login = Metasploit::Credential::Login.find(login_id)
        begin
          deleted << login.destroy
        rescue # refs suck
          elog("Forcibly deleting #{login}")
          deleted << login.delete
        end
      end

      return deleted
    }
  end
end
