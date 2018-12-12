module LoginDataProxy
  def logins(opts = {})
    begin
      self.data_service_operation do |data_service|
        data_service.logins(opts)
      end
    rescue => e
      self.log_error(e, "Problem retrieving logins")
    end
  end

  def create_credential_login(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.create_credential_login(opts)
      end
    rescue => e
      self.log_error(e, "Problem creating login")
    end
  end

  def update_login(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.update_login(opts)
      end
    rescue => e
      self.log_error(e, "Problem updating login")
    end
  end

  def invalidate_login(opts)
    begin
      add_opts_workspace(opts)
      # Search for an existing Metasploit::Credential::Core object. It requires specific attributes.
      core_opts = {}
      core_opts[:workspace] = opts[:workspace]
      # The creds search uses regex for username and password lookup.
      # Alter the search string to only look for exact matches to avoid updating unexpected entries.
      core_opts[:user] = "^#{opts.fetch(:username)}$" if opts[:username]
      core_opts[:pass] = "^#{opts.fetch(:private_data)}$" if opts[:private_data]
      core_opts[:ports] = [ opts.fetch(:port) ] if opts[:port]
      core_opts[:host_ranges] = [ opts.fetch(:address) ] if opts[:address]
      core_opts[:svcs] = [ opts.fetch(:service_name) ] if opts[:service_name]

      core = creds(core_opts).first
      if core
        core.logins.each do |login|
          login_opts = opts.slice(:access_level, :status, :last_attempted_at)
          login_opts[:id] = login.id
          update_login(login_opts)
        end
      end
    rescue => e
      self.log_error(e, "Problem invalidating login")
    end
  end
end