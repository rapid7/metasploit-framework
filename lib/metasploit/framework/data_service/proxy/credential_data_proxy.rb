module CredentialDataProxy

  def create_credential(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.create_credential(opts)
      end
    rescue => e
      self.log_error(e, "Problem creating credential")
    end
  end

  def create_cracked_credential(opts)
    begin
      self.data_service_operation do |data_service|
        opts[:workspace_id] = workspace.id
        opts[:private_data] = opts.delete(:password)
        opts[:private_type] = :password
        old_core = data_service.creds(id: opts.delete(:core_id)).first
        if old_core
          opts[:originating_core_id] = old_core.id
          opts[:origin_type] = :cracked_password
        end
        new_core = data_service.create_credential(opts)
        old_core.logins.each do |login|
          service = data_service.services(id: login.service_id).first
          data_service.create_credential_login(core: new_core, service_id: service.id, status: Metasploit::Model::Login::Status::UNTRIED)
        end
        new_core
      end
    rescue => e
      self.log_error(e, "Problem creating cracked credential")
    end
  end

  def create_credential_and_login(opts)
    begin
      self.data_service_operation do |data_service|
        core = data_service.create_credential(opts)
        opts[:core] = core
        login = data_service.create_credential_login(opts)
        core
      end
    rescue => e
      self.log_error(e, "Problem creating credential and login")
    end
  end

  def creds(opts = {})
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.creds(opts)
      end
    rescue => e
      self.log_error(e, "Problem retrieving credentials")
    end
  end

  def update_credential(opts)
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.update_credential(opts)
      end
    rescue => e
      self.log_error(e, "Problem updating credential")
    end
  end

  def delete_credentials(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.delete_credentials(opts)
      end
    rescue => e
      self.log_error(e, "Problem deleting credentials")
    end
  end
end
