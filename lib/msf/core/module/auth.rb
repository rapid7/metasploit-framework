module Msf::Module::Auth
  def store_valid_credential(user, private, private_type, proof = nil)
    service_data = {}
    if self.respond_to? ("service_details")
      service_data = service_details
    end

    cdata = {
        module_fullname: self.fullname,
        origin_type: :service,
        username: user,
        private_data: private,
        private_type: private_type,
        workspace_id: myworkspace_id
    }.merge(service_data)

    if service_data.empty?
      cdata[:origin_type] = :import
      cdata[:filename] ='msfconsole' # default as values provided on the console
    end


    core = create_credential(cdata)
    unless service_data.empty?
      login_data = {
        core: core,
        proof: proof
        # last_attempted_at: DateTime.now,
        # status: Metasploit::Model::Login::Status::SUCCESSFUL
      }.merge(service_data)
      create_credential_login(login_data)
    end

    nil
  end
end