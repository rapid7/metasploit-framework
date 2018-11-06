module Msf::Module::Auth
  def store_valid_credential(user:, private:, private_type: :password, proof: nil, service_data: {})
    if service_data.empty? && self.respond_to?("service_details")
      service_data = service_details
    end

    creation_data = {
        module_fullname: self.fullname,
        username: user,
        private_data: private,
        private_type: private_type,
        workspace_id: myworkspace_id
    }.merge(service_data)

    if service_data.empty?
      cred_data = {
        origin_type: :import,
        filename: 'msfconsole' # default as values provided on the console
      }.merge(creation_data)
      framework.db.create_credential(cred_data)
    else
      login_data = {
        proof: proof,
        last_attempted_at: DateTime.now,
        status: Metasploit::Model::Login::Status::SUCCESSFUL
      }.merge(creation_data)
      framework.db.create_credential_and_login(login_data)
    end

    nil
  end
end
