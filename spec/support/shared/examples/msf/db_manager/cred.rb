RSpec.shared_examples_for 'Msf::DBManager::Cred' do

  unless ENV['REMOTE_DB']
    it { is_expected.to respond_to :each_cred }
    it { is_expected.to respond_to :find_or_create_cred }
    it { is_expected.to respond_to :report_auth }
    it { is_expected.to respond_to :report_auth_info }
    it { is_expected.to respond_to :report_cred }
  end

  it { is_expected.to respond_to :creds }
  it { is_expected.to respond_to :create_credential }
  it { is_expected.to respond_to :update_credential }
  it { is_expected.to respond_to :delete_credentials }

  unless ENV['REMOTE_DB']
    describe '#create_credential_service' do
      let(:workspace) { subject.default_workspace }
      let(:host_addr) { '192.0.2.1' }
      let(:base_opts) do
        {
          address: host_addr,
          port: 80,
          service_name: 'http',
          protocol: 'tcp',
          workspace_id: workspace.id
        }
      end

      context 'when :info is provided' do
        it 'persists the info string on the created service' do
          service = subject.create_credential_service(base_opts.merge(info: 'Apache httpd 2.4'))
          expect(service).to be_persisted
          expect(service.info).to eq('Apache httpd 2.4')
        end
      end

      context 'when :info is nil' do
        it 'normalizes info to an empty string' do
          service = subject.create_credential_service(base_opts.merge(info: nil))
          expect(service).to be_persisted
          expect(service.info).to eq('')
        end
      end
      
      context 'when :info is not provided' do
        it 'creates the service without raising an error' do
          service = subject.create_credential_service(base_opts)
          expect(service).to be_persisted
          expect(service.port).to eq(80)
          expect(service.proto).to eq('tcp')
        end
      end

      context 'when the service already exists' do
        before do
          subject.create_credential_service(base_opts)
        end

        it 'updates the info on the existing service when :info is provided' do
          service = subject.create_credential_service(base_opts.merge(info: 'updated banner'))
          expect(service.info).to eq('updated banner')
          expect(Mdm::Service.joins(:host).where(hosts: { address: host_addr }, port: 80).count).to eq(1)
        end

        it 'does not alter info when :info is absent' do
          subject.create_credential_service(base_opts.merge(info: 'original banner'))
          service = subject.create_credential_service(base_opts)
          expect(service.info).to eq('original banner')
        end
      end

      context 'when :service_name has mixed case' do
        it 'lowercases the service name to match report_service behavior' do
          service = subject.create_credential_service(base_opts.merge(service_name: 'HTTP'))
          expect(service.name).to eq('http')
        end
      end
    end

    describe '#create_credential_core' do
      let(:workspace) { subject.default_workspace }
      let(:host_addr) { '192.0.2.1' }
      let(:module_fullname) { 'auxiliary/test/module' }

      it 'creates a Login when origin is a service origin' do
        core = subject.create_credential(
          address: host_addr,
          port: 22,
          service_name: 'ssh',
          protocol: 'tcp',
          workspace_id: workspace.id,
          origin_type: :service,
          module_fullname: module_fullname,
          username: 'admin'
        )
        expect(core).to be_persisted
        expect(core.logins.count).to eq(1)
        expect(core.logins.first.status).to eq(Metasploit::Model::Login::Status::UNTRIED)
      end

      it 'creates separate Logins when the same credential is found on different services' do
        core1 = subject.create_credential(
          address: host_addr,
          port: 22,
          service_name: 'ssh',
          protocol: 'tcp',
          workspace_id: workspace.id,
          origin_type: :service,
          module_fullname: module_fullname,
          username: 'admin'
        )

        core2 = subject.create_credential(
          address: '192.0.2.2',
          port: 80,
          service_name: 'http',
          protocol: 'tcp',
          workspace_id: workspace.id,
          origin_type: :service,
          module_fullname: module_fullname,
          username: 'admin'
        )

        expect(core1.id).to eq(core2.id)
        expect(core1.logins.reload.count).to eq(2)
      end
    end

    describe '#update_credential' do
      let(:workspace) { subject.default_workspace }
      let(:other_workspace) { Mdm::Workspace.where(name: 'other-workspace').first_or_create! }
      let(:host_addr) { '192.0.2.1' }

      let(:core) do
        subject.create_credential(
          address: host_addr,
          port: 22,
          service_name: 'ssh',
          protocol: 'tcp',
          workspace_id: workspace.id,
          origin_type: :import,
          filename: '/tmp/creds.txt',
          username: 'admin',
          private_data: 'password1',
          private_type: :password
        )
      end

      it 'ignores a raw workspace_id passed in opts' do
        subject.update_credential(id: core.id, workspace_id: other_workspace.id)
        expect(core.reload.workspace_id).to eq(workspace.id)
      end

      it 'ignores a raw origin_id/origin_type passed in opts' do
        other_origin = Metasploit::Credential::Origin::Import.create!(filename: '/tmp/other.txt')
        original_origin_id = core.origin_id

        subject.update_credential(
          id: core.id,
          origin_id: other_origin.id,
          origin_type: 'Metasploit::Credential::Origin::Import'
        )

        expect(core.reload.origin_id).to eq(original_origin_id)
      end

      it 'ignores a raw public_id passed in opts' do
        other_public = Metasploit::Credential::Username.where(username: 'someone-else').first_or_create!
        original_public_id = core.public_id

        subject.update_credential(id: core.id, public_id: other_public.id)

        expect(core.reload.public_id).to eq(original_public_id)
      end

      it 'moves the credential to another workspace when given via the :workspace option' do
        subject.update_credential(id: core.id, workspace: other_workspace.name)
        expect(core.reload.workspace_id).to eq(other_workspace.id)
      end

      it 'updates the private data when given via the :private option' do
        subject.update_credential(id: core.id, private: { id: core.private_id, data: 'newpassword' })
        expect(core.reload.private.data).to eq('newpassword')
      end
    end
  end
end
