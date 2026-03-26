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
    end
  end
end
