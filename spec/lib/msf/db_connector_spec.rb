RSpec.describe Msf::DbConnector do
  let(:file_fixtures_path) { File.join(Msf::Config.install_root, 'spec', 'file_fixtures') }
  let(:empty_config_file) { File.join(file_fixtures_path, 'config_files', 'empty.ini') }
  let(:default_remote_db_config_file) { File.join(file_fixtures_path, 'config_files', 'default_remote_db.ini') }
  let(:config_file) { empty_config_file }
  let(:db) do
    instance_double(
      Msf::DBManager,
      connection_established?: false,
      driver: 'driver',
      active: true
    )
  end
  let(:framework) do
    instance_double(
      ::Msf::Framework,
      version: 'VERSION',
      db: db
    )
  end
  before :each do
    allow_any_instance_of(::Msf::Config).to receive(:config_file).and_return(config_file)
  end

  it { is_expected.to respond_to :db_connect_postgresql }

  describe '#load_db_config' do
    context 'when the config file does not exist' do
      let(:config_file) { File.join(file_fixtures_path, 'config_files', 'non_existent_file.ini') }

      it 'returns nil' do
        expect(subject.load_db_config('local-https-data-service')).to eql(nil)
      end
    end

    context 'when there is no db config present' do
      let(:config_file) { empty_config_file }

      it 'returns nil' do
        expect(subject.load_db_config('local-https-data-service')).to eql(nil)
      end
    end

    context 'when there is a default database registered' do
      let(:config_file) { default_remote_db_config_file }

      it 'returns the cb config' do
        expected_config = {
          url: 'https://localhost:5443',
          cert: '/Users/user/.msf4/msf-ws-cert.pem',
          skip_verify: 'true',
          api_token: 'b1cd123e2f160a8a1fbf79baed180b8dc480de5b994f53eee42e57771e3f65e13bec737e4a4acbb2'
        }
        expect(subject.load_db_config('local-https-data-service')).to eql(expected_config)
      end
    end
  end

  describe '#db_connect_from_config' do
    let(:db_connect_response) { { result: 'mock result message', data_service_name: 'local-https-data-service' } }
    before :each do
      allow(subject).to receive(:db_connect).and_return(db_connect_response)
    end

    context 'when the config file does not exist' do
      let(:config_file) { File.join(file_fixtures_path, 'config_files', 'non_existent_file.ini') }

      it 'returns an empty object' do
        expect(subject.db_connect_from_config(framework)).to eql({})
      end
    end

    context 'when there is no db config present' do
      let(:config_file) { empty_config_file }

      it 'returns an empty object' do
        expect(subject.db_connect_from_config(framework)).to eql({})
      end
    end

    context 'when there is a default database registered' do
      let(:config_file) { default_remote_db_config_file }

      it 'returns the db_connect_response' do
        expected_config = {
          url: 'https://localhost:5443',
          cert: '/Users/user/.msf4/msf-ws-cert.pem',
          skip_verify: 'true',
          api_token: 'b1cd123e2f160a8a1fbf79baed180b8dc480de5b994f53eee42e57771e3f65e13bec737e4a4acbb2'
        }
        expect(subject.db_connect_from_config(framework)).to eql(db_connect_response)
        expect(subject).to have_received(:db_connect).with(framework, expected_config)
      end
    end
  end

  describe '#data_service_search' do
    context 'when the name is not present' do
      let(:config_file) { empty_config_file }

      it 'returns nil' do
        expect(subject.data_service_search(name: 'local-https-data-service')).to eql nil
      end
    end

    context 'when the name is present' do
      let(:config_file) { default_remote_db_config_file }

      it 'returns the name' do
        expect(subject.data_service_search(name: 'local-https-data-service')).to eql 'local-https-data-service'
      end
    end

    context 'when the url is not present' do
      let(:config_file) { empty_config_file }

      it 'returns nil' do
        expect(subject.data_service_search(url: 'https://localhost:5443')).to eql nil
      end
    end

    context 'when the url is present' do
      let(:config_file) { default_remote_db_config_file }

      it 'returns the name' do
        expect(subject.data_service_search(url: 'https://localhost:5443')).to eql 'local-https-data-service'
      end
    end
  end
end
