shared_context 'Msf::DBManager' do
  include_context 'DatabaseCleaner'
  include_context 'Msf::Simple::Framework'

  let(:active) do
    true
  end

  let(:db_manager) do
    framework.db
  end

  before(:each) do
    configurations = Metasploit::Framework::Database.configurations
    spec = configurations[Metasploit::Framework.env]

    # Need to connect or ActiveRecord::Base.connection_pool will raise an
    # error.
    db_manager.connect(spec)

    db_manager.stub(:active => active)
  end
end