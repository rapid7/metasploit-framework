shared_context 'Msf::DBManager' do
	include_context 'database cleaner'
	include_context 'Msf::Simple::Framework'

	let(:db_manager) do
		framework.db.tap { |db_manager|
      if skip_seeding
        db_manager.stub(:seed)
      end
    }
  end

  # skipping seeding makes the tests much faster
  let(:skip_seeding) do
    true
  end

	before(:each) do
		configurations = Metasploit::Framework::Database.configurations
		spec = configurations[Metasploit::Framework.env]

		# Need to connect or ActiveRecord::Base.connection_pool will raise an
		# error.
		db_manager.connect(spec)
	end
end