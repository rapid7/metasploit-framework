shared_examples_for 'Msf::DBManager::Seeding' do
  context '#seed' do
    include_context 'database cleaner'

    #
    # methods
    #

    def seed
      db_manager.seed
    end

    #
    # callbacks
    #

    around(:each) do |example|
      with_established_connection do
        example.run
      end
    end

    it_should_behave_like 'MetasploitDataModels db/seeds.rb'
  end
end
