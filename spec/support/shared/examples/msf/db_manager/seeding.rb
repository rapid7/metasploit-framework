shared_examples_for 'Msf::DBManager::Seeding' do
  context '#seed' do
    #
    # methods
    #

    def seed
      db_manager.seed
    end

    #
    # callbacks
    #

    before(:all) do
      # Remove seeds
      Mdm::Architecture.delete_all
      Mdm::Authority.delete_all
      Mdm::Module::Rank.delete_all
      Mdm::Platform.delete_all
    end

    after(:all) do
      # Restore seeds
      load MetasploitDataModels.root.join('db', 'seeds.rb').to_path
    end

    it_should_behave_like 'MetasploitDataModels db/seeds.rb'
  end
end
