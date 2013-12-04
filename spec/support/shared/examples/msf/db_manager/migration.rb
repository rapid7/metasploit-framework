shared_examples_for 'Msf::DBManager::Migration' do
  def connect
    db_manager.connect(connect_options)
  end

  let(:connect_options) do
    Metasploit::Framework::Database.configurations[Metasploit::Framework.env]
  end

  it { should be_a Msf::DBManager::Migration }

  context 'validations' do
    context '#migration_error', :without_established_connection do
      context 'with exception' do
        let(:exception) do
          StandardError.new("Migration error")
        end

        before(:each) do
          ActiveRecord::Migrator.should_receive(:migrate).and_raise(exception)

          connect
        end

        it 'should add error on :migration' do
          db_manager.valid?

          db_manager.errors[:migration].should include(exception.to_s)
        end
      end

      context 'without exception' do
        before(:each) do
          connect
        end

        it 'should not add error on :migration' do
          db_manager.valid?

          db_manager.errors[:migration].should be_empty
        end
      end
    end
  end

  context '#migrate' do
    subject(:migrate) do
      db_manager.migrate
    end

    it 'should create a connection' do
      ActiveRecord::Base.connection_pool.should_receive(:with_connection)

      migrate
    end

    it 'should call ActiveRecord::Migrator.migrate' do
      ActiveRecord::Migrator.should_receive(:migrate).with(
          ActiveRecord::Migrator.migrations_paths
      )

      migrate
    end

    it { should be_true }

    it 'should reset the column information' do
      db_manager.should_receive(:reset_column_information)

      migrate
    end

    context 'with StandardError from ActiveRecord::Migration.migrate' do
      let(:error) do
        StandardError.new(message)
      end

      let(:message) do
        "Error during migration"
      end

      before(:each) do
        ActiveRecord::Migrator.stub(:migrate).and_raise(error)
      end

      it 'should set Msf::DBManager#migration_error' do
        migrate

        db_manager.migration_error.should == error
      end

      it 'should log error message at error level' do
        db_manager.should_receive(:elog) do |error_message|
          error_message.should include(error.to_s)
        end

        migrate
      end

      it 'should log error backtrace at debug level' do
        db_manager.should_receive(:dlog) do |debug_message|
          debug_message.should include('Call stack')
        end

        migrate
      end

      it { should be_false }
    end

    context 'with :verbose' do
      def migrate
        db_manager.migrate(verbose: verbose)
      end

      context 'false' do
        let(:verbose) do
          false
        end

        it 'should set ActiveRecord::Migration.verbose to false' do
          ActiveRecord::Migration.should_receive(:verbose=).with(verbose)

          migrate
        end
      end

      context 'true' do
        let(:verbose) do
          true
        end

        it 'should set ActiveRecord::Migration.verbose to true' do
          ActiveRecord::Migration.should_receive(:verbose=).with(verbose)

          migrate
        end
      end
    end

    context 'without verbose' do
      it 'should set ActiveRecord::Migration.verbose to false' do
        ActiveRecord::Migration.should_receive(:verbose=).with(false)

        db_manager.migrate
      end
    end
  end

  context '#migrated?' do
    subject(:migrated?) do
      db_manager.migrated?
    end

    context 'default' do
      it { should be_false }
    end

    context 'after connect', :without_established_connection do
      before(:each) do
        connect
      end

      it { should be_true }
    end
  end

  context '#reset_column_information' do
    def reset_column_information
      db_manager.send(:reset_column_information)
    end

    it 'should use ActiveRecord::Base.descendants to find both direct and indirect subclasses' do
      ActiveRecord::Base.should_receive(:descendants).and_return([])

      reset_column_information
    end

    it 'should reset column information on each descendant of ActiveRecord::Base' do
      descendants = []

      1.upto(2) do |i|
        descendants << double("Descendant #{i}")
      end

      ActiveRecord::Base.stub(:descendants => descendants)

      descendants.each do |descendant|
        descendant.should_receive(:reset_column_information)
      end

      reset_column_information
    end
  end
end