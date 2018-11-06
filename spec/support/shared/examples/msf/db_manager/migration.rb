RSpec.shared_examples_for 'Msf::DBManager::Migration' do

  if ENV['REMOTE_DB']
    before {skip("Migration is not tested for a remoted DB")}
  end

  it { is_expected.to be_a Msf::DBManager::Migration }


  context '#add_rails_engine_migration_paths' do
    def add_rails_engine_migration_paths
      db_manager.add_rails_engine_migration_paths
    end

    it 'should not add duplicate paths to ActiveRecord::Migrator.migrations_paths' do
      add_rails_engine_migration_paths

      expect {
        add_rails_engine_migration_paths
      }.to_not change {
        ActiveRecord::Migrator.migrations_paths.length
      }

      expect(ActiveRecord::Migrator.migrations_paths.uniq).to eq ActiveRecord::Migrator.migrations_paths
    end
  end

  context '#migrate' do
    def migrate
      db_manager.migrate
    end

    it 'should call ActiveRecord::Migrator.migrate' do
      expect(ActiveRecord::Migrator).to receive(:migrate).with(
          ActiveRecord::Migrator.migrations_paths
      )

      migrate
    end

    it 'should return migrations that were ran from ActiveRecord::Migrator.migrate' do
      migrations = [double('Migration 1')]
      expect(ActiveRecord::Migrator).to receive(:migrate).and_return(migrations)

      expect(migrate).to eq migrations
    end

    it 'should reset the column information' do
      expect(db_manager).to receive(:reset_column_information)

      migrate
    end

    context 'with StandardError from ActiveRecord::Migration.migrate' do
      let(:error) do
        StandardError.new(message)
      end

      let(:message) do
        "Error during migration"
      end

      before(:example) do
        expect(ActiveRecord::Migrator).to receive(:migrate).and_raise(error)
      end

      it 'should set Msf::DBManager#error' do
        migrate

        expect(db_manager.error).to eq error
      end

      it 'should log error message at error level' do
        expect(db_manager).to receive(:elog) do |error_message|
          expect(error_message).to include(error.to_s)
        end

        migrate
      end

      it 'should log error backtrace at debug level' do
        expect(db_manager).to receive(:dlog) do |debug_message|
          expect(debug_message).to include('Call stack')
        end

        migrate
      end
    end

    context 'with verbose' do
      def migrate
        db_manager.migrate(verbose)
      end

      context 'false' do
        let(:verbose) do
          false
        end

        it 'should set ActiveRecord::Migration.verbose to false' do
          expect(ActiveRecord::Migration).to receive(:verbose=).with(verbose)

          migrate
        end
      end

      context 'true' do
        let(:verbose) do
          true
        end

        it 'should set ActiveRecord::Migration.verbose to true' do
          expect(ActiveRecord::Migration).to receive(:verbose=).with(verbose)

          migrate
        end
      end
    end

    context 'without verbose' do
      it 'should set ActiveRecord::Migration.verbose to false' do
        expect(ActiveRecord::Migration).to receive(:verbose=).with(false)

        db_manager.migrate
      end
    end
  end

  context '#migrated' do
    it { is_expected.to respond_to :migrated }
    it { is_expected.to respond_to :migrated= }
  end

  context '#reset_column_information' do
    def reset_column_information
      db_manager.send(:reset_column_information)
    end

    it 'should use ActiveRecord::Base.descendants to find both direct and indirect subclasses' do
      expect(ActiveRecord::Base).to receive(:descendants).and_return([])

      reset_column_information
    end

    it 'should reset column information on each descendant of ActiveRecord::Base' do
      descendants = []

      1.upto(2) do |i|
        descendants << double("Descendant #{i}")
      end

      expect(ActiveRecord::Base).to receive(:descendants).and_return(descendants)

      descendants.each do |descendant|
        expect(descendant).to receive(:reset_column_information)
      end

      reset_column_information
    end
  end
end
