RSpec.shared_examples_for 'Msf::DBManager::Migration' do

  if ENV['REMOTE_DB']
    before {skip("Migration is not tested for a remote DB")}
  end

  it { is_expected.to be_a Msf::DBManager::Migration }


  context '#add_rails_engine_migration_paths' do
    def add_rails_engine_migration_paths
      db_manager.add_rails_engine_migration_paths
    end

    it 'should not add duplicate paths to gather_engine_migration_paths' do
      paths = add_rails_engine_migration_paths

      expect(add_rails_engine_migration_paths.uniq).to eq paths
    end
  end

  context '#migrate' do
    def migrate
      db_manager.migrate
    end

    it 'should create an ActiveRecord::MigrationContext' do
      expect(ActiveRecord::MigrationContext).to receive(:new)

      migrate
    end


    it 'should return an ActiveRecord::MigrationContext with known migrations' do
      migrations_paths = [File.expand_path("../../../../../file_fixtures/migrate", __dir__)]
      expect(ActiveRecord::Migrator).to receive(:migrations_paths).and_return(migrations_paths).exactly(2).times
      result = migrate
      expect(result.size).to eq 1
      expect(result[0].name).to eq "TestDbMigration"
    end

    it 'should reset the column information' do
      expect(db_manager).to receive(:reset_column_information)

      migrate
    end

    context 'with StandardError from ActiveRecord::MigrationContext.migrate' do
      let(:standard_error) do
        StandardError.new(message)
      end

      let(:message) do
        "DB.migrate threw an exception"
      end

      before(:example) do
        mockContext = ActiveRecord::MigrationContext.new(nil, ActiveRecord::SchemaMigration)
        expect(ActiveRecord::MigrationContext).to receive(:new).and_return(mockContext)
        expect(mockContext).to receive(:needs_migration?).and_return(true)
        expect(mockContext).to receive(:migrate).and_raise(standard_error)
      end

      it 'should set Msf::DBManager#error' do
        migrate

        expect(db_manager.error).to eq standard_error
      end

      it 'should log error message at error level' do
        expect(db_manager).to receive(:elog) do |error_message, error:|
          expect(error_message).to include(standard_error.to_s)
          expect(error).to eql(standard_error)
        end

        migrate
      end
    end

    context 'with verbose' do
      def migrate
        db_manager.migrate(nil, verbose)
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

    it 'should use ApplicationRecord.descendants to find both direct and indirect subclasses' do
      expect(ApplicationRecord).to receive(:descendants).and_return([])

      reset_column_information
    end

    it 'should reset column information on each descendant of ApplicationRecord' do
      descendants = []

      1.upto(2) do |i|
        descendants << double("Descendant #{i}")
      end

      expect(ApplicationRecord).to receive(:descendants).and_return(descendants)

      descendants.each do |descendant|
        expect(descendant).to receive(:reset_column_information)
      end

      reset_column_information
    end
  end
end
