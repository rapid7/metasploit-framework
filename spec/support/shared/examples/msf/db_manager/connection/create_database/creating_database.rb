shared_examples_for 'Msf::DBManager::Connection#create_database creating database' do
  let(:database) do
    options.fetch('database')
  end

  it 'should log info that database is being created' do
    db_manager.should_receive(:ilog).with(/#{Regexp.escape(database)}/)

    create_database
  end

  it 'should establish connection to public postgres database' do
    ActiveRecord::Base.should_receive(:establish_connection).with(
        hash_including(
            'database' => 'postgres',
            'schema_search_path' => 'public'
        )
    )

    create_database
  end

  context 'ActiveRecord::Base.create_database' do
    before(:each) do
      ActiveRecord::Base.should_receive(:establish_connection).with(
          hash_including(
              'database' => 'postgres',
              'schema_search_path' => 'public'
          )
      )
    end

    context "with ['encoding']" do
      before(:each) do
        options['encoding'] = option_encoding
      end

      let(:option_encoding) do
        'option_encoding'
      end

      it "should create database with ['encoding'] encoding" do
        ActiveRecord::Base.should_receive(:create_database).with(
            database,
            hash_including(
                'encoding' => option_encoding
            )
        )
        ActiveRecord::Base.should_receive(:establish_connection)

        create_database
      end
    end

    context "without ['encoding']" do
      before(:each) do
        options.delete('encoding')
      end

      context "with CHARSET environment variable" do
        let(:charset) do
          'CHARSET'
        end

        around(:each) do |example|
          charset_before = ENV.delete('CHARSET')
          ENV['CHARSET'] = charset

          begin
            example.run
          ensure
            ENV['CHARSET'] = charset_before
          end
        end

        it 'should create database with CHARSET encoding' do
          ActiveRecord::Base.should_receive(:create_database).with(
              database,
              hash_including(
                  'encoding' => charset
              )
          )
          ActiveRecord::Base.should_receive(:establish_connection)

          create_database
        end
      end

      context "without CHARSET environment variable" do
        it 'should create database with default utf8 encoding' do
          ActiveRecord::Base.should_receive(:create_database).with(
              database,
              hash_including(
                  'encoding' => 'utf8'
              )
          )
          ActiveRecord::Base.should_receive(:establish_connection)

          create_database
        end
      end
    end
  end

  it 'should establish connection to created database to verify creation' do
    ActiveRecord::Base.should_receive(:establish_connection).ordered
    ActiveRecord::Base.should_receive(:create_database).ordered
    ActiveRecord::Base.should_receive(:establish_connection).ordered

    create_database
  end

  context 'with exception' do
    let(:exception) do
      Exception.new('ActiveRecord::Base.create_database error')
    end

    before(:each) do
      ActiveRecord::Base.should_receive(:establish_connection).with(
          hash_including(
              'database' => 'postgres',
              'schema_search_path' => 'public'
          )
      )

      ActiveRecord::Base.stub(:create_database).and_raise(exception)
    end

    it 'should set database_creation_error' do
      expect {
        create_database
      }.to change(db_manager, :database_creation_error).to(exception)
    end

    it 'should log error' do
      db_manager.should_receive(:elog)

      create_database
    end

    it { should be_false }
  end

  context 'without exception' do
    before(:each) do
      ActiveRecord::Base.should_receive(:establish_connection).with(
          hash_including(
              'database' => 'postgres',
              'schema_search_path' => 'public'
          )
      )
      ActiveRecord::Base.should_receive(:create_database)
      ActiveRecord::Base.should_receive(:establish_connection).with(options)
    end

    it { should be_true }
  end

  it 'should remove connection used to create database' do
    # once in #create_database and once in after(:each)
    ActiveRecord::Base.should_receive(:remove_connection).at_least(:once).and_call_original

    create_database
  end
end