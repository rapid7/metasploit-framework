shared_examples_for 'Msf::DBManager::Connection' do
  context 'CONSTANTS' do
    context 'POOL' do
      subject(:pool) do
        described_class::POOL
      end

      it { should == 75 }
    end

    context 'WAIT_TIMEOUT' do
      subject(:wait_timeout) do
        described_class::WAIT_TIMEOUT
      end

      it { should == 5.minutes }
    end
  end

  context 'validations' do
    context '#no_database_creation_error' do
      subject(:no_database_creation_error) do
        db_manager.no_database_creation_error
      end

      before(:each) do
        db_manager.stub(database_creation_error: database_creation_error)
      end

      context 'with error' do
        let(:database_creation_error) do
          Exception.new('Creation Error')
        end

        it 'should add error on :creation' do
          db_manager.valid?

          db_manager.errors[:creation].should include(database_creation_error.to_s)
        end
      end

      context 'without error' do
        let(:database_creation_error) do
          nil
        end

        it 'should not add error on :creation' do
          db_manager.valid?

          db_manager.errors[:creation].should be_empty
        end
      end
    end
  end

  context '#connect' do
    subject(:connect) do
      db_manager.connect(options)
    end

    let(:options) do
      Metasploit::Framework::Database.configurations[Metasploit::Framework.env]
    end

    after(:each) do
      ActiveRecord::Base.remove_connection
    end

    it 'should be synchronized' do
      db_manager.should_receive(:synchronize)

      connect
    end

    it 'should return #connected?' do
      connected = double('Connected')
      db_manager.stub(connected?: connected)

      connect.should == connected
    end

    context 'connected' do
      context 'with false' do
        let(:valid) do
          false
        end

        before(:each) do
          db_manager.stub(valid?: valid)
        end

        it 'should not be connected' do
          db_manager.should_not be_connected
        end

        context 'with valid' do
          let(:normalized_options) do
            Metasploit::Framework::Database.configurations[Metasploit::Framework.env]
          end

          let(:valid) do
            true
          end

          it 'should normalize options' do
            db_manager.should_receive(:normalize_connect_options).with(options).and_call_original

            connect
          end

          it 'should pass normalized options to #create_database' do
            db_manager.stub(normalize_connect_options: normalized_options)
            db_manager.should_receive(:create_database).with(normalized_options)

            connect
          end

          context 'database creation' do
            before(:each) do
              db_manager.stub(create_database: database_created)
            end

            context 'with false' do
              let(:database_created) do
                false
              end

              it 'should not try to establish connection' do
                ActiveRecord::Base.should_not_receive(:establish_connetion)

                connect
              end
            end

            context 'with true' do
              let(:database_created) do
                true
              end

              it 'should establish connection with normalized options' do
                db_manager.stub(normalize_connect_options: normalized_options)

                ActiveRecord::Base.should_receive(:establish_connection).with(normalized_options).and_call_original

                connect
              end

              context 'migrate' do
                before(:each) do
                  db_manager.stub(migrate: migrated)
                  db_manager.instance_variable_set :@migrated, migrated
                end

                context 'with false' do
                  let(:migrated) do
                    false
                  end

                  it 'should not set #workspace' do
                    db_manager.should_not_receive(:default_workspace)

                    connect
                  end
                end

                context 'with true' do
                  let(:migrated) do
                    true
                  end

                  it 'should set #workspace' do
                    expect {
                      connect
                    }.to change {
                      # can't use db_manager.workspace because it needs a connetion, so it'll only work after connect.
                      db_manager.instance_variable_get :@workspace_name
                    }
                  end

                  it 'should be connected afterward' do
                    expect {
                      connect
                    }.to change(db_manager, :connected?).to(true)
                  end
                end
              end
            end
          end
        end

        context 'without valid' do
          let(:valid) do
            false
          end

          it 'should not create database' do
            db_manager.should_not_receive(:create_database)

            connect
          end

          it 'should not migrate' do
            db_manager.should_not_receive(:migrate)

            connect
          end
        end
      end

      context 'with true' do
        before(:each) do
          spec = Metasploit::Framework::Database.configurations[Metasploit::Framework.env]

          db_manager.connect(spec)
        end

        it 'should already be connected' do
          db_manager.should be_connected
        end

        it 'should not validate' do
          db_manager.should_not_receive(:valid?)

          connect
        end

        it 'should not create database' do
          db_manager.should_not_receive(:create_database)

          connect
        end

        it 'should not migrate' do
          db_manager.should_not_receive(:migrate)

          connect
        end
      end
    end
  end

  context '#connection' do
    subject(:connection) do
      db_manager.connection(options)
    end

    let(:options) do
      {}
    end

    context 'connected' do
      context 'with false' do
        context 'with :without' do
          let(:options) do
            {
                without: without_lambda
            }
          end

          let(:without_lambda) do
            ->{
              without_value
            }
          end

          let(:without_value) do
            'Without Value'
          end

          it 'should not call ActiveRecord::Base.connection_pool' do
            ActiveRecord::Base.should_not_receive(:connection_pool)

            connection
          end

          it 'should return value from :without' do
            connection.should == without_value
          end
        end

        context 'without :without' do
          it { should be_nil }
        end
      end

      context 'with true' do
        before(:each) do
          spec = Metasploit::Framework::Database.configurations[Metasploit::Framework.env]

          db_manager.connect(spec)
        end

        after(:each) do
          ActiveRecord::Base.remove_connection
        end

        context 'with :with' do
          let(:options) do
            {
                with: with_lambda
            }
          end

          let(:with_lambda) do
            ->{
              with_value
            }
          end

          let(:with_value) do
            'With Value'
          end

          it 'should call ActiveRecord::Base.connection_pool.with_connection' do
            ActiveRecord::Base.connection_pool.should_receive(:with_connection)

            connection
          end

          it 'should return value from :with' do
            connection.should == with_value
          end
        end

        context 'without :with' do
          it { should be_nil }
        end
      end
    end
  end

  context '#connected?' do
    subject(:connected?) do
      db_manager.connected?
    end

    context 'ActiveRecord::Base.connected?' do
      after(:each) do
        ActiveRecord::Base.remove_connection
      end

      context 'with true' do
        before(:each) do
          ActiveRecord::Base.configurations = Metasploit::Framework::Database.configurations
          spec = ActiveRecord::Base.configurations[Metasploit::Framework.env]

          db_manager.connect(spec)
        end

        it 'should be ActiveRecord::Base.connected?' do
          ActiveRecord::Base.should be_connected
        end

        context 'ActiveRecord::Base.connection_pool.connected?' do
          context 'with true' do
            it 'should be ActiveRecord::Base.connection_pool.connected?' do
              ActiveRecord::Base.connection_pool.should be_connected
            end

            context '#migrated?' do
              before(:each) do
                db_manager.stub(migrated?: migrated)
              end

              context 'with true' do
                let(:migrated) do
                  true
                end

                it { should be_true }
              end

              context 'with false' do
                let(:migrated) do
                  false
                end

                it { should be_false }
              end
            end
          end

          context 'with false' do
            before(:each) do
              ActiveRecord::Base.connection_pool.disconnect!
            end

            it 'should not be ActiveRecord::Base.connection_pool.connected?' do
              ActiveRecord::Base.connection_pool.should_not be_connected
            end

            it { should be_false }
          end
        end
      end

      context 'with false' do
        it 'should not be ActiveRecord::Base.connected?' do
          ActiveRecord::Base.should_not be_connected
        end

        it { should be_false }
      end
    end
  end

  context '#create_database' do
    subject(:create_database) do
      db_manager.send(:create_database, options)
    end

    let(:options) do
      Metasploit::Framework::Database.configurations[Metasploit::Framework.env]
    end

    context 'ActiveRecord::Base.establish_connection' do
      context 'with error' do
        let(:error) do
          double('ActiveRecord::Base.establish_connection error')
        end

        before(:each) do
          ActiveRecord::Base.should_receive(:establish_connection).once.and_raise(error)
        end

        it_should_behave_like 'Msf::DBManager::Connection#create_database creating database'
      end

      context 'without error' do
        before(:each) do
          ActiveRecord::Base.should_receive(:establish_connection).with(options).and_call_original
        end

        context 'ActiveRecord::Base.connection_pool.checkout' do
          context 'with error' do
            let(:error) do
              double('ActiveRecord::Base.establish_connection error')
            end

            before(:each) do
              ActiveRecord::Base.stub_chain(:connection_pool, :checkout).and_raise(error)
            end

            it_should_behave_like 'Msf::DBManager::Connection#create_database creating database'
          end

          context 'without error' do
            it { should be_true }
          end
        end
      end
    end
  end

  context '#disconnect' do
    subject(:disconnect) do
      db_manager.disconnect
    end

    after(:each) do
      ActiveRecord::Base.remove_connection
    end

    context 'with connected' do
      before(:each) do
        ActiveRecord::Base.configurations = Metasploit::Framework::Database.configurations
        spec = ActiveRecord::Base.configurations[Metasploit::Framework.env]

        db_manager.connect(spec)
      end

      it 'should change #connected?' do
        expect {
          disconnect
        }.to change(db_manager, :connected?).to(false)
      end
    end

    context 'without connected' do
      it 'should not change #connected?' do
        expect {
          disconnect
        }.to_not change(db_manager, :connected?)
      end
    end

    context 'with exception' do
      let(:exception) do
        Exception.new('ActiveRecord::Base#remove_connection error')
      end

      it 'should log exception instead of raising it' do
        ActiveRecord::Base.should_receive(:remove_connection).once.and_raise(exception)
        # for the after(:each)
        ActiveRecord::Base.should_receive(:remove_connection).once.and_call_original

        db_manager.should_receive(:elog)

        expect {
          disconnect
        }.to_not raise_error
      end
    end
  end

  context '#normalize_connect_options' do
    subject(:normalize_connect_options) do
      db_manager.send(:normalize_connect_options, options)
    end

    let(:options) do
      {}
    end

    context "['pool']" do
      context 'with value' do
        let(:converted_pool) do
          rand(100)
        end

        let(:formatted_pool) do
          converted_pool.to_s
        end

        let(:options) do
          {
              'pool' => formatted_pool
          }
        end

        it 'should convert to integer' do
          normalize_connect_options['pool'].should == converted_pool
        end
      end

      context 'without value' do
        it 'should default to POOL' do
          normalize_connect_options['pool'].should == described_class::POOL
        end
      end
    end

    context "['port']" do
      context 'with value' do
        let(:options) do
          {
              'port' => port
          }
        end

        let(:converted_port) do
          rand(2 ** 16 - 1)
        end

        let(:port) do
          formatted_port
        end

        let(:formatted_port) do
          converted_port.to_s
        end

        it 'should convert to integer' do
          normalize_connect_options['port'].should == converted_port
        end
      end

      context 'without value' do
        it { should_not include('port') }
      end
    end

    context "['wait_timeout']" do
      context 'with value' do
        let(:converted_wait_timeout) do
          rand(15.minutes)
        end

        let(:formatted_wait_timeout) do
          converted_wait_timeout.to_s
        end

        let(:options) do
          {
              'wait_timeout' => formatted_wait_timeout
          }
        end

        it 'should convert to integer' do
          normalize_connect_options['wait_timeout'].should == converted_wait_timeout
        end
      end

      context 'without value' do
        it 'should default to WAIT_TIMEOUT' do
          normalize_connect_options['wait_timeout'].should == described_class::WAIT_TIMEOUT
        end
      end
    end

    context 'unnormalized options' do
      let(:adapter) do
        double('Adapter')
      end

      let(:database) do
        double('Database')
      end

      let(:host) do
        double('Host')
      end

      let(:options) do
        {
            'adapter' => adapter,
            'database' => database,
            'host' => host,
            'password' => password,
            'username' => username
        }
      end

      let(:password) do
        double('Password')
      end

      let(:username) do
        double('Username')
      end

      it 'should pass through adapter' do
        normalize_connect_options['adapter'].should == adapter
      end

      it 'should pass through database' do
        normalize_connect_options['database'].should == database
      end

      it 'should pass through host' do
        normalize_connect_options['host'].should == host
      end

      it 'should pass through password' do
        normalize_connect_options['password'].should == password
      end

      it 'should pass through username' do
        normalize_connect_options['username'].should == username
      end
    end
  end

  context '#with_connection' do
    subject(:with_connection) do
      db_manager.with_connection(&block)
    end

    let(:block) do
      ->{}
    end

    it 'should pass &block to connection :with' do
      db_manager.should_receive(:connection).with(with: block)

      with_connection
    end
  end
end