shared_examples_for 'Msf::DBManager::Activation::Once' do
  context 'CONSTANTS' do
    context 'ADAPTER' do
      subject(:adapter) do
        described_class::ADAPTER
      end

      it { should == 'postgresql' }
    end
  end

  context 'validations' do
    context '#no_adapter_activation_error' do
      before(:each) do
        db_manager.instance_variable_set :@adapter_activation_error, adapter_activation_error
      end

      context 'with #adapter_activation_error' do
        let(:adapter_activation_error) do
          Exception.new('Adapter Activation Error')
        end

        it 'should add error on :adapter' do
          db_manager.valid?

          db_manager.errors[:adapter].should include(adapter_activation_error.to_s)
        end
      end

      context 'without #adapter_activation_error' do
        let(:adapter_activation_error) do
          nil
        end

        it 'should not add error on :adapter' do
          db_manager.valid?

          db_manager.errors[:adapter].should be_empty
        end
      end
    end
  end

  context '#activated_once?' do
    subject(:activated_once?) do
      db_manager.activated_once?
    end

    let(:db_manager) do
      # build so valid? doesn't run and cause activation
      FactoryGirl.build(:msf_db_manager)
    end

    context 'default' do
      it { should be_false }
    end

    context 'after validation' do
      before(:each) do
        db_manager.valid?
      end

      it { should be_true }
    end
  end

  context '#activate_adapter_once' do
    subject(:activate_adapter_once) do
      db_manager.send(:activate_adapter_once)
    end

    context 'with error' do
      let(:error) do
        Exception.new('Adapter Activation Error')
      end

      it 'should set @adapter_activation_error' do
        ActiveRecord::Base.should_receive(:establish_connection).and_raise(error)

        expect {
          activate_adapter_once
        }.to change {
          db_manager.instance_variable_get :@adapter_activation_error
        }.to(error)
      end
    end

    context 'without error' do
      it 'should set default timezone to UTC' do
        ActiveRecord::Base.should_receive(:default_timezone=).with(:utc)

        activate_adapter_once
      end

      it 'should establish connection using only ADAPTER' do
        ActiveRecord::Base.should_receive(:establish_connection).with(
            adapter: described_class::ADAPTER
        )

        activate_adapter_once
      end

      it 'should remove the connection' do
        ActiveRecord::Base.should_receive(:establish_connection).ordered
        ActiveRecord::Base.should_receive(:remove_connection).ordered

        activate_adapter_once
      end
    end
  end

  context '#activate_once' do
    subject(:activate_once) do
      db_manager.activate_once
    end

    before(:each) do
      db_manager.instance_variable_set :@activated_once, activated_once
    end

    context 'with already ran' do
      let(:activated_once) do
        true
      end

      it 'should not need to synchronize to check if activated_once' do
        db_manager.should_not_receive(:synchronize)

        activate_once
      end
    end

    context 'without already ran' do
      let(:activated_once) do
        false
      end

      # @see http://en.wikipedia.org/wiki/TOCTOU
      it 'should checked if activated once, then synchronize and check again to prevent TOCTOU but be fast' do
        db_manager.should_receive(:activated_once?).ordered
        db_manager.should_receive(:synchronize).ordered.and_call_original
        db_manager.should_receive(:activated_once?).ordered

        activate_once
      end

      it 'should require active_record' do
        db_manager.should_receive(:require).with('active_record')
        db_manager.stub(:activate_metasploit_data_models_once)

        activate_once
      end

      it 'should activate metasploit_data_models once' do
        db_manager.should_receive(:activate_metasploit_data_models_once)

        activate_once
      end

      it 'should activate adapter once' do
        db_manager.should_receive(:activate_adapter_once)

        activate_once
      end

      it 'should set @activated_once' do
        expect {
          activate_once
        }.to change {
          db_manager.instance_variable_get :@activated_once
        }.to(true)
      end

      context 'with error' do
        let(:adapter_activation_error) do
          Exception.new('ActiveRecord::Base.establish_connection error')
        end

        before(:each) do
          ActiveRecord::Base.stub(:establish_connection).and_raise(adapter_activation_error)
        end

        it 'should set @adapter_activation_error' do
          expect {
            activate_once
          }.to change {
            db_manager.instance_variable_get :@adapter_activation_error
          }.to(adapter_activation_error)
        end
      end
    end
  end

  context '#adapter_activation_error' do
    subject(:adapter_activation_error) do
      db_manager.adapter_activation_error
    end

    it 'should call activate_once to populate @adapter_activation_error' do
      db_manager.should_receive(:activate_once)

      adapter_activation_error
    end
  end

  context '#activate_metasploit_data_models_once' do
    subject(:activate_metasploit_data_models_once) do
      db_manager.send(:activate_metasploit_data_models_once)
    end

    it 'should require metasploit_data_models' do
      db_manager.should_receive(:require).with('metasploit_data_models')

      activate_metasploit_data_models_once
    end

    context 'ActiveRecord::Migrator.migrations_paths' do
      let(:metasploit_data_models_migrations_path) do
        MetasploitDataModels.root.join('db', 'migrate').to_path
      end

      around(:each) do |example|
        migrations_paths = ActiveRecord::Migrator.send(:remove_instance_variable, :@migrations_paths)

        begin
          example.run
        ensure
          ActiveRecord::Migrator.instance_variable_set :@migrations_paths, migrations_paths
        end
      end

      context 'with includes MetasploitDataModels db/migrate' do
        before(:each) do
          ActiveRecord::Migrator.migrations_paths << metasploit_data_models_migrations_path
        end

        it 'should not change ActiveRecord::Migrator.migrations_paths' do
          expect {
            activate_metasploit_data_models_once
          }.to_not change(ActiveRecord::Migrator, :migrations_paths)
        end
      end

      context 'without includes MetasploitDataModels db/migrate' do
        it 'should add path to ActiveRecord::Migrator.migrations_paths' do
          expect {
            activate_metasploit_data_models_once
          }.to change {
            ActiveRecord::Migrator.migrations_paths.include?(metasploit_data_models_migrations_path)
          }
        end
      end
    end
  end
end