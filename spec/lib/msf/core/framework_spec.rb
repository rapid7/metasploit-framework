require 'spec_helper'

describe Msf::Framework do
  include_context 'Metasploit::Framework::Thread::Manager cleaner' do
    let(:thread_manager) do
      # don't create thread manager if example didn't create it
      framework.instance_variable_get :@threads
    end
  end

  subject(:framework) do
    FactoryGirl.create(:msf_framework)
  end

  it_should_behave_like 'Msf::Framework::Modules'

  it { should be_a MonitorMixin }

  context 'factories' do
    context 'msf_framework' do
      subject(:msf_framework) do
        FactoryGirl.build(:msf_framework)
      end

      it { should be_valid }

      context '#module_types' do
        subject(:module_types) do
          msf_framework.module_types
        end

        it 'should have all module types' do
          expect(module_types).to match_array(Metasploit::Model::Module::Type::ALL)
        end
      end
    end
  end

  context '#database_disabled' do
    subject(:database_disabled) do
      framework.database_disabled
    end

    it 'should default to false' do
      database_disabled.should be_false
    end

    it 'should be memoized' do
      memoized = double('#database_disabled')
      framework.instance_variable_set :@database_disabled, memoized

      database_disabled.should == memoized
    end
  end

  context '#database_disabled?' do
    subject(:database_disabled?) do
      framework.database_disabled?
    end

    it 'should alias database_disabled' do
      database_disabled = double('#database_disabled')
      framework.database_disabled = database_disabled

      database_disabled?.should == framework.database_disabled
    end
  end

  context '#datastore' do
    subject(:datastore) do
      framework.datastore
    end

    it 'should use lazy initialization' do
      Msf::DataStore.should_not_receive(:new)

      framework
    end

    it 'should be synchronized' do
      framework.should_receive(:synchronize)

      datastore
    end

    it 'should be memoized' do
      memoized = double('Msf::Datastore')
      framework.instance_variable_set :@datastore, memoized

      datastore.should == memoized
    end

    it { should be_a Msf::DataStore }
  end

  context '#db' do
    subject(:db) do
      framework.db
    end

    it 'should use lazy initialization' do
      Msf::DBManager.should_not_receive(:new)

      framework
    end

    it 'should be synchronized' do
      framework.should_receive(:synchronize)

      db
    end

    it 'should be memoized' do
      memoized = double('Msf::Datastore')
      framework.instance_variable_set :@db, memoized

      db.should == memoized
    end

    it 'should pass framework to Msf::DBManager.new' do
      Msf::DBManager.should_receive(:new).with(
          hash_including(
              framework: framework
          )
      )

      db
    end

    it { should be_a Msf::DBManager }
  end

  context '#events' do
    subject(:events) do
      framework.events
    end

    it 'should be initialized in #initialize to allow event subscriptions #initialize' do
      Msf::EventDispatcher.should_receive(:new).and_call_original

      framework
    end

    it 'should be synchronized' do
      framework.should_receive(:synchronize)

      events
    end

    it 'should be memoized' do
      memoized = double('Msf::Datastore')
      framework.instance_variable_set :@events, memoized

      events.should == memoized
    end

    it 'should pass framework to Msf::EventDispatcher.new' do
      # can't use with(framework) as it will trigger call before should_receive is setup
      Msf::EventDispatcher.should_receive(:new).with(
          an_instance_of(Msf::Framework)
      ).and_call_original

      framework
    end

    it { should be_a Msf::EventDispatcher }
  end

  context '#initialize' do
    subject(:framework) do
      described_class.new
    end

    # TODO https://www.pivotaltracker.com/story/show/57432206
    it 'should set Rex::ThreadFactory.provider to #threads' do
      framework

      Rex::ThreadFactory.class_variable_get(:@@provider).should == framework.threads
    end

    context 'events' do
      it 'should create an Msf::FrameworkEventSubscriber' do
        Msf::FrameworkEventSubscriber.should_receive(:new).with(
            an_instance_of(Msf::Framework)
        ).and_call_original

        framework
      end

      it 'should add exploit subscriber' do
        Msf::EventDispatcher.any_instance.should_receive(:add_exploit_subscriber)

        framework
      end

      it 'should add session subscriber' do
        Msf::EventDispatcher.any_instance.should_receive(:add_session_subscriber)

        framework
      end

      it 'should add general subscriber' do
        Msf::EventDispatcher.any_instance.should_receive(:add_general_subscriber)

        framework
      end

      it 'should add db subscriber' do
        Msf::EventDispatcher.any_instance.should_receive(:add_db_subscriber)

        framework
      end

      it 'should add ui subscriber' do
        Msf::EventDispatcher.any_instance.should_receive(:add_ui_subscriber)

        framework
      end
    end
  end

  context '#jobs' do
    subject(:jobs) do
      framework.jobs
    end

    it 'should use lazy initialization' do
      Rex::JobContainer.should_not_receive(:new)

      framework
    end

    it 'should be synchronized' do
      framework.should_receive(:synchronize)

      jobs
    end

    it 'should be memoized' do
      memoized = double('Rex::JobContainer')
      framework.instance_variable_set :@jobs, memoized

      jobs.should == memoized
    end

    it 'should pass framework to Rex::JobContainer.new' do
      Rex::JobContainer.should_receive(:new)

      jobs
    end

    it { should be_a Rex::JobContainer }
  end

  context '#plugins' do
    subject(:plugins) do
      framework.plugins
    end

    it 'should use lazy initialization' do
      Msf::PluginManager.should_not_receive(:new)

      framework
    end

    it 'should be synchronized' do
      framework.should_receive(:synchronize)

      plugins
    end

    it 'should be memoized' do
      memoized = double('Msf::PluginManager')
      framework.instance_variable_set :@plugins, memoized

      plugins.should == memoized
    end

    it 'should pass framework to Msf::PluginManager.new' do
      Msf::PluginManager.should_receive(:new).with(framework)

      plugins
    end

    it { should be_a Msf::PluginManager }
  end

  context '#sessions' do
    subject(:sessions) do
      framework.sessions
    end

    it 'should use lazy initialization' do
      Msf::SessionManager.should_not_receive(:new)

      framework
    end

    it 'should be synchronized' do
      framework.should_receive(:synchronize)

      sessions
    end

    it 'should be memoized' do
      memoized = double('Msf::SessionManager')
      framework.instance_variable_set :@sessions, memoized

      sessions.should == memoized
    end

    it 'should pass framework to Msf::SessionManager.new' do
      sessions.framework.should == framework
    end

    it { should be_a Msf::SessionManager }
  end

  context '#threads' do
    subject(:threads) do
      framework.threads
    end

    # TODO https://www.pivotaltracker.com/story/show/57432206
    it 'should be initialized in #initialize when Rex::ThreadFactory.provider is set' do
      Metasploit::Framework::Thread::Manager.should_receive(:new)

      framework
    end

    it 'should be synchronized' do
      framework.should_receive(:synchronize)

      threads
    end

    it 'should be memoized' do
      memoized = double('Metasploit::Framework::Thread::Manager')
      framework.instance_variable_set :@threads, memoized

      begin
        threads.should == memoized
      ensure
        # make sure @threads is nil so Metasploit::Framework::Thread::Manager cleaner doesn't try to call #list on
        # memoized.
        framework.instance_variable_set :@threads, nil
      end
    end

    it 'should pass framework to Metasploit::Framework::Thread::Manager.new' do
      Metasploit::Framework::Thread::Manager.should_receive(:new).with(
          hash_including(
              framework: framework
          )
      ).and_call_original

      framework
    end

    it { should be_a Metasploit::Framework::Thread::Manager }
  end
end