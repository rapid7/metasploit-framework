require 'spec_helper'

describe Metasploit::Framework::Thread::Manager do
  subject(:manager) do
    FactoryGirl.create(:metasploit_framework_thread_manager)
  end

  let(:framework) do
    manager.framework
  end

  context 'factories' do
    context 'metasploit_framework_thread_manager' do
      subject(:metasploit_framework_thread_manager) do
        FactoryGirl.build(:metasploit_framework_thread_manager)
      end

      it { should be_valid }

      it 'should not create any Threads' do
        expect {
          metasploit_framework_thread_manager
        }.to_not change {
          Thread.list.count
        }
      end
    end
  end

  context 'validations' do
    it { should validate_presence_of :framework }
  end

  context '#framework' do
    subject(:framework) do
      manager.framework
    end

    it 'should be synchronized' do
      manager.should_receive(:synchronize)

      framework
    end

    it 'should retrieve @framework' do
      expected_framework = double('Msf::Simple::Framework')
      manager.instance_variable_set :@framework, expected_framework

      framework.should == expected_framework
    end
  end

  context '#framework=' do
    it 'should be synchronized' do
      manager.should_receive(:synchronize)

      manager.framework = nil
    end

    it 'should set @framework' do
      framework = double('Msf::Simple::Framework')
      manager.framework = framework

      manager.instance_variable_get(:@framework).should == framework
    end
  end

  context '#list' do
    subject(:list) do
      manager.list
    end

    it 'should delegate to #thread_group' do
      manager.send(:thread_group).should_receive(:list)

      list
    end
  end

  context 'valid!' do
    subject(:valid!) do
      manager.valid!
    end

    it 'should be synchronized' do
      manager.should_receive(:synchronize)

      valid!
    end

    it 'should call super' do
      manager.framework = nil

      expect {
        valid!
      }.to raise_error(Metasploit::Model::Invalid)
    end
  end

  context '#register' do
    subject(:register) do
      manager.register(attributes, &block_block)
    end

    let(:attributes) do
      {
          critical: critical,
          name: name
      }
    end

    let(:block_block) do
      ->(*args) { args }
    end

    let(:critical) do
      false
    end

    let(:name) do
      FactoryGirl.generate :metasploit_framework_thread_name
    end

    let(:options_block) do
      ->(*args) { args }
    end

    context 'with already registered' do
      it 'should raise Metasploit::Framework::Thread::Manager::AlreadyRegistered' do
        thread = manager.spawn(name, critical) {
          manager.register(
              name: name,
              critical: critical,
              &block_block
          )
        }

        expect {
          thread.join
        }.to raise_error(Metasploit::Framework::Thread::Manager::AlreadyRegistered) do |error|
          error.metasploit_framework_thread.should == thread[:metasploit_framework_thread]
        end
      end
    end

    context 'without already registered' do
      context 'with valid attributes' do
        it 'should pass attributes and &block to Metasploit::Framework::Thread.new' do
          Metasploit::Framework::Thread.should_receive(:new).with(
              hash_including(attributes),
              &block_block
          ).and_call_original

          # need to be in a different thread so that Thread.current[:metasploit_framework_thread] is not set for the
          # main thread.
          Thread.new {
            register
          }.join
        end

        it 'should set :metasploit_framework_thread thread local variable' do
          # have to register inside a child thread so we can inspect it from the outside
          thread = Thread.new {
            manager.register(attributes) {
              Thread.current[:metasploit_framework_thread]
            }
          }
          metasploit_framework_thread = thread.value

          metasploit_framework_thread.should be_a Metasploit::Framework::Thread
        end

        it 'should set Thread.current.group to #thread_group' do
          thread = Thread.new {
            manager.register(attributes) {
              Thread.current.group
            }
          }
          register_thread_group = thread.value

          register_thread_group.should == manager.send(:thread_group)
        end

        context 'Metasploit::Framework::Thread#run' do
          context 'with exception' do
            let(:exception) do
              Exception.new(exception_message)
            end

            let(:exception_message) do
              'Exception Message'
            end

            it 'should log and raise exception' do
              thread = Thread.new {
                manager.register(attributes) {
                  metasploit_framework_thread = Thread.current[:metasploit_framework_thread]

                  metasploit_framework_thread.should_receive(:log_and_raise).with(exception).and_call_original

                  raise exception
                }
              }

              expect {
                thread.join
              }.to raise_error(exception)
            end

            it 'should clear :metasploit_framework_thread' do
              thread = Thread.new {
                begin
                  manager.register(attributes) {
                    raise exception
                  }
                rescue Exception
                  thread[:metasploit_framework_thread].should be_nil
                end
              }

              thread.join
            end

            it 'should restore previous Thread.current.group' do
              thread = Thread.new {
                before_thread_group = Thread.current.group

                begin
                  manager.register(attributes) {
                    raise exception
                  }
                rescue Exception
                  after_thread_group = Thread.current.group
                end

                before_thread_group == after_thread_group
              }
              thread.value.should be_true
            end
          end

          context 'without exception' do
            it 'should return yieldreturn' do
              thread = Thread.new {
                yieldreturn = double("Yielded")

                manager.register(attributes) {
                  yieldreturn
                }.should == yieldreturn
              }

              thread.join
            end

            it 'should clear :metasploit_framework_thread' do
              thread = Thread.new {
                manager.register(attributes, &block_block)
              }
              thread.join
              thread[:metasploit_framework_thread].should be_nil
            end

            it 'should restore previous Thread.current.group' do
              thread = Thread.new {
                before_thread_group = Thread.current.group

                manager.register(attributes, &block_block)

                after_thread_group = Thread.current.group

                before_thread_group == after_thread_group
              }
              thread.value.should be_true
            end
          end
        end
      end

      context 'without valid attributes' do
        let(:attributes) do
          {}
        end

        it 'should raise Metasploit::Model::Invalid' do
          expect {
            register
          }.to raise_error(Metasploit::Model::Invalid)
        end
      end
    end
  end

  context '#registered?' do
    subject(:registered?) do
      manager.registered?
    end

    let(:critical) do
      false
    end

    let(:name) do
      FactoryGirl.generate :metasploit_framework_thread_name
    end

    context 'with spawned thread' do
      it 'should be true' do
        thread = manager.spawn(name, critical) {
          manager.registered?
        }
        thread.value.should be_true
      end
    end

    context 'with registered thread' do
      let(:attributes) do
        {
            critical: critical,
            name: name
        }
      end

      context 'in block' do
        it 'should be true' do
          thread = Thread.new {
            manager.register(attributes) {
              manager.should be_registered
            }
          }

          thread.join
        end
      end

      context 'outside block' do
        it 'should be false' do
          thread = Thread.new {
            manager.register(attributes) {}

            manager.should_not be_registered
          }
        end
      end
    end

    context 'without managed thread' do
      it { should be_false }
    end
  end

  context '#spawn' do
    subject(:spawn) do
      manager.spawn(name, critical, *block_arguments, &block_block)
    end

    let(:block_arguments) do
      []
    end

    let(:block_block) do
      ->(*args) { args }
    end

    let(:critical) do
      false
    end

    let(:name) do
      FactoryGirl.generate :metasploit_framework_thread_name
    end

    it 'should #register thread' do
      manager.should_receive(:register).with(
          hash_including(
              block: block_block,
              block_arguments: block_arguments,
              critical: critical,
              name: name,
              spawned_at: an_instance_of(Time)
          )
      )

      thread = spawn
      thread.join
    end

    context '&block' do
      context 'with exception' do
      end

      context 'without exception' do
        it 'should return yieldreturn' do
          yieldreturn = double('Yield Return')

          thread = manager.spawn(name, critical) {
            yieldreturn
          }
          thread.value.should == yieldreturn
        end

        context 'with connected' do
          include_context 'database cleaner'

          before(:each) do
            framework.db.stub(connected?: true)
          end

          it 'should release connection' do
            with_established_connection do
              ActiveRecord::Base.connection_pool.should_receive(:release_connection).at_least(:once).and_call_original

              thread = spawn
              thread.join
            end
          end
        end

        context 'without connected' do
          before(:each) do
            framework.db.stub(connected?: false)
          end

          it 'should not release connection' do
            ActiveRecord::Base.should_not_receive(:connection_pool)

            thread = spawn
            thread.join
          end
        end
      end
    end
  end

  context '#thread_group' do
    subject(:thread_group) do
      manager.send(:thread_group)
    end

    it 'should be synchronized' do
      manager.should_receive(:synchronize)

      thread_group
    end

    context 'with @thread_group' do
      let(:expected_thread_group) do
        double('ThreadGroup')
      end

      before(:each) do
        manager.instance_variable_set :@thread_group, expected_thread_group
      end

      it 'should return current value' do
        thread_group.should == expected_thread_group
      end
    end

    context 'without @thread_group' do
      it 'should create a new ThreadGroup' do
        ThreadGroup.should_receive(:new)

        thread_group
      end
    end
  end
end