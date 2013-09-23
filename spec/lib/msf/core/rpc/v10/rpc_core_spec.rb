require 'spec_helper'

require 'msf/core/rpc/v10/rpc_core'

describe Msf::RPC::RPC_Core do
  include_context 'Metasploit::Framework::Thread::Manager cleaner' do
    let(:thread_manager) do
      # don't initialize threads if the example hasn't
      framework.instance_variable_get :@threads
    end
  end

  subject(:rpc_core) do
    described_class.new(service)
  end

  let(:framework) do
    FactoryGirl.create(:msf_simple_framework)
  end

  let(:service) do
    # Don't want to use a full Msf::RPC::Service since it will include more than just RPC_Core and it doesn't use lazy
    # initialization.
    double(
        'Msf::RPC::Service',
        framework: framework,
        tokens: tokens,
        users: users
    )
  end

  let(:tokens) do
    []
  end

  let(:users) do
    []
  end

  context 'CONSTANTS' do
    context 'FORMATTED_STATUS_BY_THREAD_STATUS' do
      subject(:formatted_status_by_thread_status) do
        described_class::FORMATTED_STATUS_BY_THREAD_STATUS
      end

      its([false]) { 'terminated normally' }
      its([nil]) { 'terminated with exception' }
    end
  end

  context '#rpc_thread_kill' do
    subject(:rpc_thread_kill) do
      rpc_core.rpc_thread_kill(name)
    end

    let(:name) do
      FactoryGirl.generate :metasploit_framework_thread_name
    end

    let(:success) do
      {
          'result' => 'success'
      }
    end

    context 'with named Thread' do
      let(:critical) do
        false
      end

      let(:thread) do
        framework.threads.spawn(name, critical) {
          # stop the spawned thread so it's not dead, and unlisted by the time example tries to kill the thread.
          Thread.stop
        }
      end

      before(:each) do
        # wait for thread to run and stop itself, so it will appear in framework.threads.list
        until thread.status == 'sleep'
          Thread.pass
        end
      end

      it 'should kill named Thread' do
        framework.threads.list.should have(1).items

        rpc_thread_kill

        # use a timeout to protect from test failure
        Timeout::timeout(5.seconds) {
          # wait for thread to wake up and notice it was killed.
          until thread.status != 'sleep'
            Thread.pass
          end
        }
      end

      it { should == success }
    end

    context 'without named Thread' do
      it 'should not kill any Threads' do
        expect {
          rpc_thread_kill
        }.to_not change {
          framework.threads.list.count
        }
      end

      it { should == success }
    end
  end

  context '#rpc_thread_list' do
    subject(:rpc_thread_list) do
      rpc_core.rpc_thread_list
    end

    context 'with spawned thread' do
      subject(:thread_entry) do
        rpc_thread_list.first
      end

      let(:critical) do
        false
      end

      let(:metasploit_framework_thread) do
        thread[:metasploit_framework_thread]
      end

      let(:name) do
        FactoryGirl.generate :metasploit_framework_thread_name
      end

      let(:thread) do
        framework.threads.spawn(name, critical) {
          # stop the spawned thread so it's not dead, and unlisted by the time example tries to kill the thread.
          Thread.stop
        }
      end

      before(:each) do
        # wait for thread to run and stop itself, so it will appear in framework.threads.list
        until thread.status == 'sleep'
          Thread.pass
        end
      end

      it 'include Metasploit::Framework::Thread#as_json' do
        # since the before(:each) waits for the thread to stop itself, it's safe to assume the thread local variable is
        # set here.
        json = metasploit_framework_thread.as_json

        json.each do |key, value|
          thread_entry[key].should == value
        end
      end

      it 'should include :status' do
        thread_entry[:status].should == 'sleep'
      end
    end

    context 'Thread' do
      subject(:thread_entry) do
        rpc_thread_list.first
      end

      let(:list) do
        [
            thread
        ]
      end

      let(:metasploit_framework_thread) do
        FactoryGirl.create(:metasploit_framework_thread)
      end

      let(:thread) do
        # its difficult to have a Thread die between the call to ThreadGroup.list and Thread#status, so emulate Thread
        # and Thread#status since this is mostly formatting code anyway.
        thread = double('Thread')
        thread.stub(:[]).with(:metasploit_framework_thread).and_return(metasploit_framework_thread)
        thread.stub(status: status)

        thread
      end

      before(:each) do
        thread_manager = double('Metasploit::Framework::Thread::Manager', list: list)
        framework.stub(threads: thread_manager)
      end

      context '#status' do
        context 'with aborting' do
          let(:status) do
            'aborting'
          end

          its([:status]) { should == status }
        end

        context 'with false' do
          let(:status) do
            false
          end

          its([:status]) { should == 'terminated normally' }
        end

        context 'with nil' do
          let(:status) do
            nil
          end

          its([:status]) { should == 'terminated with exception' }
        end

        context 'with run' do
          let(:status) do
            'run'
          end

          its([:status]) { should == status }
        end

        context 'with sleep' do
          let(:status) do
            'sleep'
          end

          its([:status]) { should == 'sleep' }
        end
      end
    end
  end
end