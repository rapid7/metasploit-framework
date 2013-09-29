require 'spec_helper'

describe Msf::Auxiliary::Report do
  include_context 'database cleaner'

  include_context 'Metasploit::Framework::Thread::Manager cleaner' do
    let(:thread_manager) do
      # don't create thread manager if example didn't create it
      framework.instance_variable_get :@threads
    end
  end

  subject(:auxiliary_metasploit_instance) do
    auxiliary_metasploit_class.new(framework: framework)
  end

  let(:auxiliary_metasploit_class) do
    described_class = self.described_class

    Class.new(Msf::Auxiliary) do
      include described_class
    end
  end

  let(:framework) do
    FactoryGirl.create(:msf_framework)
  end

  let(:task) do
    with_established_connection {
      FactoryGirl.create(:mdm_task)
    }
  end

  let(:workspace) do
    with_established_connection {
      FactoryGirl.create(:mdm_workspace)
    }
  end

  it_should_behave_like 'Msf::Auxiliary::Report::Workspace'

  context 'getters' do
    it_should_behave_like 'Msf::Auxiliary::Report.get', :client
    it_should_behave_like 'Msf::Auxiliary::Report.get', :host
  end

  context 'reporters' do
    it_should_behave_like 'Msf::Auxiliary::Report.report', :auth_info
    it_should_behave_like 'Msf::Auxiliary::Report.report', :client
    it_should_behave_like 'Msf::Auxiliary::Report.report', :exploit
    it_should_behave_like 'Msf::Auxiliary::Report.report', :host
    it_should_behave_like 'Msf::Auxiliary::Report.report', :loot
    it_should_behave_like 'Msf::Auxiliary::Report.report', :note
    it_should_behave_like 'Msf::Auxiliary::Report.report', :service
    it_should_behave_like 'Msf::Auxiliary::Report.report', :vuln
    it_should_behave_like 'Msf::Auxiliary::Report.report', :web_form
    it_should_behave_like 'Msf::Auxiliary::Report.report', :web_page
    it_should_behave_like 'Msf::Auxiliary::Report.report', :web_site
    it_should_behave_like 'Msf::Auxiliary::Report.report', :web_vuln
  end

  context '#mytask' do
    subject(:mytask) do
      auxiliary_metasploit_instance.mytask
    end

    context 'with [:task]' do
      let(:module_store_task) do
        # XXX I'm not sure what type is supposed to actually be used in the module_store.
        double('Msf::Module#module_store', record: task)
      end

      before(:each) do
        auxiliary_metasploit_instance[:task] = module_store_task
      end

      it 'should be [:task].record' do
        mytask.should == task
      end
    end

    context 'without [:task]' do
      context 'with @task' do
        before(:each) do
          auxiliary_metasploit_instance.instance_variable_set :@task, instance_task
        end

        context 'with Mdm::Task' do
          let(:instance_task) do
            task
          end

          it 'should be @task' do
            mytask.should == task
          end
        end

        context 'without Mdm::Task' do
          let(:instance_task) do
            double('Not an Mdm::Task')
          end

          it { should be_nil }
        end
      end

      context 'without @task' do
        it { should be_nil }
      end
    end
  end

  context '#store_cred' do
    it 'should work'
  end

  context '#store_local' do
    it 'should work'
  end

  context '#store_loot' do
    it 'should work'
  end
end