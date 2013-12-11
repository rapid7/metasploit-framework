require 'spec_helper'

describe Msf::Auxiliary::AuthBrute do
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

  context '#build_credentials_array' do
    subject(:build_credentials_array) do
      auxiliary_metasploit_instance.build_credentials_array
    end

    context 'with connection' do
      include_context 'database cleaner'

      #
      # lets
      #

      let(:db_all_creds) do
        false
      end

      let(:db_all_pass) do
        false
      end

      let(:db_all_users) do
        false
      end

      let(:workspace) do
        workspace_service.host.workspace
      end

      #
      # let!s
      #

      let!(:other_workspace_service) do
        FactoryGirl.create(:mdm_service)
      end

      let!(:other_workspace_other_creds) do
        FactoryGirl.create_list(
            :full_mdm_cred,
            2,
            service: other_workspace_service,
            ptype: 'ssh'
        )
      end

      let!(:other_workspace_password_creds) do
        FactoryGirl.create_list(
            :full_mdm_cred,
            2,
            service: other_workspace_service,
            ptype: 'password'
        )
      end

      let!(:workspace_service) do
        FactoryGirl.create(:mdm_service)
      end

      let!(:workspace_other_creds) do
        FactoryGirl.create_list(
            :full_mdm_cred,
            2,
            service: workspace_service,
            ptype: 'ssh'
        )
      end

      let!(:workspace_password_creds) do
        FactoryGirl.create_list(
            :full_mdm_cred,
            2,
            service: workspace_service,
            ptype: 'password'
        )
      end

      before(:each) do
        # make sure that with_connection/connection is not stubbed so that connection's logic is still tested.
        framework.db.stub(connected?: true)

        auxiliary_metasploit_instance.datastore['DB_ALL_CREDS'] = db_all_creds
        auxiliary_metasploit_instance.datastore['DB_ALL_PASS'] = db_all_pass
        auxiliary_metasploit_instance.datastore['DB_ALL_USERS'] = db_all_users
        auxiliary_metasploit_instance.datastore['WORKSPACE'] = workspace.name
      end

      context 'datastore' do
        context 'DB_ALL_CREDS' do
          before(:each) do
          end

          context 'with true' do
            let(:db_all_creds) do
              true
            end

            it 'should include credentials from #myworkspace' do
              workspace_password_creds.each do |cred|
                build_credentials_array.should include([cred.user, cred.pass])
              end
            end

            it 'should only include password credentials' do
              workspace_other_creds.each do |cred|
                build_credentials_array.should_not include([cred.user, cred.pass])
              end
            end

            it 'should not include credentials from other workspaces' do
              other_workspace_other_creds.each do |cred|
                build_credentials_array.should_not include([cred.user, cred.pass])
              end

              other_workspace_password_creds.each do |cred|
                build_credentials_array.should_not include([cred.user, cred.pass])
              end
            end
          end

          context 'with false' do
            let(:db_all_creds) do
              false
            end

            it { should be_empty }
          end
        end

        context 'with DB_ALL_USERS' do
          let(:db_all_users) do
            true
          end

          it 'should include all users from credentials from #myworkspace' do
            workspace_other_creds.each do |cred|
              build_credentials_array.should include([cred.user, ''])
            end

            workspace_password_creds.each do |cred|
              build_credentials_array.should include([cred.user, ''])
            end
          end

          it 'should not include users from credentials from other workspaces' do
            other_workspace_other_creds.each do |cred|
              build_credentials_array.should_not include([cred.user, ''])
            end

            other_workspace_password_creds.each do |cred|
              build_credentials_array.should_not include([cred.user, ''])
            end
          end
        end

        context 'without DB_ALL_USERS' do
          let(:db_all_users) do
            false
          end

          it { should be_empty }
        end

        context 'with DB_ALL_PASS' do
          let(:db_all_pass) do
            true
          end

          it 'should include all passwords from password credentials from #myworkspace' do
            workspace_password_creds.each do |cred|
              build_credentials_array.should include(['', cred.pass])
            end
          end

          it 'should not include non-password credentials from #myworkspace' do
            workspace_other_creds.each do |cred|
              build_credentials_array.should_not include(['', cred.pass])
            end
          end

          it 'should not include credentials from other workspaces' do
            other_workspace_other_creds.each do |cred|
              build_credentials_array.should_not include(['', cred.pass])
            end

            other_workspace_password_creds.each do |cred|
              build_credentials_array.should_not include(['', cred.pass])
            end
          end
        end

        context 'without DB_ALL_PASS' do
          let(:db_all_pass) do
            false
          end

          it { should be_empty }
        end
      end
    end
  end
end