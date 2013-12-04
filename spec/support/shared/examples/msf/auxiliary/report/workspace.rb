shared_examples_for 'Msf::Auxiliary::Report::Workspace' do
  context '#inside_workspace_boundary?' do
    subject(:inside_workspace_boundary?) do
      auxiliary_metasploit_instance.inside_workspace_boundary?(ip)
    end

    let(:ip) do
      double('IP')
    end

    context 'connected' do
      before(:each) do
        auxiliary_metasploit_instance.stub(myworkspace: workspace)

        framework.db.stub(connected?: connected)
      end

      context 'with true' do
        let(:connected) do
          true
        end

        it 'should delegate to Mdm::Workspace#allow_actions_on?' do
          allowed = double('Allowed')
          workspace.should_receive(:allow_actions_on?).with(ip).and_return(allowed)

          inside_workspace_boundary?.should == allowed
        end
      end

      context 'with false' do
        let(:connected) do
          false
        end

        it { should be_true }
      end
    end
  end

  context '#myworkspace' do
    subject(:myworkspace) do
      auxiliary_metasploit_instance.myworkspace
    end

    it 'should be memoized' do
      memoized = double('Mdm::Workspace')
      auxiliary_metasploit_instance.instance_variable_set :@myworkspace, memoized

      myworkspace.should == memoized
    end

    context 'connected' do
      before(:each) do
        framework.db.stub(connected?: connected)
      end

      context 'with false' do
        let(:connected) do
          false
        end

        it { should be_nil }
      end

      context 'with true' do
        let(:connected) do
          true
        end

        context '#workspace' do
          before(:each) do
            auxiliary_metasploit_instance.datastore['WORKSPACE'] = workspace_name
          end

          context 'with nil' do
            let(:workspace_name) do
              nil
            end

            it { should be_nil }
          end

          context 'with Mdm::Workspace#name' do
            let(:workspace) do
              FactoryGirl.create(:mdm_workspace)
            end

            let(:workspace_name) do
              workspace.name
            end

            it 'should be Mdm::Workspace' do
              myworkspace.should == workspace
            end
          end
        end
      end
    end
  end
end