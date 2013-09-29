shared_examples_for 'Msf::Auxiliary::Report.get' do |suffix|
  method_name = "get_#{suffix}"

  context method_name do
    subject(method_name) do
      with_established_connection {
        auxiliary_metasploit_instance.send(method_name, options)
      }
    end

    let(:options) do
      {
          passed: :in
      }
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

        it 'should delegate to framework.db' do
          framework.db.should_receive(method_name)

          send(method_name)
        end

        it 'should pass #myworkspace as :workspace' do
          auxiliary_metasploit_instance.stub(myworkspace: workspace)

          framework.db.should_receive(method_name).with(
              hash_including(
                  workspace: workspace
              )
          )

          send(method_name)
        end

        it 'should pass options' do
          framework.db.should_receive(method_name).with(
              hash_including(
                  options
              )
          )

          send(method_name)
        end
      end
    end
  end
end