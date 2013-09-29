shared_examples_for 'Msf::Auxiliary::Report.report' do |suffix|
  method_name = "report_#{suffix}"

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
        auxiliary_metasploit_instance.stub(
            mytask: task,
            myworkspace: workspace
        )

        framework.db.stub(connected?: connected)
      end

      context 'with false' do
        let(:connected) do
          false
        end

        it 'should not call #mytask' do
          auxiliary_metasploit_instance.should_not_receive(:mytask)

          send(method_name)
        end

        it 'should not call #myworkspace' do
          auxiliary_metasploit_instance.should_not_receive(:myworkspace)

          send(method_name)
        end

        it "should not call framework.db.#{method_name}" do
          framework.db.should_not_receive(method_name)

          send(method_name)
        end
      end

      context 'with true' do
        let(:connected) do
          true
        end

        it "should call framework.db.#{method_name}" do
          framework.db.should_receive(method_name)

          send(method_name)
        end

        it 'should pass #mytask as :task' do
          framework.db.should_receive(method_name).with(
              hash_including(
                  task: task
              )
          )

          send(method_name)
        end

        it 'should pass #myworkspace as :workspace' do
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