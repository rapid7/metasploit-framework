shared_examples_for 'Msf::DBManager::Activation' do
  it_should_behave_like 'Msf::DBManager::Activation::Once'

  context '#activate' do
    subject(:activate) do
      db_manager.activate
    end

    it 'should be synchronized' do
      db_manager.should_receive(:synchronize)

      activate
    end

    context 'activated already' do
      before(:each) do
        db_manager.instance_variable_set :@activated, activated
      end

      context 'with false' do
        let(:activated) do
          false
        end

        it 'should call #activate_once' do
          db_manager.should_receive(:activate_once)

          activate
        end

        it 'should set @activated to true' do
          expect {
            activate
          }.to change {
            db_manager.instance_variable_get :@activated
          }.to(true)
        end
      end

      context 'with true' do
        let(:activated) do
          true
        end

        it 'should not call #activate_once' do
          db_manager.should_not_receive(:activate_once)

          activate
        end
      end
    end
  end
end