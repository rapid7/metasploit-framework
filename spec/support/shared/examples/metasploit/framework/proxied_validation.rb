shared_examples_for 'Metasploit::Framework::ProxiedValidation' do
  context '#errors' do
    subject(:errors) do
      target.errors
    end

    it 'should delegate to #validation_proxy' do
      target.validation_proxy.should_receive(:errors)

      errors
    end
  end

  context '#invalid?' do
    subject(:invalid?) do
      target.invalid?
    end

    context 'with context' do
      subject(:invalid?) do
        target.invalid?(context)
      end

      let(:context) do
        :validation_context
      end

      it 'should pass context to #valid?' do
        target.should_receive(:valid?).with(context)

        invalid?
      end
    end

    context 'without context' do
      it 'should use nil context by default' do
        target.should_receive(:valid?).with(nil)

        invalid?
      end
    end

    context 'with valid?' do
      before(:each) do
        target.stub(valid?: true )
      end

      it { should be_false }
    end

    context 'without valid?' do
      before(:each) do
        target.stub(valid?: false)
      end

      it { should be_true }
    end
  end

  context '#valid?' do
    subject(:valid?) do
      target.valid?
    end

    let(:validation_proxy) do
      target.validation_proxy
    end

    it 'should delegate to #validation_proxy' do
      validation_proxy.should_receive(:valid?)

      valid?
    end

    context 'with context' do
      subject(:valid?) do
        target.valid?(validation_context)
      end

      let(:validation_context) do
        :validation_context
      end

      it 'should pass context to validation_proxy.valid?' do
        validation_proxy.should_receive(:valid?).with(validation_context)

        valid?
      end
    end

    context 'without context' do
      it 'should default to nil context' do
        validation_proxy.should_receive(:valid?).with(nil)

        valid?
      end
    end
  end

  context '#validation_proxy' do
    subject(:validation_proxy) do
      target.validation_proxy
    end

    it 'should be instance of #validation_proxy_class' do
      validation_proxy.should be_a target.validation_proxy_class
    end

    context 'target' do
      subject(:validation_proxy_target) do
        validation_proxy.target
      end

      it 'should be the Module that includes Metasploit::Framework::ProxiedValidation' do
        validation_proxy_target.should == target
      end
    end
  end
end