RSpec.describe Metasploit::Model::Invalid do
  subject(:invalid) do
    described_class.new(model)
  end

  let(:model) do
    model_class.new
  end

  let(:model_class) do
    Class.new do
      include ActiveModel::Validations
    end
  end

  it { is_expected.to be_a Metasploit::Model::Error }

  it 'should use ActiveModel::Errors#full_messages' do
    expect(model.errors).to receive(:full_messages).and_call_original

    described_class.new(model)
  end

  it 'should translate errors using metasploit.model.invalid' do
    expect(I18n).to receive(:translate).with(
        'metasploit.model.errors.messages.model_invalid',
        hash_including(
            :errors => anything
        )
    ).and_call_original

    described_class.new(model)
  end

  it 'should set translated errors as message' do
    message = "translated message"
    allow(I18n).to receive(:translate).with('metasploit.model.errors.messages.model_invalid', anything).and_return(message)
    instance = described_class.new(model)

    expect(instance.message).to eq(message)
  end

  context '#model' do
    subject(:error_model) do
      invalid.model
    end

    it 'should be the passed in model' do
      expect(error_model).to eq(model)
    end
  end
end