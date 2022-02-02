require 'spec_helper'
require 'metasploit/framework/login_scanner/invalid'

RSpec.describe Metasploit::Framework::LoginScanner::Invalid do

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

  it { is_expected.to be_a StandardError }

  it 'should use ActiveModel::Errors#full_messages' do
    expect(model.errors).to receive(:full_messages).and_call_original

    described_class.new(model)
  end

  context '#model' do
    subject(:error_model) do
      invalid.model
    end

    it 'should be the passed in model' do
      expect(error_model).to eq model
    end
  end

end
