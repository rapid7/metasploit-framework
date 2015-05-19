require 'spec_helper'
require 'metasploit/framework/login_scanner/invalid'

describe Metasploit::Framework::LoginScanner::Invalid do

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

  it { should be_a StandardError }

  it 'should use ActiveModel::Errors#full_messages' do
    model.errors.should_receive(:full_messages).and_call_original

    described_class.new(model)
  end

  context '#model' do
    subject(:error_model) do
      invalid.model
    end

    it 'should be the passed in model' do
      error_model.should == model
    end
  end

end
