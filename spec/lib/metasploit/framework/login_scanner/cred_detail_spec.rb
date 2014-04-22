require 'spec_helper'
require 'metasploit/framework/login_scanner'

describe Metasploit::Framework::LoginScanner::CredDetail do

  subject(:cred_detail) {
    described_class.new
  }

  it { should respond_to :paired }
  it { should respond_to :private }
  it { should respond_to :public }
  it { should respond_to :realm }

  context 'validations' do

    it 'is not valid without paired being set' do
      expect(cred_detail).to_not be_valid
    end

    context 'when not paired' do
      before(:each) do
        cred_detail.paired = false
      end

      it 'is invalid without at least a public or a private' do
        expect(cred_detail).to_not be_valid
      end

      it 'is valid with just a public' do
        cred_detail.public = 'root'
        expect(cred_detail).to be_valid
      end

      it 'is valid with just a private' do
        cred_detail.private = 'toor'
        expect(cred_detail).to be_valid
      end
    end

    context 'when paired' do
      before(:each) do
        cred_detail.paired = true
      end

      it 'is invalid with only a public' do
        cred_detail.public = 'root'
        expect(cred_detail).to_not be_valid
      end

      it 'is invalid with only a private' do
        cred_detail.private = 'toor'
        expect(cred_detail).to_not be_valid
      end

      it 'is invalid with empty string for public' do
        cred_detail.public = ''
        cred_detail.private = 'toor'
        expect(cred_detail).to_not be_valid
      end

      it 'is valid with empty string for private' do
        cred_detail.public = 'root'
        cred_detail.private = ''
        expect(cred_detail).to be_valid
      end
    end


  end
end