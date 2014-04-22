require 'spec_helper'
require 'metasploit/framework/login_scanner'

describe Metasploit::Framework::LoginScanner::Result do

  let(:private) { 'toor' }
  let(:proof) { 'foobar' }
  let(:public) { 'root' }
  let(:realm) { nil }
  let(:status) { :success }

  subject(:login_result) {
    described_class.new(
        private: private,
        proof: proof,
        public: public,
        status: status,
        realm: realm
    )
  }

  it { should respond_to :private }
  it { should respond_to :proof }
  it { should respond_to :public }
  it { should respond_to :realm }
  it { should respond_to :status }
  it { should respond_to :success? }

  context '#success?' do
    context 'when the status code is success' do
        it 'returns true' do
          expect(login_result.success?).to be_true
        end
    end

    context 'when the status code is anything else' do
      let(:status) { :connection_error }
      it 'returns false' do
        expect(login_result.success?).to be_false
      end
    end
  end


end