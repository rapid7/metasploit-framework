require 'spec_helper'
require 'metasploit/framework/login_scanner'

describe Metasploit::Framework::LoginScanner::Result do

  let(:private) { 'toor' }
  let(:proof) { 'foobar' }
  let(:public) { 'root' }
  let(:realm) { nil }
  let(:status) { Metasploit::Model::Login::Status::SUCCESSFUL }
  let(:cred) {
    Metasploit::Framework::Credential.new(public: public, private: private, realm: realm, paired: true)
  }

  subject(:login_result) {
    described_class.new(
        credential: cred,
        proof: proof,
        status: status
    )
  }

  it { should respond_to :access_level }
  it { should respond_to :credential }
  it { should respond_to :proof }
  it { should respond_to :status }
  it { should respond_to :success? }

  context '#success?' do
    context 'when the status code is success' do
        it 'returns true' do
          expect(login_result.success?).to be_truthy
        end
    end

    context 'when the status code is anything else' do
      let(:status) { :connection_error }
      it 'returns false' do
        expect(login_result.success?).to be_falsey
      end
    end
  end


end
