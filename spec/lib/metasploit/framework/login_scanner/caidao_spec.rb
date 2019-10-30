require 'spec_helper'
require 'metasploit/framework/login_scanner/caidao'

RSpec.describe Metasploit::Framework::LoginScanner::Caidao do

    it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
    it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

    subject do
      described_class.new
    end

    describe '#check_setup' do
      context 'when uri is php' do
        before do
          allow(subject).to receive(:uri).and_return('php')
        end

        it 'returns true' do
          expect(subject.check_setup).to be_truthy
        end

        it 'creates a php payload' do
          subject.check_setup
          expect(subject.instance_variable_get(:@payload)).to include(';echo ')
        end
      end

      context 'when uri is asp' do
        before do
          allow(subject).to receive(:uri).and_return('asp')
        end

        it 'returns true' do
          expect(subject.check_setup).to be_truthy
        end

        it 'creates an asp payload' do
          subject.check_setup
          expect(subject.instance_variable_get(:@payload)).to include('execute("response.write(')
        end
      end

      context 'when uri is aspx' do
        before do
          allow(subject).to receive(:uri).and_return('aspx')
        end

        it 'returns true' do
          expect(subject.check_setup).to be_truthy
        end

        it 'creates an aspx payload' do
          subject.check_setup
          expect(subject.instance_variable_get(:@payload)).to include('Response.Write')
        end
      end

      context 'when uri is unexpected' do
        before do
          allow(subject).to receive(:uri).and_return('html')
        end

        it 'returns false' do
          expect(subject.check_setup).to be_falsy
        end

        it 'creates no payload' do
          expect(subject.instance_variable_get(:@payload)).to be_nil
        end
      end
    end

    describe '#try_login' do
      let(:username) do
        'username'
      end

      let(:password) do
        'password'
      end

      context 'when the response is nil' do
        before do
          allow(subject).to receive(:send_request).and_return(nil)
        end

        it 'returns a hash' do
          expect(subject.try_login(username, password)).to be_kind_of(Hash)
        end

        it 'returns the UNABLE_TO_CONNECT status in the hash' do
          expect(subject.try_login(username, password)[:status]).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
        end
      end

      context 'when the response includes our flag' do
        before do
          allow(subject).to receive(:uri).and_return('php')
          subject.check_setup
          lmark = subject.instance_variable_get(:@lmark)
          flag = subject.instance_variable_get(:@flag)
          rmark = subject.instance_variable_get(:@rmark)
          res = Rex::Proto::Http::Response.new
          res.code = 200
          res.body = "#{lmark}#{flag}#{rmark}"
          allow(subject).to receive(:send_request).and_return(res)
        end

        it 'returns a hash' do
          expect(subject.try_login(username, password)).to be_kind_of(Hash)
        end

        it 'returns the SUCCESSFUL status in the hash' do
          expect(subject.try_login(username, password)[:status]).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        end
      end

      context 'when the response does not include our flag' do
        before do
          allow(subject).to receive(:uri).and_return('html')
          res = Rex::Proto::Http::Response.new
          allow(subject).to receive(:send_request).and_return(res)
          subject.check_setup
        end

        it 'returns a hash' do
          expect(subject.try_login(username, password)).to be_kind_of(Hash)
        end

        it 'returns the INCORRECT status in the hash' do
          expect(subject.try_login(username, password)[:status]).to eq(Metasploit::Model::Login::Status::INCORRECT)
        end
      end
    end

    describe '#attempt_login' do
      context 'when a login is attempted' do
        it 'returns a Result object' do
        end
      end
    end

end