require 'spec_helper'
require 'metasploit/framework/login_scanner/redis'

RSpec.describe Metasploit::Framework::LoginScanner::Redis do
  let(:socket) { double('Socket') }

  def update_socket_res(*res)
    allow(socket).to receive(:put)
    allow(socket).to receive(:get_once).and_return(*res)
    allow(subject).to receive(:sock).and_return(socket)
  end

  let(:credential) do
    cred = double('Credential')
    allow(cred).to receive(:public).and_return('USER')
    allow(cred).to receive(:private).and_return('PASSWORD')
    allow(cred).to receive(:realm).and_return('REALM')
    cred
  end

  subject do
    described_class.new
  end

  describe '#redis_proto' do
    let(:command_parts) do
      ['data']
    end

    it 'returns a String' do
      expect(subject.redis_proto(command_parts)).to be_kind_of(String)
    end
  end

  describe '#attempt_login' do
    before do
      allow(subject).to receive(:connect)
      allow(subject).to receive(:disconnect)
      allow(subject).to receive(:select)
    end

    context 'with Redis version < 6' do
      context 'when server returns incorrect arguments' do
        let(:res) do
          [
            "-ERR wrong number of arguments for 'auth' command",
            '+OK'
          ]
        end

        before { update_socket_res(*res) }

        it 'successfully retries and gets the correct response' do
          expect(subject.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        end
      end

      context 'when server returns no password is set' do
        let(:res) { '-ERR Client sent AUTH, but no password is set' }

        before do
          update_socket_res(res)
        end

        it 'returns NO_AUTH_REQUIRED' do
          expect(subject.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::NO_AUTH_REQUIRED)
        end
      end

      context 'when server returns invalid password' do
        let(:res) { '-ERR invalid password' }

        before do
          update_socket_res(res)
        end

        it 'returns INCORRECT' do
          expect(subject.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::INCORRECT)
        end
      end

      context 'when server returns OK' do
        let(:res) { '+OK' }

        before do
          update_socket_res(res)
        end

        it 'returns SUCCESSFUL' do
          expect(subject.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        end
      end
    end

    context 'with Redis version > 6' do
      context 'when server returns no password is set' do
        let(:res) { '-ERR AUTH <password> called without any password configured for the default user. Are you sure your configuration is correct?' }

        before do
          update_socket_res(res)
        end

        it 'returns NO_AUTH_REQUIRED' do
          expect(subject.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::NO_AUTH_REQUIRED)
        end
      end

      context 'when server returns invalid password' do
        let(:res) { '-WRONGPASS invalid username-password pair or user is disabled' }

        before do
          update_socket_res(res)
        end

        it 'returns INCORRECT' do
          expect(subject.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::INCORRECT)
        end
      end

      context 'when server returns OK' do
        let(:res) { '+OK' }

        before do
          update_socket_res(res)
        end

        it 'returns SUCCESSFUL' do
          expect(subject.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        end
      end
    end
  end

  describe '#set_sane_defaults' do
    context 'when initialized' do
      before(:each) do
        subject.send(:set_sane_defaults)
      end

      it 'sets the connection_timeout to 30' do
        expect(subject.connection_timeout).to be(30)
      end

      it 'sets the default port to 6379' do
        expect(subject.port).to be(6379)
      end

      it 'sets the max_send_size to 0' do
        expect(subject.max_send_size).to be(0)
      end

      it 'sets the send_delay to 0' do
        expect(subject.send_delay).to be(0)
      end
    end
  end

end