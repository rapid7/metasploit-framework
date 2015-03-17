require 'spec_helper'
require 'metasploit/framework/login_scanner/swg'

describe Metasploit::Framework::LoginScanner::SymantecWebGateway do

    it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
    it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

    describe '#check_setup' do
      context 'when target is Symantec Web Gateway' do
        it 'returns true' do
        end
      end

      context 'when target is not Symantec Web Gateway' do
        it 'returns false' do
        end
      end
    end

    describe '#send_request' do
      context 'when a valid request is sent' do
        it 'returns a response object' do
        end
      end

      context 'when the server times out' do
        it 'raises Rex::ConnectionError' do
        end
      end
    end

    describe '#get_last_sid' do
      context 'when there is no session ID' do
        it 'returns a new session ID' do
        end
      end

      context 'when there is already a session ID' do
        it 'returns the current session ID' do
        end
      end
    end

    describe '#get_login_state' do
      context 'when the credential is valid' do
        it 'returns a hash indicating successful' do
        end
      end

      context 'when the creential is invalid' do
        it 'returns a hash indicating an incorrect cred' do
        end
      end
    end

    describe '#attempt_login' do
      context 'when the credential is valid' do
        it 'returns a Result object indicating successful' do
        end
      end

      context 'when the credential is invalid' do
        it 'returns a Result object indicating an incorrect cred' do
        end
      end
    end
end