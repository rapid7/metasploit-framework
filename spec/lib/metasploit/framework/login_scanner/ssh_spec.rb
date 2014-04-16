require 'spec_helper'
require 'metasploit/framework/login_scanner/ssh'

describe Metasploit::Framework::LoginScanner::SSH do

  subject(:ssh_scanner) {
    described_class.new
  }

  it { should respond_to :port }
  it { should respond_to :host }
  it { should respond_to :cred_details }

  context 'validations' do
    context 'port' do

      it 'is not valid for not set' do
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:port]).to include "is not a number"
      end

      it 'is not valid for a non-number' do
        ssh_scanner.port = "a"
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:port]).to include "is not a number"
      end

      it 'is not valid for a floating point' do
        ssh_scanner.port = 5.76
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:port]).to include "must be an integer"
      end

      it 'is not valid for a negative number' do
        ssh_scanner.port = -8
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:port]).to include "must be greater than or equal to 1"
      end

      it 'is not valid for 0' do
        ssh_scanner.port = 0
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:port]).to include "must be greater than or equal to 1"
      end

      it 'is not valid for a number greater than 65535' do
        ssh_scanner.port = rand(1000) + 65535
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:port]).to include "must be less than or equal to 65535"
      end

      it 'is valid for a legitimate port number' do
        ssh_scanner.port = rand(65534) + 1
        expect(ssh_scanner.errors[:port]).to be_empty
      end
    end

    context 'host' do

      it 'is not valid for not set' do
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:host]).to include "can't be blank"
      end

      it 'is not valid for a non-string input' do
        ssh_scanner.host = 5
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:host]).to include "must be a string"
      end

      it 'is not valid for an improper IP address' do
        ssh_scanner.host = '192.168.1.1.5'
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is not valid for an incomplete IP address' do
        ssh_scanner.host = '192.168'
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is not valid for an invalid IP address' do
        ssh_scanner.host = '192.300.675.123'
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is not valid for DNS name that cannot be resolved' do
        ssh_scanner.host = 'nosuchplace.metasploit.com'
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:host]).to include "could not be resolved"
      end

      it 'is valid for a valid IP address' do
        ssh_scanner.host = '127.0.0.1'
        expect(ssh_scanner.errors[:host]).to be_empty
      end

      it 'is valid for a DNS name it can resolve' do
        ssh_scanner.host = 'localhost'
        expect(ssh_scanner.errors[:host]).to be_empty
      end
    end

    context 'cred_details' do
      it 'is not valid for not set' do
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:cred_details]).to include "can't be blank"
      end

      it 'is not valid for a non-array input' do
        ssh_scanner.cred_details = rand(10)
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:cred_details]).to include "must be an array"
      end

      it 'is not valid if any of the elements are not a hash' do
        ssh_scanner.cred_details = [1,2]
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:cred_details]).to include "has invalid element 1"
      end

      it 'is not valid if any of the elements are missing a public component' do
        detail = { private: 'toor'}
        ssh_scanner.cred_details = [detail]
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:cred_details]).to include "has invalid element, missing public component #{detail}"
      end

      it 'is not valid if any of the elements have an invalid public component' do
        detail = { public: 5, private: 'toor'}
        ssh_scanner.cred_details = [detail]
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:cred_details]).to include "has invalid element, invalid public component #{detail}"
      end

      it 'is not valid if any of the elements are missing a public component' do
        detail = { public: 'root'}
        ssh_scanner.cred_details = [detail]
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:cred_details]).to include "has invalid element, missing private component #{detail}"
      end

      it 'is not valid if any of the elements have an invalid public component' do
        detail = { public: 'root', private: []}
        ssh_scanner.cred_details = [detail]
        expect(ssh_scanner).to_not be_valid
        expect(ssh_scanner.errors[:cred_details]).to include "has invalid element, invalid private component #{detail}"
      end

      it 'is valid if all of the lements are properly formed hashes' do
        detail = { public: 'root', private: 'toor'}
        ssh_scanner.cred_details = [detail]
        expect(ssh_scanner.errors[:cred_details]).to be_empty
      end
    end

    context '#valid!' do
      it 'raises a Metasploit::Framework::LoginScanner::Invalid when validations fail' do
        expect{ssh_scanner.valid!}.to raise_error Metasploit::Framework::LoginScanner::Invalid
      end
    end
  end
end