require 'spec_helper'
require 'metasploit/framework/login_scanner/ssh'

describe Metasploit::Framework::LoginScanner::SSH do

  subject(:ssh_scanner) {
    described_class.new
  }

  it { should respond_to :port }
  it { should respond_to :host }
  it { should respond_to :cred_pairs }

  context 'validations' do
    context 'port' do

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
    end
  end
end