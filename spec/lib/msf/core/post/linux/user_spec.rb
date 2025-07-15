require 'spec_helper'

RSpec.describe Msf::Post::Linux::User do
  subject do
    mod = ::Msf::Module.new
    mod.extend described_class
    mod
  end

  describe '#get_home_dir' do
    let(:user) { 'testuser' }
    let(:expected_command) { "grep '^#{user}:' /etc/passwd | cut -d ':' -f 6" }

    context 'when the user exists' do
      it 'returns the home directory path from /etc/passwd' do
        expect(tester).to receive(:cmd_exec)
          .with(expected_command)
          .and_return("/home/testuser\n")

        result = tester.get_home_dir(user)
        expect(result).to eq('/home/testuser')
      end
    end

    context 'when the user does not exist in /etc/passwd' do
      it 'returns an empty string' do
        expect(tester).to receive(:cmd_exec)
          .with(expected_command)
          .and_return("\n")

        result = tester.get_home_dir(user)
        expect(result).to eq('')
      end
    end

  end
end
