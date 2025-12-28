require 'spec_helper'

RSpec.describe Msf::Post::Linux::Wsl do
  subject do
    mod = ::Msf::Module.new
    mod.extend described_class
    mod
  end

  describe '#wsl?' do
    let(:expected_command) { 'uname -r' }

    context 'when the kernel includes Microsoft' do
      it 'returns true' do
        expect(subject).to receive(:cmd_exec)
          .with(expected_command)
          .and_return("4.4.0-18362-Microsoft\n") # Ubuntu 24.04 on Windows 10 as of Dec 28 2025

        result = subject.wsl?
        expect(result).to be true
      end
    end

    context 'when the kernel doesn\'t includes Microsoft' do
      it 'returns false' do
        expect(subject).to receive(:cmd_exec)
          .with(expected_command)
          .and_return("6.17.10+kali-amd64\n")

        result = subject.wsl?
        expect(result).to be false
      end
    end
  end
end
