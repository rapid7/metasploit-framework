require 'spec_helper'
require Metasploit::Framework.root.join('plugins/capture.rb').to_path

RSpec.describe Msf::Plugin::Capture::ConsoleCommandDispatcher do
  describe '#cmd_captureg' do
    let(:driver) do
      double(Object).as_null_object.tap do |dbl|
        allow(dbl).to receive(:print_line) do |args|
          args
        end
      end
    end

    subject { described_class.new(driver) }
    context 'without args' do
      it 'returns generic help text' do
        expect(subject.cmd_captureg).to eql subject.help
      end
    end

    context 'single arg matching the HELP regex' do
      it 'returns generic help text' do
        expect(subject.cmd_captureg('--help')).to eql subject.help
      end
    end

    context 'two args, first one matches HELP regex' do
      it 'calls `help` with second arg' do
        expect(subject.cmd_captureg('--help', 'start')).to eql subject.help('start')
      end
    end
  end
end
