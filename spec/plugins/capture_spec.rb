require 'spec_helper'
require Metasploit::Framework.root.join('plugins/capture.rb').to_path

RSpec.describe Msf::Plugin::Capture::ConsoleCommandDispatcher do
  include_context 'Msf::UIDriver'

  let(:framework) { instance_double(Msf::Framework) }

  describe '#cmd_captureg' do
    subject { described_class.new(driver) }

    context 'when called without args' do
      it 'returns generic help text' do
        expect(subject.cmd_captureg).to eql subject.help
      end
    end

    context 'when there is a single arg matching the HELP regex' do
      it 'returns generic help text' do
        expect(subject.cmd_captureg('--help')).to eql subject.help
      end
    end

    context 'when there are two args with first one matching the HELP regex' do
      it 'calls `help` with second arg' do
        expect(subject.cmd_captureg('--help', 'start')).to eql subject.help('start')
      end
    end
  end
end

RSpec.describe Msf::Plugin::Capture::ConsoleCommandDispatcher::CaptureJobListener do
  include_context 'Msf::UIDriver'
  let(:dispatcher) { instance_double(Msf::Plugin::Capture::ConsoleCommandDispatcher) }
  let(:done_event) { instance_double(Rex::Sync::Event, set: nil) }
  let(:name) { 'my-little-module' }

  subject { described_class.new(name, done_event, dispatcher) }

  before(:each) do
    capture_logging(dispatcher)
  end

  describe '#waiting' do
    it 'sets the `succeeded` flag' do
      subject.waiting('ignored')

      expect(subject.succeeded).to eql true
    end

    it 'outputs a message via the dispatcher' do
      subject.waiting('ignored')

      expect(@output).to include("#{name} started")
    end

    it 'sets the done event' do
      expect(done_event).to receive(:set)

      subject.waiting('ignored')
    end
  end

  describe '#failed' do
    it 'outputs a message via the dispatcher' do
      subject.failed('ignored', 'ignored', 'ignored')

      expect(@error).to include("#{name} failed to start")
    end

    it 'sets the done event' do
      expect(done_event).to receive(:set)

      subject.failed('ignored', 'ignored', 'ignored')
    end
  end
end
