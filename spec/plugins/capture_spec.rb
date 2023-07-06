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

RSpec.describe Msf::Plugin::Capture::ConsoleCommandDispatcher::CaptureJobListener do
  let(:dispatcher) do
    instance_double(
      Msf::Plugin::Capture::ConsoleCommandDispatcher,
      print_error: nil,
      print_good: nil
    )
  end
  let(:done_event) { instance_double(Rex::Sync::Event, set: nil) }
  let(:name) { 'my-little-module' }

  subject { described_class.new(name, done_event, dispatcher) }

  describe '#waiting' do
    it 'sets the `succeeded` flag' do
      subject.waiting('ignored')

      expect(subject.succeeded).to eql true
    end

    it 'outputs a message via the dispatcher' do
      expect(dispatcher).to receive(:print_good).with("#{name} started")

      subject.waiting('ignored')
    end

    it 'sets the done event' do
      expect(done_event).to receive(:set)

      subject.waiting('ignored')
    end
  end

  describe '#failed' do
    it 'outputs a message via the dispatcher' do
      expect(dispatcher).to receive(:print_error).with("#{name} failed to start")

      subject.failed('ignored', 'ignored', 'ignored')
    end

    it 'sets the done event' do
      expect(done_event).to receive(:set)

      subject.failed('ignored', 'ignored', 'ignored')
    end
  end
end
