# frozen_string_literal: true

require 'spec_helper'

COMMANDS = %i[help background sessions resource shell download upload source irb pry]

RSpec.describe Msf::Sessions::CommandShell do
  let(:type) { 'shell' }

  it 'should have the correct type' do
    expect(described_class.type).to eq(type)
  end

  it 'should be able to cleanup files' do
    expect(described_class.can_cleanup_files).to eq(true)
  end

  context 'when we have a command shell session' do
    subject(:command_shell) { described_class.new(nil) }
    let(:command_functions) do
      COMMANDS.map { |command| "cmd_#{command}" }
    end
    let(:command_help_functions) do
      command_functions.map { |command| "#{command}_help" }
    end
    let(:description) { 'Command shell' }

    it { is_expected.to respond_to(*command_functions) }
    it { is_expected.to respond_to(*command_help_functions) }

    it 'should have the correct type' do
      expect(subject.type).to eq(type)
    end
    it 'should have the correct description' do
      expect(subject.desc).to eq(description)
    end

    it 'should not support aborting the process running in the session' do
      expect(subject.abort_foreground_supported).to be(true)
    end

    it 'should initialise the shell by default' do
      expect(subject.shell_init).to be(true)
    end

    describe 'Builtin commands' do
      COMMANDS.each do |command|
        next if command == :help

        describe "#cmd_#{command}" do
          context 'when called with the `-h` argument' do
            it 'should call the corresponding help function' do
              expect(subject).to receive("cmd_#{command}_help")
              subject.send("cmd_#{command}", '-h')
            end
          end

          context 'when called with the `--help` argument' do
            it 'should call the corresponding help function' do
              expect(subject).to receive("cmd_#{command}_help")
              subject.send("cmd_#{command}", '--help')
            end
          end
        end
      end
    end

    describe '#run_builtin_cmd' do
      COMMANDS.each do |command|
        context "when called with `#{command}`" do
          it "should call cmd_#{command}" do
            expect(subject).to receive("cmd_#{command}")
            subject.run_builtin_cmd(command.to_s, nil)
          end
        end
      end
    end

    describe '#run_single' do
      COMMANDS.each do |command|
        context "when called with builtin command `#{command}`" do
          it 'should call the builtin function' do
            expect(subject).to receive(:run_builtin_cmd)
            subject.run_single(command.to_s)
          end
        end
      end

      context 'when called with a non-builtin command' do
        let(:cmd) { 'some_command' }
        it 'should write the command to the shell' do
          expect(subject).to receive(:shell_write).with("#{cmd}\n")
          subject.run_single(cmd)
        end
      end
    end

    describe '#process_autoruns' do
      let(:initial_auto_run_script) { 'initial_auto_run_script' }
      let(:auto_run_script) { 'auto_run_script' }

      context 'The datastore is empty' do
        let(:datastore) do
          Msf::DataStore.new
        end
        it 'should not execute any script' do
          is_expected.not_to receive(:execute_script)
          subject.process_autoruns(datastore)
        end
      end

      context 'The datastore contains an `InitialAutoRunScript`' do
        let(:datastore) do
          datastore = Msf::DataStore.new
          datastore['InitialAutoRunScript'] = initial_auto_run_script
          datastore
        end
        it 'should execute the script' do
          is_expected.to receive(:execute_script).with(initial_auto_run_script)
          subject.process_autoruns(datastore)
        end
      end

      context 'The datastore contains an `AutoRunScript`' do
        let(:datastore) do
          datastore = Msf::DataStore.new
          datastore['AutoRunScript'] = auto_run_script
          datastore
        end
        it 'should execute the script' do
          is_expected.to receive(:execute_script).with(auto_run_script)
          subject.process_autoruns(datastore)
        end
      end

      context 'The datastore contains both `InitialAutoRunScript` and `AutoRunScript`' do
        let(:datastore) do
          datastore = Msf::DataStore.new
          datastore['InitialAutoRunScript'] = initial_auto_run_script
          datastore['AutoRunScript'] = auto_run_script
          datastore
        end
        it 'should execute initial script before the auto run script' do
          is_expected.to receive(:execute_script).ordered.with(initial_auto_run_script)
          is_expected.to receive(:execute_script).ordered.with(auto_run_script)
          subject.process_autoruns(datastore)
        end
      end
    end

    context 'when the platform is windows' do
      let(:platform) { 'windows' }
      before(:each) do
        subject.platform = platform
      end

      it 'should not support aborting the process running in the session' do
        expect(subject.abort_foreground_supported).to be(false)
      end
    end
  end
end
