# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Sessions::CommandShell do
  let(:type) { 'shell' }

  describe '.type' do
    it 'should have the correct type' do
      expect(described_class.type).to eq(type)
    end
  end

  describe '.can_cleanup_files' do
    it 'should be able to cleanup files' do
      expect(described_class.can_cleanup_files).to eq(true)
    end
  end

  context 'when we have a command shell session' do
    subject(:command_shell) { described_class.new(nil) }
    let(:command_functions) do
      %i[help background sessions resource shell download upload source irb pry].map { |command| "cmd_#{command}" }
    end
    let(:command_help_functions) do
      command_functions.map { |command| "#{command}_help" }
    end
    let(:description) { 'Command shell' }

    describe '#type' do
      it 'should have the correct type' do
        expect(subject.type).to eq(type)
      end
    end

    describe '#desc' do
      it 'should have the correct description' do
        expect(subject.desc).to eq(description)
      end
    end

    describe '#abort_foreground_supported' do
      it 'should not support aborting the process running in the session' do
        expect(subject.abort_foreground_supported).to be(true)
      end
    end

    describe '#shell_init' do
      it 'should initialise the shell by default' do
        expect(subject.shell_init).to be(true)
      end
    end

    describe 'Builtin commands' do
      %i[background sessions resource shell download upload source irb pry].each do |command|
        before(:each) do
          allow(subject).to receive("cmd_#{command}_help")
        end

        describe "#cmd_#{command}" do
          context 'when called with the `-h` argument' do
            it 'should call the corresponding help function' do
              subject.send("cmd_#{command}", '-h')
              expect(subject).to have_received("cmd_#{command}_help")
            end
          end

          context 'when called with the `--help` argument' do
            it 'should call the corresponding help function' do
              subject.send("cmd_#{command}", '--help')
              expect(subject).to have_received("cmd_#{command}_help")
            end
          end
        end
      end
    end

    describe '#run_builtin_cmd' do
      %i[help background sessions resource shell download upload source irb pry].each do |command|
        before(:each) do
          allow(subject).to receive("cmd_#{command}")
        end
        context "when called with `#{command}`" do
          it "should call cmd_#{command}" do
            subject.run_builtin_cmd(command.to_s, nil)
            expect(subject).to have_received("cmd_#{command}")
          end
        end
      end
    end

    describe '#run_single' do
      before(:each) do
        allow(subject).to receive(:run_builtin_cmd)
        allow(subject).to receive(:shell_write)
      end
      %i[help background sessions resource shell download upload source irb pry].each do |command|
        context "when called with builtin command `#{command}`" do
          it 'should call the builtin function' do
            subject.run_single(command.to_s)
            expect(subject).to have_received(:run_builtin_cmd)
          end
        end
      end

      context 'when called with a non-builtin command' do
        let(:cmd) { 'some_command' }
        it 'should write the command to the shell' do
          subject.run_single(cmd)
          expect(subject).to have_received(:shell_write).with("#{cmd}\n")
        end
      end
    end

    describe '#process_autoruns' do
      let(:initial_auto_run_script) { 'initial_auto_run_script' }
      let(:auto_run_script) { 'auto_run_script' }

      before(:each) do
        allow(subject).to receive(:execute_script)
      end

      context 'The datastore is empty' do
        let(:datastore) do
          Msf::DataStore.new
        end
        it 'should not execute any script' do
          subject.process_autoruns(datastore)
          is_expected.not_to have_received(:execute_script)
        end
      end

      context 'The datastore contains an `InitialAutoRunScript`' do
        let(:datastore) do
          datastore = Msf::DataStore.new
          datastore['InitialAutoRunScript'] = initial_auto_run_script
          datastore
        end

        it 'should execute the script' do
          subject.process_autoruns(datastore)
          is_expected.to have_received(:execute_script).with(initial_auto_run_script)
        end
      end

      context 'The datastore contains an `AutoRunScript`' do
        let(:datastore) do
          datastore = Msf::DataStore.new
          datastore['AutoRunScript'] = auto_run_script
          datastore
        end
        it 'should execute the script' do
          subject.process_autoruns(datastore)
          is_expected.to have_received(:execute_script).with(auto_run_script)
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
          subject.process_autoruns(datastore)
          is_expected.to have_received(:execute_script).ordered.with(initial_auto_run_script)
          is_expected.to have_received(:execute_script).ordered.with(auto_run_script)
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
