# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'post/multi/manage/sudo' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject do
    mod = load_and_create_module(
      module_type: 'post',
      reference_name: 'multi/manage/sudo'
    )
    mod.datastore['SESSION'] = 1
    mod
  end

  let(:session) do
    double(
      'session',
      type: 'shell',
      platform: 'linux',
      exploit_datastore: { 'PASSWORD' => nil, 'USERNAME' => 'test-user' }
    )
  end

  before do
    allow(subject).to receive(:session).and_return(session)
    allow(session).to receive(:escape_arg) { |value| "'#{value}'" }
    allow(subject).to receive(:print_status)
    allow(subject).to receive(:print_good)
    allow(subject).to receive(:print_error)
    allow(subject).to receive(:vprint_status)
  end

  describe '#askpass_script' do
    it 'quotes shell metacharacters and single quotes without expansion' do
      password = "p@ss' $(id) \\$HOME \`uname\`"
      expect(subject.send(:askpass_script, password)).to eq(
        "#!/bin/sh\nprintf '%s\\n' 'p@ss'\"'\"' $(id) \\$HOME \`uname\`'\n"
      )
    end
  end

  describe 'session compatibility' do
    it 'is restricted to shell sessions' do
      expect(subject.session_types).to contain_exactly('shell')
    end
  end

  describe '#with_askpass_script' do
    let(:password) { "synthetic' password" }
    let(:askpass_dir) { '/tmp/.AbCdEfG' }
    let(:askpass_sh) { "#{askpass_dir}/askpass" }
    let(:remove_askpass_sh) { "rm -f '#{askpass_sh}'" }
    let(:remove_askpass_dir) { "rmdir '#{askpass_dir}'" }

    before do
      allow(Rex::Text).to receive(:rand_text_alpha).with(7).and_return('AbCdEfG')
    end

    it 'creates a private directory and file before yielding, then verifies cleanup without stale registrations' do
      expect(subject).not_to receive(:register_dir_for_cleanup)
      expect(subject).not_to receive(:register_file_for_cleanup)
      expect(subject).to receive(:_shell_command_with_success_code)
        .with("/bin/sh -c 'umask 077 && mkdir -m 700 \"$1\"' sh '#{askpass_dir}'")
        .ordered
        .and_return(true)
      expect(subject).to receive(:_shell_command_with_success_code)
        .with("/bin/sh -c 'umask 077 && touch \"$1\" && chmod 700 \"$1\"' sh '#{askpass_sh}'")
        .ordered
        .and_return(true)
      expect(subject).to receive(:write_file)
        .with(askpass_sh, subject.send(:askpass_script, password))
        .ordered
        .and_return(true)
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_sh).ordered.and_return(true)
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_dir).ordered.and_return(true)

      result = subject.send(:with_askpass_script, password) do |path|
        expect(path).to eq(askpass_sh)
        :used
      end
      expect(result).to eq(:used)
      expect(subject.instance_variable_get(:@dropped_files)).to be_empty
      expect(subject.instance_variable_get(:@dropped_dirs)).to be_empty
    end

    it 'does not remove or register a pre-existing path when private directory creation fails' do
      expect(subject).to receive(:_shell_command_with_success_code)
        .with("/bin/sh -c 'umask 077 && mkdir -m 700 \"$1\"' sh '#{askpass_dir}'")
        .and_return(false)
      expect(subject).not_to receive(:_shell_command_with_success_code).with(remove_askpass_sh)
      expect(subject).not_to receive(:_shell_command_with_success_code).with(remove_askpass_dir)
      expect(subject).not_to receive(:register_file_for_cleanup)
      expect(subject).not_to receive(:register_dir_for_cleanup)

      expect { subject.send(:with_askpass_script, password) { nil } }
        .to raise_error(RuntimeError, 'Could not create a private SUDO_ASKPASS directory')
    end

    it 'verifies cleanup of the private directory if writing the script fails' do
      allow(subject).to receive(:_shell_command_with_success_code).and_return(true)
      allow(subject).to receive(:write_file).and_return(false)
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_sh).and_return(true)
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_dir).and_return(true)

      expect { subject.send(:with_askpass_script, password) { nil } }
        .to raise_error(RuntimeError, 'Could not write the SUDO_ASKPASS script')
    end

    it 'verifies cleanup when an enclosing timeout unwinds through password writing' do
      allow(subject).to receive(:_shell_command_with_success_code).and_return(true)
      allow(subject).to receive(:write_file) { sleep 1 }
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_sh).and_return(true)
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_dir).and_return(true)

      expect do
        ::Timeout.timeout(0.01) do
          subject.send(:with_askpass_script, password) { raise 'unreachable' }
        end
      end.to raise_error(::Timeout::Error)
    end

    it 'verifies cleanup when an enclosing timeout expires inside the yielded use' do
      allow(subject).to receive(:_shell_command_with_success_code).and_return(true)
      allow(subject).to receive(:write_file).and_return(true)
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_sh).and_return(true)
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_dir).and_return(true)

      expect do
        ::Timeout.timeout(0.01) do
          subject.send(:with_askpass_script, password) { sleep 1 }
        end
      end.to raise_error(::Timeout::Error)
    end
  end

  describe '#cleanup_askpass_script' do
    let(:askpass_dir) { '/tmp/.AbCdEfG' }
    let(:askpass_sh) { "#{askpass_dir}/askpass" }
    let(:remove_askpass_sh) { "rm -f '#{askpass_sh}'" }
    let(:remove_askpass_dir) { "rmdir '#{askpass_dir}'" }

    it 'does not warn or register when both removals are verified' do
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_sh).ordered.and_return(true)
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_dir).ordered.and_return(true)
      expect(subject).not_to receive(:print_warning)
      expect(subject).not_to receive(:register_file_for_cleanup)
      expect(subject).not_to receive(:register_dir_for_cleanup)

      subject.send(:cleanup_askpass_script, askpass_dir, askpass_sh)
    end

    it 'treats verified directory removal as complete after an unverified file removal' do
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_sh).ordered.and_return(false)
      expect(subject).to receive(:print_warning).with(/attempting private directory cleanup/).ordered
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_dir).ordered.and_return(true)
      expect(subject).not_to receive(:register_file_for_cleanup)
      expect(subject).not_to receive(:register_dir_for_cleanup)

      subject.send(:cleanup_askpass_script, askpass_dir, askpass_sh)
    end

    it 'warns without registering a reusable path when both removals are unverified' do
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_sh).ordered.and_return(false)
      expect(subject).to receive(:print_warning).with(/attempting private directory cleanup/).ordered
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_dir).ordered.and_return(false)
      expect(subject).to receive(:print_warning).with(/manual cleanup may be required/).ordered
      expect(subject).not_to receive(:register_file_for_cleanup)
      expect(subject).not_to receive(:register_dir_for_cleanup)
      expect(subject).not_to receive(:rm_rf)

      subject.send(:cleanup_askpass_script, askpass_dir, askpass_sh)
    end

    it 'leaves unexpected directory contents for manual cleanup without a recursive fallback' do
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_sh).ordered.and_return(true)
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_dir).ordered.and_return(false)
      expect(subject).to receive(:print_warning).with(/manual cleanup may be required/).ordered
      expect(subject).not_to receive(:register_file_for_cleanup)
      expect(subject).not_to receive(:register_dir_for_cleanup)
      expect(subject).not_to receive(:rm_rf)

      subject.send(:cleanup_askpass_script, askpass_dir, askpass_sh)
    end

    it 'still attempts directory removal when file removal raises' do
      expect(subject).to receive(:_shell_command_with_success_code)
        .with(remove_askpass_sh)
        .ordered
        .and_raise(RuntimeError, 'synthetic file failure')
      expect(subject).to receive(:print_warning).with(
        satisfy do |message|
          message.include?('RuntimeError') &&
            !message.include?('synthetic file failure') &&
            !message.include?(askpass_dir) &&
            !message.include?(askpass_sh)
        end
      ).ordered
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_dir).ordered.and_return(true)
      expect(subject).not_to receive(:register_file_for_cleanup)
      expect(subject).not_to receive(:register_dir_for_cleanup)

      expect { subject.send(:cleanup_askpass_script, askpass_dir, askpass_sh) }.not_to raise_error
    end

    it 'warns without overriding the handled result when directory removal raises' do
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_sh).ordered.and_return(true)
      expect(subject).to receive(:_shell_command_with_success_code)
        .with(remove_askpass_dir)
        .ordered
        .and_raise(RuntimeError, 'synthetic directory failure')
      expect(subject).to receive(:print_warning).with(
        satisfy do |message|
          message.include?('RuntimeError') &&
            !message.include?('synthetic directory failure') &&
            !message.include?(askpass_dir) &&
            !message.include?(askpass_sh)
        end
      ).ordered
      expect(subject).not_to receive(:register_file_for_cleanup)
      expect(subject).not_to receive(:register_dir_for_cleanup)

      expect { subject.send(:cleanup_askpass_script, askpass_dir, askpass_sh) }.not_to raise_error
    end

    it 'attempts directory removal and preserves an outer timeout that expires during file removal' do
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_sh).ordered do
        sleep 1
      end
      expect(subject).to receive(:_shell_command_with_success_code).with(remove_askpass_dir).ordered.and_return(true)
      expect(subject).not_to receive(:register_file_for_cleanup)
      expect(subject).not_to receive(:register_dir_for_cleanup)

      expect do
        ::Timeout.timeout(0.01) do
          subject.send(:cleanup_askpass_script, askpass_dir, askpass_sh)
        end
      end.to raise_error(::Timeout::Error)
    end

    it 'does not expose cleanup paths when removal cannot be verified' do
      warnings = []
      allow(subject).to receive(:_shell_command_with_success_code).and_return(false, false)
      allow(subject).to receive(:print_warning) { |message| warnings << message }
      expect(subject).not_to receive(:register_file_for_cleanup)
      expect(subject).not_to receive(:register_dir_for_cleanup)
      expect(subject).not_to receive(:rm_rf)

      subject.send(:cleanup_askpass_script, askpass_dir, askpass_sh)

      warning_text = warnings.join(' ')
      expect(warning_text).not_to include(askpass_dir)
      expect(warning_text).not_to include(askpass_sh)
    end
  end

  describe '#askpass_sudo' do
    let(:askpass_dir) { '/tmp/.AbCdEfG' }
    let(:askpass_sh) { "#{askpass_dir}/askpass" }

    before do
      allow(subject).to receive(:with_askpass_script).and_yield(askpass_sh)
    end

    it 'cleans up immediately after success' do
      allow(subject).to receive(:cmd_exec)
      expect(subject).to receive(:with_askpass_script).with('synthetic-password').and_yield(askpass_sh)

      subject.send(:askpass_sudo, 'synthetic-password')
    end

    it 'cleans up after a timeout' do
      allow(subject).to receive(:cmd_exec).and_raise(::Timeout::Error)
      expect(subject).to receive(:with_askpass_script).with('synthetic-password').and_yield(askpass_sh)
      expect(subject).to receive(:print_error).with('SUDO: Sudo with a password timed out.')

      subject.send(:askpass_sudo, 'synthetic-password')
    end

    it 'cleans up after an execution error' do
      allow(subject).to receive(:cmd_exec).and_raise(RuntimeError)
      expect(subject).to receive(:with_askpass_script).with('synthetic-password').and_yield(askpass_sh)
      expect(subject).to receive(:print_error).with('SUDO: Sudo with a password failed. Check the session log.')

      subject.send(:askpass_sudo, 'synthetic-password')
    end
  end

  describe '#get_root' do
    it 'does not print the supplied password' do
      secret = 'do-not-log-this'
      subject.datastore['PASSWORD'] = secret
      allow(subject).to receive(:askpass_sudo)
      allow(subject).to receive(:is_root?).and_return(false)

      expect(subject).to receive(:print_status).with('Sudoing with the supplied password.')
      expect(subject).not_to receive(:print_status).with(/#{Regexp.escape(secret)}/)

      subject.send(:get_root)
    end
  end
end
