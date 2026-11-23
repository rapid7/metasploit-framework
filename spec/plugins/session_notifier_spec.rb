# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require_relative '../../plugins/session_notifier'

RSpec.describe Msf::Plugin::SessionNotifier::SessionNotifierCommandDispatcher do
  subject(:dispatcher) { described_class.allocate }

  let(:settings) do
    {
      'smtp_address' => 'smtp.example.invalid',
      'smtp_port' => '2525',
      'smtp_username' => 'fixture-user',
      'smtp_password' => 'fixture-password',
      'smtp_from' => 'test@example.invalid',
      'sms_number' => '0102030405',
      'sms_carrier' => 'fixture'
    }
  end

  around do |example|
    Dir.mktmpdir do |directory|
      @path = File.join(directory, 'config')
      example.run
    end
  end

  before do
    config = Rex::Parser::Ini.new
    config['SessionNotifier'] = settings
    config.to_file(@path)
    allow(Msf::Config).to receive(:config_file).and_return(@path)
    allow(dispatcher).to receive(:print_status)

    first_read = true
    allow(IO).to receive(:readlines).and_call_original
    allow(IO).to receive(:readlines).with(@path).and_wrap_original do |read, *args|
      if first_read
        first_read = false
        raise Errno::EIO, @path
      end

      read.call(*args)
    end
    dispatcher.send(:load_settings_from_config)
  end

  it 'keeps all stored settings if the initial load failed' do
    dispatcher.cmd_save_session_notifier_settings

    expect(Rex::Parser::Ini.new(@path)['SessionNotifier']).to eq(settings)
  end

  it 'changes only the setting explicitly assigned after the failed load' do
    dispatcher.cmd_set_session_smtp_address('updated.example.invalid')
    dispatcher.cmd_save_session_notifier_settings

    expect(Rex::Parser::Ini.new(@path)['SessionNotifier']).to eq(settings.merge('smtp_address' => 'updated.example.invalid'))
  end

  it 'clears a setting explicitly assigned an empty value without removing other settings' do
    dispatcher.cmd_set_session_smtp_username('')
    dispatcher.cmd_save_session_notifier_settings

    expect(Rex::Parser::Ini.new(@path)['SessionNotifier']).to eq(settings.except('smtp_username'))
  end
end
