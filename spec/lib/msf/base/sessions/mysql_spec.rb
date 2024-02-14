# frozen_string_literal: true

require 'spec_helper'
require 'mysql'

RSpec.describe Msf::Sessions::MySQL do
  let(:rstream) { instance_double(::Rex::Socket) }
  let(:client) { instance_double(::Mysql) }
  let(:opts) { { client: client } }
  let(:console_class) { Rex::Post::MySQL::Ui::Console }
  let(:user_input) { instance_double(Rex::Ui::Text::Input::Readline) }
  let(:user_output) { instance_double(Rex::Ui::Text::Output::Stdio) }
  let(:name) { 'mysql' }
  let(:log_source) { "session_#{name}" }
  let(:type) { 'mysql' }
  let(:description) { 'MySQL' }
  let(:can_cleanup_files) { false }
  let(:address) { '192.0.2.1' }
  let(:port) { '3306' }
  let(:peerinfo) { "#{address}:#{port}" }
  let(:database) { 'database_name' }

  before(:each) do
    allow(user_input).to receive(:output=)
    allow(user_input).to receive(:intrinsic_shell?).and_return(true)
    allow(rstream).to receive(:peerinfo).and_return(peerinfo)
    allow(client).to receive(:socket).and_return(rstream)
    allow(client).to receive(:database).and_return(database)
    allow(::Mysql).to receive(:connect).and_return(client)
  end

  subject(:session) do
    mysql_session = described_class.new(rstream, opts)
    mysql_session.user_input = user_input
    mysql_session.user_output = user_output
    mysql_session.name = name
    mysql_session
  end

  describe '.type' do
    it 'should have the correct type' do
      expect(described_class.type).to eq(type)
    end
  end

  describe '.can_cleanup_files' do
    it 'should be able to cleanup files' do
      expect(described_class.can_cleanup_files).to eq(can_cleanup_files)
    end
  end

  describe '#desc' do
    it 'should have the correct description' do
      expect(subject.desc).to eq(description)
    end
  end

  describe '#type' do
    it 'should have the correct type' do
      expect(subject.type).to eq(type)
    end
  end

  describe '#initialize' do
    context 'without a client' do
      let(:opts) { {} }

      it 'raises a KeyError' do
        expect { subject }.to raise_exception(KeyError)
      end
    end
    context 'with a client' do
      it 'does not raise an exception' do
        expect { subject }.not_to raise_exception
      end
    end

    it 'creates a new console' do
      expect(subject.console).to be_a(console_class)
    end
  end

  describe '#bootstrap' do
    subject { session.bootstrap }

    it 'keeps the sessions user input' do
      expect { subject }.not_to change(session, :user_input).from(user_input)
    end

    it 'keeps the sessions user output' do
      expect { subject }.not_to change(session, :user_output).from(user_output)
    end

    it 'sets the console input' do
      expect { subject }.to change(session.console, :input).to(user_input)
    end

    it 'sets the console output' do
      expect { subject }.to change(session.console, :output).to(user_output)
    end

    it 'sets the log source' do
      expect { subject }.to change(session.console, :log_source).to(log_source)
    end
  end

  describe '#reset_ui' do
    before(:each) do
      session.bootstrap
    end

    subject { session.reset_ui }

    it 'keeps the sessions user input' do
      expect { subject }.not_to change(session, :user_input).from(user_input)
    end

    it 'keeps the sessions user output' do
      expect { subject }.not_to change(session, :user_output).from(user_output)
    end

    it 'resets the console input' do
      expect { subject }.to change(session.console, :input).from(user_input).to(nil)
    end

    it 'resets the console output' do
      expect { subject }.to change(session.console, :output).from(user_output).to(nil)
    end
  end

  describe '#exit' do
    subject { session.exit }

    it 'exits the session' do
      expect { subject }.to change(session.console, :stopped?).from(false).to(true)
    end
  end

  describe '#address' do
    subject { session.address }

    it { is_expected.to eq(address) }
  end

  describe '#port' do
    subject { session.port }

    it { is_expected.to eq(port) }
  end
end
