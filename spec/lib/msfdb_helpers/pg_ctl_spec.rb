require 'spec_helper'
require 'fileutils'
require 'tmpdir'
require 'shellwords'
require 'timeout'
require 'pg'
require 'msfdb_helpers/pg_ctl'

RSpec.describe MsfdbHelpers::PgCtl do
  subject(:driver) do
    described_class.new(db_path: db_path, options: options, localconf: '/unused', db_conf: '/unused/database.yml')
  end

  let(:db_path) { '/database path/with spaces' }
  let(:options) { { db_port: 5433, debug: false } }
  let(:startup_status) { instance_double(Process::Status, success?: true) }
  let(:waiter) { instance_double(Process::Waiter, value: startup_status) }

  before do
    # The command-line entry point defines these states, outside the helper.
    stub_const('DatabaseStatus', Class.new)
    stub_const('DatabaseStatus::RUNNING', 0)
    stub_const('DatabaseStatus::INACTIVE', 1)
    stub_const('DatabaseStatus::NOT_FOUND', 2)
    # msfdb also supplies String color helpers; they are presentation only.
    without_partial_double_verification do
      %i[green red bold].each do |method|
        allow_any_instance_of(String).to receive(method) { |string| string }
      end
    end
  end

  describe '#start' do
    before do
      allow(driver).to receive(:status).and_return(DatabaseStatus::INACTIVE, DatabaseStatus::RUNNING)
      allow(Process).to receive(:spawn).and_return(1234)
      allow(Process).to receive(:detach).with(1234).and_return(waiter)
    end

    it 'passes bounded, literal startup options' do
      expect(Process).to receive(:spawn).with(
        'pg_ctl', '-o', '-p 5433', '-D', db_path, '-l', "#{db_path}/log", '-w', '-t', '60', 'start'
      ).ordered.and_return(1234)
      expect(waiter).to receive(:value).ordered.and_return(startup_status)
      expect(driver.start).to be true
    end

    it 'avoids captured output pipes' do
      expect(driver).not_to receive(:run_cmd)
      expect(driver.start).to be true
    end

    it 'waits for startup completion' do
      waiting = Queue.new
      ready = Queue.new
      allow(waiter).to receive(:value) do
        waiting << true
        ready.pop
        startup_status
      end

      startup = Thread.new { driver.start }
      begin
        Timeout.timeout(5) { waiting.pop }
        expect(startup).to be_alive
        ready << true
        expect(Timeout.timeout(5) { startup.value }).to be true
      ensure
        ready << true
        startup.kill if startup.alive?
        startup.join
      end
    end

    context 'when the postmaster is running but startup has not succeeded' do
      let(:startup_status) { instance_double(Process::Status, success?: false) }

      it 'reports the startup failure' do
        expect(driver.start).to be false
        expect(waiter).to have_received(:value)
        expect(driver).to have_received(:status).once
      end
    end

    context 'when the database was already running' do
      before do
        allow(driver).to receive(:status).and_return(DatabaseStatus::RUNNING)
      end

      it 'does not launch another server' do
        expect(Process).not_to receive(:spawn)
        expect(driver.start).to be true
      end
    end
  end

  describe '#init' do
    around do |example|
      Dir.mktmpdir('pg-ctl-spec') do |directory|
        @temporary_directory = directory
        example.run
      end
    end

    let(:db_path) { File.join(@temporary_directory, 'data') }

    before do
      allow(driver).to receive(:run_cmd).and_return(0)
      allow(driver).to receive(:test_executable_file).and_return(true)
      allow(driver).to receive(:create_db_users)
      allow(driver).to receive(:write_db_client_auth_config)
      allow(driver).to receive(:restart).and_return(true)
    end

    it 'aborts setup when startup fails' do
      allow(driver).to receive(:start).and_return(false)
      expect(driver).not_to receive(:create_db_users)
      expect(driver).not_to receive(:write_db_client_auth_config)
      expect(driver).not_to receive(:restart)

      expect { driver.init('test-password', 'test-password') }.to raise_error(PG::ConnectionBad, /did not become ready/)
    end

    it 'starts before configuring users' do
      expect(driver).to receive(:start).ordered.and_return(true)
      expect(driver).to receive(:create_db_users).with('test-password', 'test-password').ordered
      expect(driver).to receive(:write_db_client_auth_config).ordered
      expect(driver).to receive(:restart).ordered.and_return(true)

      expect(driver.init('test-password', 'test-password')).to be true
    end
  end
end
