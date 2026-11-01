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
    stub_const('DatabaseStatus::NEEDS_INIT', 3)
    # msfdb also supplies String color helpers; they are presentation only.
    without_partial_double_verification do
      %i[green red bold].each do |method|
        allow_any_instance_of(String).to receive(method) { |string| string }
      end
    end
  end

  describe '#start' do
    before do
      allow(driver).to receive(:running?).and_return(false)
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
        expect(driver).to have_received(:running?).once
      end
    end

    context 'when the database was already running' do
      before do
        allow(driver).to receive(:running?).and_return(true)
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
    end

    it 'aborts setup when startup fails' do
      allow(driver).to receive(:start_database).and_return(false)
      expect(driver).not_to receive(:create_db_users)
      expect(driver).to receive(:write_db_client_auth_config)
      expect(driver).not_to receive(:restart)

      expect { driver.init('test-password', 'test-password') }.to raise_error(PG::ConnectionBad, /did not become ready/)
    end

    it 'starts before configuring users' do
      expect(driver).to receive(:write_db_client_auth_config).ordered
      expect(driver).to receive(:start_database).ordered.and_return(true)
      expect(driver).to receive(:create_db_users).with('test-password', 'test-password').ordered
      expect(driver).not_to receive(:restart)

      expect(driver.init('test-password', 'test-password')).to be true
    end

    it 'leaves failed startup distinguishable from an existing database' do
      allow(driver).to receive(:start_database).and_return(false)
      expect { driver.init('password', 'password') }.to raise_error(PG::ConnectionBad)
      expect(driver.status).to eq(DatabaseStatus::NEEDS_INIT)
    end

    it 'does not overwrite an unmarked existing data directory' do
      Dir.mkdir(db_path)
      File.write(File.join(db_path, 'existing-data'), 'preserve')
      expect(driver).not_to receive(:run_cmd)
      expect { driver.init('password', 'password') { raise 'must not write config' } }.to raise_error(Errno::EEXIST)
      expect(File.read(File.join(db_path, 'existing-data'))).to eq('preserve')
    end

    it 'yields configuration only after claiming the cluster and before provisioning' do
      allow(driver).to receive(:start_database).and_return(true)
      configured = false
      expect(driver).to receive(:create_db_users) { expect(configured).to be true }
      driver.init('password', 'password') do
        expect(driver.initialization_pending?).to be true
        configured = true
      end
    end

    it 'does not start a cluster after initdb fails' do
      allow(driver).to receive(:run_cmd).and_return(1)
      expect(driver).not_to receive(:start_database)
      expect { driver.init('password', 'password') }.to raise_error(PG::ConnectionBad, /Could not initialize/)
      expect(driver.status).to eq(DatabaseStatus::NEEDS_INIT)
      expect { driver.init('password', 'password') }.to raise_error(PG::ConnectionBad, /did not finish/)
    end

    context 'with an interrupted initialization' do
      before do
        Dir.mkdir(db_path)
        File.write("#{db_path}.initializing", 'setup')
      end

      it 'does not allow start or restart to bypass initialization' do
        allow(driver).to receive(:stop)
        without_partial_double_verification do
          allow(driver).to receive(:print_error)
        end
        expect(driver).not_to receive(:start_database)
        expect(driver.start).to be false
        expect(driver.restart).to be false
      end

      it 'stops the incomplete server before replacing its configuration' do
        allow(driver).to receive(:running?).and_return(true)
        expect(driver).to receive(:stop).ordered.and_return(0)
        expect(driver).to receive(:write_db_client_auth_config).ordered
        expect(driver).to receive(:start_database).ordered.and_return(true)
        expect(driver).to receive(:create_db_users).ordered
        driver.init('password', 'password')
      end

      it 'preserves the marker when the incomplete server cannot stop' do
        allow(driver).to receive(:running?).and_return(true)
        allow(driver).to receive(:stop).and_return(1)
        expect(driver).not_to receive(:write_db_client_auth_config)
        expect { driver.init('password', 'password') }.to raise_error(PG::ConnectionBad, /Could not stop/)
        expect(driver.initialization_pending?).to be true
      end

      it 'resumes a stopped incomplete cluster without running initdb again' do
        allow(driver).to receive(:running?).and_return(false)
        allow(driver).to receive(:start_database).and_return(true)
        expect(driver).not_to receive(:run_cmd)
        expect(driver.init('password', 'password')).to be true
      end
    end

    describe '#with_initialization' do
      before do
        Dir.mkdir(db_path)
        File.write("#{db_path}.initializing", 'setup')
      end

      it 'keeps the marker until the caller finishes configuration and migrations' do
        driver.with_initialization do
          expect(driver.initialization_pending?).to be true
        end
        expect(driver.initialization_pending?).to be false
      end

      it 'preserves the marker on a caller failure and releases the lock for retry' do
        expect { driver.with_initialization { raise PG::Error, 'migration failed' } }.to raise_error(PG::Error)
        expect(driver.initialization_pending?).to be true
        driver.with_initialization { nil }
        expect(driver.initialization_pending?).to be false
      end

      it 'rejects concurrent initialization without clearing the marker' do
        other_driver = described_class.new(db_path: db_path, options: options, localconf: '/unused', db_conf: '/unused/database.yml')
        driver.with_initialization do
          expect { other_driver.with_initialization { raise 'must not enter' } }.to raise_error(PG::ConnectionBad, /already in progress/)
          expect(driver.initialization_pending?).to be true
        end
      end
    end
  end

  describe '#create_db_users' do
    let(:options) do
      { db_port: 5433, msf_db_user: 'msf', msftest_db_user: 'msftest', msf_db_name: 'msf', msftest_db_name: 'msftest' }
    end
    let(:admin) { instance_double(PG::Connection) }
    let(:application) { instance_double(PG::Connection) }

    before do
      allow(PG).to receive(:connect).with(host: db_path, dbname: 'postgres', port: 5433, user: 'postgres').and_yield(admin)
      allow(PG).to receive(:connect).with(host: db_path, dbname: 'postgres', port: 5433, user: 'msf', password: 'new-password').and_yield(application)
      [admin, application].each do |connection|
        allow(connection).to receive(:quote_ident) { |value| PG::Connection.quote_ident(value) }
        allow(connection).to receive(:exec)
      end
      allow(admin).to receive(:escape_literal).with('new-password').and_return("'new-password'")
      allow(admin).to receive(:exec_params).and_return([])
      allow(application).to receive(:exec_params).and_return([])
    end

    it 'creates both databases as the application role' do
      expect(application).to receive(:exec).with('CREATE DATABASE "msf"')
      expect(application).to receive(:exec).with('CREATE DATABASE "msftest"')
      driver.create_db_users('new-password', 'new-password')
    end

    it 'updates passwords and preserves databases already created by an interrupted attempt' do
      allow(admin).to receive(:exec_params).and_return([{ 'exists' => '1' }])
      allow(application).to receive(:exec_params).and_return([{ 'exists' => '1' }])
      expect(admin).not_to receive(:exec).with(/CREATE ROLE/)
      expect(admin).to receive(:exec).with('ALTER ROLE "msf" LOGIN CREATEDB PASSWORD \'new-password\'')
      expect(admin).to receive(:exec).with('ALTER ROLE "msftest" LOGIN CREATEDB PASSWORD \'new-password\'')
      expect(application).not_to receive(:exec)
      driver.create_db_users('new-password', 'new-password')
    end

    it 'propagates provisioning failures instead of reporting success' do
      allow(admin).to receive(:exec).and_raise(PG::Error, 'role creation failed')
      expect { driver.create_db_users('new-password', 'new-password') }.to raise_error(PG::Error, /role creation failed/)
    end
  end
end
