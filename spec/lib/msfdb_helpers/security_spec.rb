require 'fileutils'
require 'rspec'
require 'rbconfig'
require 'msfdb_helpers/db_interface'

RSpec.describe MsfdbHelpers::DbInterface do
  let(:options) do
    { msf_db_name: 'msf', msf_db_user: 'msf', msftest_db_name: 'msftest', msftest_db_user: 'msftest' }
  end
  let(:expected_rules) do
    <<~HBA.lines.map(&:split)
      local "msf" "msf" md5
      host "msf" "msf" 127.0.0.1/32 md5
      host "msf" "msf" ::1/128 md5
      local "msftest" "msftest" md5
      host "msftest" "msftest" 127.0.0.1/32 md5
      host "msftest" "msftest" ::1/128 md5
      local "postgres" "msftest" md5
      host "postgres" "msftest" 127.0.0.1/32 md5
      host "postgres" "msftest" ::1/128 md5
    HBA
  end

  def generated_rules
    described_class.new(options).authentication_config.lines.reject { |line| line.start_with?('#') }.map(&:split).reject(&:empty?)
  end

  it 'only permits the application database/role pairs with passwords over sockets and loopback on Unix' do
    allow(Gem).to receive(:win_platform?).and_return(false)
    expect(generated_rules).to eq(expected_rules)
  end

  it 'only emits the password-protected loopback rules on Windows' do
    allow(Gem).to receive(:win_platform?).and_return(true)
    expect(generated_rules).to eq(expected_rules.reject { |rule| rule.first == 'local' })
  end

  it 'rejects database names that PostgreSQL would interpret as HBA regular expressions' do
    options[:msf_db_name] = '/.*'
    expect { generated_rules }.to raise_error(ArgumentError, /leading slash/)
  end

  it 'rejects role names that PostgreSQL would interpret as HBA regular expressions' do
    options[:msf_db_user] = '/.*'
    expect { generated_rules }.to raise_error(ArgumentError, /leading slash/)
  end

  it 'accepts database and role names at the 63-byte identifier limit' do
    options[:msf_db_name] = 'd' * 63
    options[:msf_db_user] = ('é' * 31) + 'r'
    expect { generated_rules }.not_to raise_error
  end

  it 'rejects database names that PostgreSQL would truncate' do
    options[:msf_db_name] = 'd' * 64
    expect { generated_rules }.to raise_error(ArgumentError, /63 bytes/)
  end

  it 'measures the role identifier limit in bytes rather than characters' do
    options[:msf_db_user] = 'é' * 32
    expect { generated_rules }.to raise_error(ArgumentError, /63 bytes/)
  end

  describe '#run_cmd' do
    let(:driver) { described_class.new(options) }
    let(:failure_command) { [RbConfig.ruby, '-e', '$stderr.puts "migration failed"; exit 7'] }

    it 'prints captured output on failure when requested' do
      result = nil
      expect { result = driver.run_cmd(failure_command, show_output_on_failure: true) }.to output("migration failed\n").to_stderr
      expect(result).to eq(7)
    end

    it 'keeps captured output quiet on success' do
      command = [RbConfig.ruby, '-e', '$stderr.puts "migration succeeded"']
      expect { driver.run_cmd(command, show_output_on_failure: true) }.not_to output.to_stderr
    end

    it 'keeps failure output quiet by default' do
      expect { driver.run_cmd(failure_command) }.not_to output.to_stderr
    end
  end

  describe '#migrate_database' do
    around do |example|
      schema = ENV.delete('SCHEMA')
      example.run
    ensure
      ENV['SCHEMA'] = schema
    end

    it 'uses the generated database configuration and excludes conflicting connection overrides' do
      driver = described_class.new(options)
      expect(driver).to receive(:run_cmd).with(
        ['bundle', 'exec', 'rake', 'db:migrate'],
        env: {
          'MSF_DATABASE_CONFIG' => '/example/database.yml',
          'SCHEMA' => '/example/schema.rb',
          'RAILS_ENV' => 'development',
          'DATABASE_URL' => nil,
          'PRIMARY_DATABASE_URL' => nil,
          'PGHOSTADDR' => nil,
          'PGSERVICE' => nil,
          'PGSERVICEFILE' => nil,
          'PGOPTIONS' => nil
        },
        show_output_on_failure: true
      ).and_return(0)

      expect(driver.migrate_database('/example/database.yml')).to eq(0)
    end

    it 'prints the migration error when the command fails' do
      original_path = ENV['PATH']
      skip 'A Unix shell is required for the test command' if Gem.win_platform?

      driver = described_class.new(options)
      Dir.mktmpdir('msfdb-migration-spec-') do |directory|
        executable = File.join(directory, 'bundle')
        File.write(executable, "#!/bin/sh\nprintf 'migration failed\\n' >&2\nexit 7\n")
        File.chmod(0o700, executable)
        ENV['PATH'] = directory

        result = nil
        expect { result = driver.migrate_database('/example/database.yml') }.to output("migration failed\n").to_stderr
        expect(result).to eq(7)
      end
    ensure
      ENV['PATH'] = original_path
    end

    it 'isolates connection settings while preserving an explicit schema destination' do
      keys = %w[PATH SCHEMA MSF_DATABASE_CONFIG RAILS_ENV DATABASE_URL PRIMARY_DATABASE_URL PGHOSTADDR PGSERVICE PGSERVICEFILE PGOPTIONS]
      original = keys.to_h { |key| [key, ENV[key]] }
      skip 'A Unix shell is required for the test command' if Gem.win_platform?

      Dir.mktmpdir('msfdb-migration-spec-') do |directory|
        executable = File.join(directory, 'bundle')
        script = <<~SH
          #!/bin/sh
          [ "$MSF_DATABASE_CONFIG" = '/example/database.yml' ] || exit 1
          [ "$RAILS_ENV" = 'development' ] || exit 2
          [ "$SCHEMA" = 'unrelated' ] || exit 4
          [ -z "${DATABASE_URL+x}${PRIMARY_DATABASE_URL+x}${PGHOSTADDR+x}${PGSERVICE+x}${PGSERVICEFILE+x}${PGOPTIONS+x}" ] || exit 3
        SH
        File.write(executable, script)
        File.chmod(0o700, executable)
        keys.each { |key| ENV[key] = 'unrelated' }
        ENV['PATH'] = directory

        expect(described_class.new(options).migrate_database('/example/database.yml')).to eq(0)
      end
    ensure
      original&.each { |key, value| ENV[key] = value }
    end
  end

  describe 'private file publication' do
    let(:root) { Dir.mktmpdir('msfdb-file-spec-') }
    let(:db_conf) { File.join(root, 'database.yml') }
    let(:driver) { described_class.new(options) }

    after { FileUtils.remove_entry(root) }

    it 'applies the Windows ACL to an empty staging directory before writing credentials' do
      allow(Gem).to receive(:win_platform?).and_return(true)
      allow(driver).to receive(:windows_sid).and_return('S-1-5-21-1000')
      allow(driver).to receive(:run_cmd) do |arguments|
        if File.directory?(arguments[1])
          expect(Dir.children(arguments[1])).to be_empty
          expect(arguments).to include('/inheritance:r', '*S-1-5-21-1000:(OI)(CI)F')
        else
          expect(File.size(arguments[1])).to eq(0)
          expect(arguments).to include('/inheritance:r', '*S-1-5-21-1000:F')
        end
        0
      end

      driver.write_private_file(db_conf, 'credential')
      expect(File.read(db_conf)).to eq('credential')
    end

    it 'does not publish credentials if the Windows file ACL cannot be protected' do
      allow(Gem).to receive(:win_platform?).and_return(true)
      allow(driver).to receive(:windows_sid).and_return('S-1-5-21-1000')
      allow(driver).to receive(:run_cmd) { |arguments| File.directory?(arguments[1]) ? 0 : 1 }

      expect { driver.write_private_file(db_conf, 'credential') }.to raise_error(MsfdbHelpers::SecurityError, /credential file/)
      expect(File).not_to exist(db_conf)
    end
  end
end
