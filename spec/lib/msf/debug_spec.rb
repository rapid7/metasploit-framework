require 'spec_helper'
require 'msf/ui/debug'
require 'msf/base/config'
require 'msf/ui/console/driver'

RSpec.describe Msf::Ui::Debug do
  let(:file_fixtures_path) { File.join(Msf::Config.install_root, 'spec', 'file_fixtures') }

  it 'correctly parses an error log' do
    allow(::Msf::Config).to receive(:log_directory).and_return(File.join(file_fixtures_path, 'debug', 'error_logs', 'basic'))

    error_log_output = <<~LOG
      ##  %grnErrors%clr

      The following errors occurred before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      [00/00/0000 00:00:00] [e(0)] core: [-] Error 1

      [11/11/1111 11:11:11] [e(0)] core: [-] Error 2
      Call stack:
      Stack_Trace
      stack trace
      STACK-TRACE

      [22/22/2222 22:22:22] [e(0)] core: [-] Error 3
      ```

      </details>


    LOG

    expect(subject.errors).to eql(error_log_output)
  end

  it 'correctly parses an error log file larger than the log line total' do
    allow(::Msf::Config).to receive(:log_directory).and_return(File.join(file_fixtures_path, 'debug', 'error_logs', 'long'))

    logs = ''
    digits = 11..20

    digits.each do |d|
      logs += "[00/00/0000 00:00:00] [e(0)] core: [-] Error #{d}\n\n"
    end

    error_log_output = <<~LOG
      ##  %grnErrors%clr

      The following errors occurred before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      #{logs.strip}
      ```

      </details>


    LOG

    expect(subject.errors).to eql(error_log_output)
  end

  it 'correctly parses an empty error log file' do
    allow(::Msf::Config).to receive(:log_directory).and_return(File.join(file_fixtures_path, 'debug', 'error_logs', 'empty'))

    error_log_output = <<~EMPTY
      ##  %grnErrors%clr

      The following errors occurred before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      The error log file was empty
      ```

      </details>


    EMPTY

    expect(subject.errors).to eql(error_log_output)
  end

  it 'correctly retrieves and parses a command history shorter than the command total' do
    stub_const('Readline::HISTORY', Array.new(4) { |i| "Command #{i + 1}" })

    driver = instance_double(
      Msf::Ui::Console::Driver,
      hist_last_saved: 0
    )

    stub_const('Msf::Ui::Debug::COMMAND_HISTORY_TOTAL', 10)

    history_output = <<~E_LOG
      ##  %grnHistory%clr

      The following commands were ran during the session and before this issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      0      Command 1
      1      Command 2
      2      Command 3
      3      Command 4
      ```

      </details>


    E_LOG

    expect(subject.history(driver)).to eql(history_output)
  end

  it 'correctly retrieves and parses a command history equal in length to the command total' do
    driver = instance_double(
      ::Msf::Ui::Console::Driver,
      hist_last_saved: 0
    )

    stub_const('Msf::Ui::Debug::COMMAND_HISTORY_TOTAL', 10)

    stub_const('Readline::HISTORY', Array.new(10) { |i| "Command #{i + 1}" })

    history_output = <<~E_LOG
      ##  %grnHistory%clr

      The following commands were ran during the session and before this issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      0      Command 1
      1      Command 2
      2      Command 3
      3      Command 4
      4      Command 5
      5      Command 6
      6      Command 7
      7      Command 8
      8      Command 9
      9      Command 10
      ```

      </details>


    E_LOG

    expect(subject.history(driver)).to eql(history_output)
  end

  it 'correctly retrieves and parses a command history larger than the command total' do
    driver = instance_double(
      ::Msf::Ui::Console::Driver,
      hist_last_saved: 0
    )

    stub_const('Msf::Ui::Debug::COMMAND_HISTORY_TOTAL', 10)
    stub_const('Readline::HISTORY', Array.new(15) { |i| "Command #{i + 1}" })

    history_output = <<~E_LOG
      ##  %grnHistory%clr

      The following commands were ran during the session and before this issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      5      Command 6
      6      Command 7
      7      Command 8
      8      Command 9
      9      Command 10
      10     Command 11
      11     Command 12
      12     Command 13
      13     Command 14
      14     Command 15
      ```

      </details>


    E_LOG

    expect(subject.history(driver)).to eql(history_output)
  end

  it 'correctly retrieves and parses a command history larger than the command total and a session command count smaller than the command total' do
    driver = instance_double(
      ::Msf::Ui::Console::Driver,
      hist_last_saved: 10
    )

    stub_const('Msf::Ui::Debug::COMMAND_HISTORY_TOTAL', 10)
    stub_const('Readline::HISTORY', Array.new(15) { |i| "Command #{i + 1}" })

    history_output = <<~E_LOG
      ##  %grnHistory%clr

      The following commands were ran during the session and before this issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      10     Command 11
      11     Command 12
      12     Command 13
      13     Command 14
      14     Command 15
      ```

      </details>


    E_LOG

    expect(subject.history(driver)).to eql(history_output)
  end

  it 'correctly retrieves and parses an empty config file and datastore' do
    allow(::Msf::Config).to receive(:config_file).and_return(File.join(file_fixtures_path, 'debug', 'config_files', 'empty.ini'))

    framework = instance_double(
      ::Msf::Framework,
      datastore: {}
    )

    driver = instance_double(
      ::Msf::Ui::Console::Driver,
      get_config_core: 'config_core',
      get_config: {},
      get_config_group: 'config_group',
      active_module: nil
    )

    expected_output = <<~OUTPUT
      ##  %grnModule/Datastore%clr

      The following global/module datastore, and database setup was configured before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      The local config file is empty, no global variables are set, and there is no active module.
      ```

      </details>


    OUTPUT

    expect(subject.datastore(framework, driver)).to eql(expected_output)
  end

  it 'correctly retrieves and parses a populated global datastore' do
    allow(::Msf::Config).to receive(:config_file).and_return(File.join(file_fixtures_path, 'debug', 'config_files', 'empty.ini'))

    framework = instance_double(
      ::Msf::Framework,
      datastore: {
        'key1' => 'val1',
        'key2' => 'val2',
        'key3' => 'val3'
      }
    )

    driver = instance_double(
      ::Msf::Ui::Console::Driver,
      get_config_core: 'group/name/1',
      get_config: {},
      get_config_group: 'config_group',
      active_module: nil
    )

    expected_output = <<~OUTPUT
      ##  %grnModule/Datastore%clr

      The following global/module datastore, and database setup was configured before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      [group/name/1]
      key1=val1
      key2=val2
      key3=val3
      ```

      </details>


    OUTPUT

    expect(subject.datastore(framework, driver)).to eql(expected_output)
  end

  it 'correctly retrieves and parses a populated global datastore and current module' do
    allow(::Msf::Config).to receive(:config_file).and_return(File.join(file_fixtures_path, 'debug', 'config_files', 'empty.ini'))

    framework = instance_double(
      ::Msf::Framework,
      datastore: {
        'key1' => 'val1',
        'key2' => 'val2',
        'key3' => 'val3'
      }
    )

    driver = instance_double(
      ::Msf::Ui::Console::Driver,
      get_config_core: 'group/name/1',
      get_config: {
        'key4' => 'val4',
        'key5' => 'val5',
        'key6' => 'val6'
      },
      get_config_group: 'group/name/2',
      active_module: nil
    )

    expected_output = <<~OUTPUT
      ##  %grnModule/Datastore%clr

      The following global/module datastore, and database setup was configured before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      [group/name/1]
      key1=val1
      key2=val2
      key3=val3

      [group/name/2]
      key4=val4
      key5=val5
      key6=val6
      ```

      </details>


    OUTPUT

    expect(subject.datastore(framework, driver)).to eql(expected_output)
  end

  it 'correctly retrieves and parses active module variables' do
    allow(::Msf::Config).to receive(:config_file).and_return(File.join(file_fixtures_path, 'debug', 'config_files', 'empty.ini'))

    framework = instance_double(
      ::Msf::Framework,
      datastore: {}
    )

    active_module = instance_double(
      Msf::Module,
      datastore: {
        'key7' => 'val7',
        'key8' => 'default_val8',
        'key9' => 'val9'
      },
      refname: 'active/module/variables'
    )

    driver = instance_double(
      ::Msf::Ui::Console::Driver,
      get_config_core: 'group/name/1',
      get_config: {},
      get_config_group: 'config_group',
      active_module: active_module
    )

    expected_output = <<~OUTPUT
      ##  %grnModule/Datastore%clr

      The following global/module datastore, and database setup was configured before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      [active/module/variables]
      key7=val7
      key8=default_val8
      key9=val9
      ```

      </details>


    OUTPUT

    expect(subject.datastore(framework, driver)).to eql(expected_output)
  end

  it 'preferences the framework datastore values over config stored values' do
    allow(::Msf::Config).to receive(:config_file).and_return(File.join(file_fixtures_path, 'debug', 'config_files', 'module.ini'))

    framework = instance_double(
      ::Msf::Framework,
      datastore: {
        'key1' => 'val1',
        'key2' => 'val2',
        'key3' => 'val3'
      }
    )

    driver = instance_double(
      ::Msf::Ui::Console::Driver,
      get_config_core: 'group/name/1',
      get_config: {
        'key4' => 'val4',
        'key5' => 'val5',
        'key6' => 'val6'
      },
      get_config_group: 'group/name/2',
      active_module: nil
    )

    expected_output = <<~OUTPUT
      ##  %grnModule/Datastore%clr

      The following global/module datastore, and database setup was configured before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      [group/name/1]
      key1=val1
      key2=val2
      key3=val3

      [group/name/2]
      key4=val4
      key5=val5
      key6=val6
      ```

      </details>


    OUTPUT

    expect(subject.datastore(framework, driver)).to eql(expected_output)
  end

  it 'correctly retrieves and parses Database information' do
    allow(::Msf::Config).to receive(:config_file).and_return(File.join(file_fixtures_path, 'debug', 'config_files', 'db.ini'))

    framework = instance_double(
      ::Msf::Framework,
      datastore: {}
    )

    driver = instance_double(
      ::Msf::Ui::Console::Driver,
      get_config_core: 'group/name/1',
      get_config: {},
      get_config_group: 'group/name/2',
      active_module: nil
    )

    expected_output = <<~OUTPUT
      ##  %grnModule/Datastore%clr

      The following global/module datastore, and database setup was configured before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      [framework/database/1]
      key10=[Filtered]
      key11=[Filtered]

      [framework/database/2]
      key12=[Filtered]
      key13=[Filtered]
      ```

      </details>


    OUTPUT

    expect(subject.datastore(framework, driver)).to eql(expected_output)
  end

  it 'correctly retrieves and parses logs shorter than the log line total' do
    range = 1..30
    logs = ''
    range.each do |i|
      logs += "[00/00/0000 00:00:00] [e(0)] core: Log Line #{i}\n"
    end

    allow(::Msf::Config).to receive(:log_directory).and_return(File.join(file_fixtures_path, 'debug', 'framework_logs', 'short'))

    error_log_output = <<~E_LOG
      ##  %grnLogs%clr

      The following logs were recorded before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      #{logs.strip}
      ```

      </details>


    E_LOG

    expect(subject.logs).to eql(error_log_output)
  end

  it 'correctly retrieves and parses logs equal to the log line total' do
    range = 1..50
    logs = ''
    range.each do |i|
      logs += "[00/00/0000 00:00:00] [e(0)] core: Log Line #{i}\n"
    end

    allow(::Msf::Config).to receive(:log_directory).and_return(File.join(file_fixtures_path, 'debug', 'framework_logs', 'equal'))

    error_log_output = <<~E_LOG
      ##  %grnLogs%clr

      The following logs were recorded before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      #{logs.strip}
      ```

      </details>


    E_LOG

    expect(subject.logs).to eql(error_log_output)
  end

  it 'correctly retrieves and parses logs larger than the log line total' do
    range = 51..100
    logs = ''
    range.each do |i|
      logs += "[00/00/0000 00:00:00] [e(0)] core: Log Line #{i}\n"
    end

    allow(::Msf::Config).to receive(:log_directory).and_return(File.join(file_fixtures_path, 'debug', 'framework_logs', 'long'))

    error_log_output = <<~E_LOG
      ##  %grnLogs%clr

      The following logs were recorded before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      #{logs.strip}
      ```

      </details>


    E_LOG

    expect(subject.logs).to eql(error_log_output)
  end

  it 'correctly retrieves and parses an empty log file' do
    allow(::Msf::Config).to receive(:log_directory).and_return(File.join(file_fixtures_path, 'debug', 'framework_logs', 'empty'))

    error_log_output = <<~E_LOG
      ##  %grnLogs%clr

      The following logs were recorded before the issue occurred:
      <details>
      <summary>Collapse</summary>

      ```
      
      ```

      </details>


    E_LOG

    expect(subject.logs).to eql(error_log_output)
  end

  it 'correctly retrieves version information with no connected DB' do
    db = instance_double(
      Msf::DBManager,
      connection_established?: false,
      driver: 'driver'
    )

    framework = instance_double(
      ::Msf::Framework,
      version: 'VERSION',
      db: db
    )

    allow(::Msf::Config).to receive(:install_root).and_return('bad/path')

    expected_output = <<~OUTPUT
      ##  %grnVersion/Install%clr

      The versions and install method of your Metasploit setup:
      <details>
      <summary>Collapse</summary>

      ```
      Framework: VERSION
      Ruby: #{RUBY_DESCRIPTION}
      Install Root: bad/path
      Session Type: driver selected, no connection
      Install Method: Other - Please specify
      ```

      </details>


    OUTPUT

    expect(subject.versions(framework)).to eql(expected_output)
  end

  it 'correctly retrieves version information with DB connected via http' do
    db = double(
      'Metasploit::Framework::DataService::DataProxy',
      name: 'db_name',
      driver: 'http',
      connection_established?: true,
      get_data_service: 'db_data_service'
    )

    framework = instance_double(
      ::Msf::Framework,
      version: 'VERSION',
      db: db
    )

    allow(::Msf::Config).to receive(:install_root).and_return('bad/path')

    expected_output = <<~OUTPUT
      ##  %grnVersion/Install%clr

      The versions and install method of your Metasploit setup:
      <details>
      <summary>Collapse</summary>

      ```
      Framework: VERSION
      Ruby: #{RUBY_DESCRIPTION}
      Install Root: bad/path
      Session Type: Connected to db_name. Connection type: http. Connection name: db_data_service.
      Install Method: Other - Please specify
      ```

      </details>


    OUTPUT

    expect(subject.versions(framework)).to eql(expected_output)
  end

  it 'correctly retrieves version information with DB connected via local connection' do
    db = double(
      'Metasploit::Framework::DataService::DataProxy',
      connection_established?: true,
      driver: 'local',
      get_data_service: 'db_data_service'
    )

    framework = instance_double(
      ::Msf::Framework,
      version: 'VERSION',
      db: db
    )

    connection_pool = instance_double(ActiveRecord::ConnectionAdapters::ConnectionPool)
    connection = double(
      'connection',
      current_database: 'current_db_connection',
      respond_to?: true
    )
    allow(connection_pool).to receive(:with_connection).and_yield(connection)

    allow(::ActiveRecord::Base).to receive(:connection_pool).and_return(connection_pool)
    allow(::Msf::Config).to receive(:install_root).and_return('bad/path')

    expected_output = <<~OUTPUT
      ##  %grnVersion/Install%clr

      The versions and install method of your Metasploit setup:
      <details>
      <summary>Collapse</summary>

      ```
      Framework: VERSION
      Ruby: #{RUBY_DESCRIPTION}
      Install Root: bad/path
      Session Type: Connected to current_db_connection. Connection type: local. Connection name: db_data_service.
      Install Method: Other - Please specify
      ```

      </details>


    OUTPUT

    expect(subject.versions(framework)).to eql(expected_output)
  end

  it 'correctly retrieves version information with no connected DB and a Kali Install' do
    db = instance_double(
      Msf::DBManager,
      connection_established?: false,
      driver: 'driver'
    )

    framework = instance_double(
      ::Msf::Framework,
      version: 'VERSION',
      db: db
    )

    allow(::Msf::Config).to receive(:install_root).and_return(File.join(File::SEPARATOR, 'usr', 'share', 'metasploit-framework'))

    expected_output = <<~OUTPUT
      ##  %grnVersion/Install%clr

      The versions and install method of your Metasploit setup:
      <details>
      <summary>Collapse</summary>

      ```
      Framework: VERSION
      Ruby: #{RUBY_DESCRIPTION}
      Install Root: #{File.join(File::SEPARATOR, 'usr', 'share', 'metasploit-framework')}
      Session Type: driver selected, no connection
      Install Method: Other - Please specify
      ```

      </details>


    OUTPUT

    expect(subject.versions(framework)).to eql(expected_output)
  end

  it 'correctly retrieves version information with no connected DB and an Omnibus Install' do
    db = instance_double(
      Msf::DBManager,
      connection_established?: false,
      driver: 'driver'
    )

    framework = instance_double(
      ::Msf::Framework,
      version: 'VERSION',
      db: db
    )

    allow(::Msf::Config).to receive(:install_root).and_return(File.join(file_fixtures_path, 'debug', 'installs', 'omnibus'))

    expected_output = <<~OUTPUT
      ##  %grnVersion/Install%clr

      The versions and install method of your Metasploit setup:
      <details>
      <summary>Collapse</summary>

      ```
      Framework: VERSION
      Ruby: #{RUBY_DESCRIPTION}
      Install Root: #{File.join(file_fixtures_path, 'debug', 'installs', 'omnibus')}
      Session Type: driver selected, no connection
      Install Method: Omnibus Installer
      ```

      </details>


    OUTPUT

    expect(subject.versions(framework)).to eql(expected_output)
  end

  it 'correctly retrieves version information with no connected DB and a Git Clone' do
    db = instance_double(
      Msf::DBManager,
      connection_established?: false,
      driver: 'driver'
    )

    framework = instance_double(
      ::Msf::Framework,
      version: 'VERSION',
      db: db
    )

    allow(::Msf::Config).to receive(:install_root).and_return(File.join(file_fixtures_path, 'debug', 'installs'))
    allow(File).to receive(:directory?).with(File.join(Msf::Config.install_root, '.git')).and_return(true)

    expected_output = <<~OUTPUT
      ##  %grnVersion/Install%clr

      The versions and install method of your Metasploit setup:
      <details>
      <summary>Collapse</summary>

      ```
      Framework: VERSION
      Ruby: #{RUBY_DESCRIPTION}
      Install Root: #{File.join(file_fixtures_path, 'debug', 'installs')}
      Session Type: driver selected, no connection
      Install Method: Git Clone
      ```

      </details>


    OUTPUT

    expect(subject.versions(framework)).to eql(expected_output)
  end

  it 'correctly retrieves version information with no connected DB and a Arch Pacman install' do
    db = instance_double(
      Msf::DBManager,
      connection_established?: false,
      driver: 'driver'
    )

    framework = instance_double(
      ::Msf::Framework,
      version: 'VERSION',
      db: db
    )

    allow(::Msf::Config).to receive(:install_root).times.and_return(File.join(File::SEPARATOR, 'opt', 'metasploit'))

    expected_output = <<~OUTPUT
      ##  %grnVersion/Install%clr

      The versions and install method of your Metasploit setup:
      <details>
      <summary>Collapse</summary>

      ```
      Framework: VERSION
      Ruby: #{RUBY_DESCRIPTION}
      Install Root: #{File.join(File::SEPARATOR, 'opt', 'metasploit')}
      Session Type: driver selected, no connection
      Install Method: Other - Please specify
      ```

      </details>


    OUTPUT

    expect(subject.versions(framework)).to eql(expected_output)
  end
end
