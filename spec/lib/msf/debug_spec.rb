require 'spec_helper'

RSpec.describe Msf::Ui::Debug do
  let(:file_fixtures_path) { File.join(Msf::Config.install_root, 'spec', 'file_fixtures') }

  it 'error parsing correctly parses framework.log and msf-ws.log' do
    allow(::Msf::Config).to receive(:log_directory).and_return(Pathname.new(file_fixtures_path).join('debug', 'error_logs', 'basic'))

    error_log_output = <<~LOG
      ##  %grnFramework Errors%clr
      
      The following framework errors occurred before the issue occurred:
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
      
      
      ##  %grnWeb Service Errors%clr
      
      The following web service errors occurred before the issue occurred:
      <details>
      <summary>Collapse</summary>
      
      ```
      [-] Error 1
      
      [-] Error 2
      [-] Error 3
      ```
      
      </details>
      

    LOG

    expect(subject.errors).to eql(error_log_output)
  end

  it 'error parsing correctly parses log files larger than the log line total' do
    allow(::Msf::Config).to receive(:log_directory).and_return(File.join(file_fixtures_path, 'debug', 'error_logs', 'long'))

    logs = ''
    digits = 11..20

    digits.each do |d|
      logs += "[00/00/0000 00:00:00] [e(0)] core: [-] Error #{d}\n\n"
    end

    error_log_output = <<~LOG
      ##  %grnFramework Errors%clr
      
      The following framework errors occurred before the issue occurred:
      <details>
      <summary>Collapse</summary>
      
      ```
      [00/00/0000 00:00:00] [e(0)] core: [-] Error 11
      
      [00/00/0000 00:00:00] [e(0)] core: [-] Error 12
      
      [00/00/0000 00:00:00] [e(0)] core: [-] Error 13
      
      [00/00/0000 00:00:00] [e(0)] core: [-] Error 14
      
      [00/00/0000 00:00:00] [e(0)] core: [-] Error 15
      
      [00/00/0000 00:00:00] [e(0)] core: [-] Error 16
      
      [00/00/0000 00:00:00] [e(0)] core: [-] Error 17
      
      [00/00/0000 00:00:00] [e(0)] core: [-] Error 18
      
      [00/00/0000 00:00:00] [e(0)] core: [-] Error 19
      
      [00/00/0000 00:00:00] [e(0)] core: [-] Error 20
      ```
      
      </details>
      
      
      ##  %grnWeb Service Errors%clr
      
      The following web service errors occurred before the issue occurred:
      <details>
      <summary>Collapse</summary>
      
      ```
      [-] Error 11
      
      [-] Error 12
      
      [-] Error 13
      
      [-] Error 14
      
      [-] Error 15
      
      [-] Error 16
      
      [-] Error 17
      
      [-] Error 18
      
      [-] Error 19
      
      [-] Error 20
      ```
      
      </details>


    LOG

    expect(subject.errors).to eql(error_log_output)
  end

  it 'error parsing correctly parses empty log files' do
    allow(::Msf::Config).to receive(:log_directory).and_return(File.join(file_fixtures_path, 'debug', 'error_logs', 'empty'))

    error_log_output = <<~EMPTY
      ##  %grnFramework Errors%clr
      
      The following framework errors occurred before the issue occurred:
      <details>
      <summary>Collapse</summary>
      
      ```
      No matching patterns were found in framework.log.
      ```
      
      </details>
      
      
      ##  %grnWeb Service Errors%clr
      
      The following web service errors occurred before the issue occurred:
      <details>
      <summary>Collapse</summary>
      
      ```
      No matching patterns were found in msf-ws.log.
      ```
      
      </details>


    EMPTY

    expect(subject.errors).to eql(error_log_output)
  end

  it 'error parsing correctly returns a missing log file message' do
    allow(::Msf::Config).to receive(:log_directory).and_return('FAKE_PATH')

    error_log_output = <<~EMPTY
      ##  %grnFramework Errors%clr
      
      The following framework errors occurred before the issue occurred:
      <details>
      <summary>Collapse</summary>
      
      ```
      framework.log does not exist.
      ```
      
      </details>
      
      
      ##  %grnWeb Service Errors%clr
      
      The following web service errors occurred before the issue occurred:
      <details>
      <summary>Collapse</summary>
      
      ```
      msf-ws.log does not exist.
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
    allow(::Msf::Config).to receive(:config_file).and_return(File.join(file_fixtures_path, 'config_files', 'empty.ini'))

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
    allow(::Msf::Config).to receive(:config_file).and_return(File.join(file_fixtures_path, 'config_files', 'empty.ini'))

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
    allow(::Msf::Config).to receive(:config_file).and_return(File.join(file_fixtures_path, 'config_files', 'empty.ini'))

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
    allow(::Msf::Config).to receive(:config_file).and_return(File.join(file_fixtures_path, 'config_files', 'empty.ini'))

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
    allow(::Msf::Config).to receive(:config_file).and_return(File.join(file_fixtures_path, 'config_files', 'module.ini'))

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
    allow(::Msf::Config).to receive(:config_file).and_return(File.join(file_fixtures_path, 'config_files', 'db.ini'))

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

  it 'log parsing correctly retrieves and parses logs shorter than the log line total' do
    range = 1..30
    logs = ''
    range.each do |i|
      logs += "[00/00/0000 00:00:00] [e(0)] core: Log Line #{i}\n"
    end

    allow(::Msf::Config).to receive(:log_directory).and_return(File.join(file_fixtures_path, 'debug', 'framework_logs', 'short'))

    error_log_output = <<~E_LOG
    ##  %grnFramework Logs%clr

    The following framework logs were recorded before the issue occurred:
    <details>
    <summary>Collapse</summary>
    
    ```
    [00/00/0000 00:00:00] [e(0)] core: Log Line 1
    [00/00/0000 00:00:00] [e(0)] core: Log Line 2
    [00/00/0000 00:00:00] [e(0)] core: Log Line 3
    [00/00/0000 00:00:00] [e(0)] core: Log Line 4
    [00/00/0000 00:00:00] [e(0)] core: Log Line 5
    [00/00/0000 00:00:00] [e(0)] core: Log Line 6
    [00/00/0000 00:00:00] [e(0)] core: Log Line 7
    [00/00/0000 00:00:00] [e(0)] core: Log Line 8
    [00/00/0000 00:00:00] [e(0)] core: Log Line 9
    [00/00/0000 00:00:00] [e(0)] core: Log Line 10
    [00/00/0000 00:00:00] [e(0)] core: Log Line 11
    [00/00/0000 00:00:00] [e(0)] core: Log Line 12
    [00/00/0000 00:00:00] [e(0)] core: Log Line 13
    [00/00/0000 00:00:00] [e(0)] core: Log Line 14
    [00/00/0000 00:00:00] [e(0)] core: Log Line 15
    [00/00/0000 00:00:00] [e(0)] core: Log Line 16
    [00/00/0000 00:00:00] [e(0)] core: Log Line 17
    [00/00/0000 00:00:00] [e(0)] core: Log Line 18
    [00/00/0000 00:00:00] [e(0)] core: Log Line 19
    [00/00/0000 00:00:00] [e(0)] core: Log Line 20
    [00/00/0000 00:00:00] [e(0)] core: Log Line 21
    [00/00/0000 00:00:00] [e(0)] core: Log Line 22
    [00/00/0000 00:00:00] [e(0)] core: Log Line 23
    [00/00/0000 00:00:00] [e(0)] core: Log Line 24
    [00/00/0000 00:00:00] [e(0)] core: Log Line 25
    [00/00/0000 00:00:00] [e(0)] core: Log Line 26
    [00/00/0000 00:00:00] [e(0)] core: Log Line 27
    [00/00/0000 00:00:00] [e(0)] core: Log Line 28
    [00/00/0000 00:00:00] [e(0)] core: Log Line 29
    [00/00/0000 00:00:00] [e(0)] core: Log Line 30
    ```
    
    </details>
    
    
    ##  %grnWeb Service Logs%clr
    
    The following web service logs were recorded before the issue occurred:
    <details>
    <summary>Collapse</summary>
    
    ```
    [-] core: Log Line 1
    [-] core: Log Line 2
    [-] core: Log Line 3
    [-] core: Log Line 4
    [-] core: Log Line 5
    [-] core: Log Line 6
    [-] core: Log Line 7
    [-] core: Log Line 8
    [-] core: Log Line 9
    [-] core: Log Line 10
    [-] core: Log Line 11
    [-] core: Log Line 12
    [-] core: Log Line 13
    [-] core: Log Line 14
    [-] core: Log Line 15
    [-] core: Log Line 16
    [-] core: Log Line 17
    [-] core: Log Line 18
    [-] core: Log Line 19
    [-] core: Log Line 20
    [-] core: Log Line 21
    [-] core: Log Line 22
    [-] core: Log Line 23
    [-] core: Log Line 24
    [-] core: Log Line 25
    [-] core: Log Line 26
    [-] core: Log Line 27
    [-] core: Log Line 28
    [-] core: Log Line 29
    [-] core: Log Line 30
    ```
    
    </details>


    E_LOG

    expect(subject.logs).to eql(error_log_output)
  end

  it 'log parsing correctly retrieves and parses logs equal to the log line total' do
    range = 1..50
    logs = ''
    range.each do |i|
      logs += "[00/00/0000 00:00:00] [e(0)] core: Log Line #{i}\n"
    end

    allow(::Msf::Config).to receive(:log_directory).and_return(File.join(file_fixtures_path, 'debug', 'framework_logs', 'equal'))

    error_log_output = <<~E_LOG
    ##  %grnFramework Logs%clr

    The following framework logs were recorded before the issue occurred:
    <details>
    <summary>Collapse</summary>
    
    ```
    [00/00/0000 00:00:00] [e(0)] core: Log Line 1
    [00/00/0000 00:00:00] [e(0)] core: Log Line 2
    [00/00/0000 00:00:00] [e(0)] core: Log Line 3
    [00/00/0000 00:00:00] [e(0)] core: Log Line 4
    [00/00/0000 00:00:00] [e(0)] core: Log Line 5
    [00/00/0000 00:00:00] [e(0)] core: Log Line 6
    [00/00/0000 00:00:00] [e(0)] core: Log Line 7
    [00/00/0000 00:00:00] [e(0)] core: Log Line 8
    [00/00/0000 00:00:00] [e(0)] core: Log Line 9
    [00/00/0000 00:00:00] [e(0)] core: Log Line 10
    [00/00/0000 00:00:00] [e(0)] core: Log Line 11
    [00/00/0000 00:00:00] [e(0)] core: Log Line 12
    [00/00/0000 00:00:00] [e(0)] core: Log Line 13
    [00/00/0000 00:00:00] [e(0)] core: Log Line 14
    [00/00/0000 00:00:00] [e(0)] core: Log Line 15
    [00/00/0000 00:00:00] [e(0)] core: Log Line 16
    [00/00/0000 00:00:00] [e(0)] core: Log Line 17
    [00/00/0000 00:00:00] [e(0)] core: Log Line 18
    [00/00/0000 00:00:00] [e(0)] core: Log Line 19
    [00/00/0000 00:00:00] [e(0)] core: Log Line 20
    [00/00/0000 00:00:00] [e(0)] core: Log Line 21
    [00/00/0000 00:00:00] [e(0)] core: Log Line 22
    [00/00/0000 00:00:00] [e(0)] core: Log Line 23
    [00/00/0000 00:00:00] [e(0)] core: Log Line 24
    [00/00/0000 00:00:00] [e(0)] core: Log Line 25
    [00/00/0000 00:00:00] [e(0)] core: Log Line 26
    [00/00/0000 00:00:00] [e(0)] core: Log Line 27
    [00/00/0000 00:00:00] [e(0)] core: Log Line 28
    [00/00/0000 00:00:00] [e(0)] core: Log Line 29
    [00/00/0000 00:00:00] [e(0)] core: Log Line 30
    [00/00/0000 00:00:00] [e(0)] core: Log Line 31
    [00/00/0000 00:00:00] [e(0)] core: Log Line 32
    [00/00/0000 00:00:00] [e(0)] core: Log Line 33
    [00/00/0000 00:00:00] [e(0)] core: Log Line 34
    [00/00/0000 00:00:00] [e(0)] core: Log Line 35
    [00/00/0000 00:00:00] [e(0)] core: Log Line 36
    [00/00/0000 00:00:00] [e(0)] core: Log Line 37
    [00/00/0000 00:00:00] [e(0)] core: Log Line 38
    [00/00/0000 00:00:00] [e(0)] core: Log Line 39
    [00/00/0000 00:00:00] [e(0)] core: Log Line 40
    [00/00/0000 00:00:00] [e(0)] core: Log Line 41
    [00/00/0000 00:00:00] [e(0)] core: Log Line 42
    [00/00/0000 00:00:00] [e(0)] core: Log Line 43
    [00/00/0000 00:00:00] [e(0)] core: Log Line 44
    [00/00/0000 00:00:00] [e(0)] core: Log Line 45
    [00/00/0000 00:00:00] [e(0)] core: Log Line 46
    [00/00/0000 00:00:00] [e(0)] core: Log Line 47
    [00/00/0000 00:00:00] [e(0)] core: Log Line 48
    [00/00/0000 00:00:00] [e(0)] core: Log Line 49
    [00/00/0000 00:00:00] [e(0)] core: Log Line 50
    ```
    
    </details>
    
    
    ##  %grnWeb Service Logs%clr
    
    The following web service logs were recorded before the issue occurred:
    <details>
    <summary>Collapse</summary>
    
    ```
    [-] core: Log Line 1
    [-] core: Log Line 2
    [-] core: Log Line 3
    [-] core: Log Line 4
    [-] core: Log Line 5
    [-] core: Log Line 6
    [-] core: Log Line 7
    [-] core: Log Line 8
    [-] core: Log Line 9
    [-] core: Log Line 10
    [-] core: Log Line 11
    [-] core: Log Line 12
    [-] core: Log Line 13
    [-] core: Log Line 14
    [-] core: Log Line 15
    [-] core: Log Line 16
    [-] core: Log Line 17
    [-] core: Log Line 18
    [-] core: Log Line 19
    [-] core: Log Line 20
    [-] core: Log Line 21
    [-] core: Log Line 22
    [-] core: Log Line 23
    [-] core: Log Line 24
    [-] core: Log Line 25
    [-] core: Log Line 26
    [-] core: Log Line 27
    [-] core: Log Line 28
    [-] core: Log Line 29
    [-] core: Log Line 30
    [-] core: Log Line 31
    [-] core: Log Line 32
    [-] core: Log Line 33
    [-] core: Log Line 34
    [-] core: Log Line 35
    [-] core: Log Line 36
    [-] core: Log Line 37
    [-] core: Log Line 38
    [-] core: Log Line 39
    [-] core: Log Line 40
    [-] core: Log Line 41
    [-] core: Log Line 42
    [-] core: Log Line 43
    [-] core: Log Line 44
    [-] core: Log Line 45
    [-] core: Log Line 46
    [-] core: Log Line 47
    [-] core: Log Line 48
    [-] core: Log Line 49
    [-] core: Log Line 50
    [-] core: Log Line 51
    [-] core: Log Line 52
    [-] core: Log Line 53
    [-] core: Log Line 54
    [-] core: Log Line 55
    [-] core: Log Line 56
    [-] core: Log Line 57
    [-] core: Log Line 58
    [-] core: Log Line 59
    [-] core: Log Line 60
    [-] core: Log Line 61
    [-] core: Log Line 62
    [-] core: Log Line 63
    [-] core: Log Line 64
    [-] core: Log Line 65
    [-] core: Log Line 66
    [-] core: Log Line 67
    [-] core: Log Line 68
    [-] core: Log Line 69
    [-] core: Log Line 70
    [-] core: Log Line 71
    [-] core: Log Line 72
    [-] core: Log Line 73
    [-] core: Log Line 74
    [-] core: Log Line 75
    [-] core: Log Line 76
    [-] core: Log Line 77
    [-] core: Log Line 78
    [-] core: Log Line 79
    [-] core: Log Line 80
    [-] core: Log Line 81
    [-] core: Log Line 82
    [-] core: Log Line 83
    [-] core: Log Line 84
    [-] core: Log Line 85
    [-] core: Log Line 86
    [-] core: Log Line 87
    [-] core: Log Line 88
    [-] core: Log Line 89
    [-] core: Log Line 90
    [-] core: Log Line 91
    [-] core: Log Line 92
    [-] core: Log Line 93
    [-] core: Log Line 94
    [-] core: Log Line 95
    [-] core: Log Line 96
    [-] core: Log Line 97
    [-] core: Log Line 98
    [-] core: Log Line 99
    [-] core: Log Line 100
    [-] core: Log Line 101
    [-] core: Log Line 102
    [-] core: Log Line 103
    [-] core: Log Line 104
    [-] core: Log Line 105
    [-] core: Log Line 106
    [-] core: Log Line 107
    [-] core: Log Line 108
    [-] core: Log Line 109
    [-] core: Log Line 110
    [-] core: Log Line 111
    [-] core: Log Line 112
    [-] core: Log Line 113
    [-] core: Log Line 114
    [-] core: Log Line 115
    [-] core: Log Line 116
    [-] core: Log Line 117
    [-] core: Log Line 118
    [-] core: Log Line 119
    [-] core: Log Line 120
    [-] core: Log Line 121
    [-] core: Log Line 122
    [-] core: Log Line 123
    [-] core: Log Line 124
    [-] core: Log Line 125
    [-] core: Log Line 126
    [-] core: Log Line 127
    [-] core: Log Line 128
    [-] core: Log Line 129
    [-] core: Log Line 130
    [-] core: Log Line 131
    [-] core: Log Line 132
    [-] core: Log Line 133
    [-] core: Log Line 134
    [-] core: Log Line 135
    [-] core: Log Line 136
    [-] core: Log Line 137
    [-] core: Log Line 138
    [-] core: Log Line 139
    [-] core: Log Line 140
    [-] core: Log Line 141
    [-] core: Log Line 142
    [-] core: Log Line 143
    [-] core: Log Line 144
    [-] core: Log Line 145
    [-] core: Log Line 146
    [-] core: Log Line 147
    [-] core: Log Line 148
    [-] core: Log Line 149
    [-] core: Log Line 150
    ```
    
    </details>


    E_LOG

    expect(subject.logs).to eql(error_log_output)
  end

  it 'log parsing correctly retrieves and parses logs larger than the log line total' do
    range = 51..100
    logs = ''
    range.each do |i|
      logs += "[00/00/0000 00:00:00] [e(0)] core: Log Line #{i}\n"
    end

    allow(::Msf::Config).to receive(:log_directory).and_return(File.join(file_fixtures_path, 'debug', 'framework_logs', 'long'))

    error_log_output = <<~E_LOG
    ##  %grnFramework Logs%clr

    The following framework logs were recorded before the issue occurred:
    <details>
    <summary>Collapse</summary>
    
    ```
    [00/00/0000 00:00:00] [e(0)] core: Log Line 51
    [00/00/0000 00:00:00] [e(0)] core: Log Line 52
    [00/00/0000 00:00:00] [e(0)] core: Log Line 53
    [00/00/0000 00:00:00] [e(0)] core: Log Line 54
    [00/00/0000 00:00:00] [e(0)] core: Log Line 55
    [00/00/0000 00:00:00] [e(0)] core: Log Line 56
    [00/00/0000 00:00:00] [e(0)] core: Log Line 57
    [00/00/0000 00:00:00] [e(0)] core: Log Line 58
    [00/00/0000 00:00:00] [e(0)] core: Log Line 59
    [00/00/0000 00:00:00] [e(0)] core: Log Line 60
    [00/00/0000 00:00:00] [e(0)] core: Log Line 61
    [00/00/0000 00:00:00] [e(0)] core: Log Line 62
    [00/00/0000 00:00:00] [e(0)] core: Log Line 63
    [00/00/0000 00:00:00] [e(0)] core: Log Line 64
    [00/00/0000 00:00:00] [e(0)] core: Log Line 65
    [00/00/0000 00:00:00] [e(0)] core: Log Line 66
    [00/00/0000 00:00:00] [e(0)] core: Log Line 67
    [00/00/0000 00:00:00] [e(0)] core: Log Line 68
    [00/00/0000 00:00:00] [e(0)] core: Log Line 69
    [00/00/0000 00:00:00] [e(0)] core: Log Line 70
    [00/00/0000 00:00:00] [e(0)] core: Log Line 71
    [00/00/0000 00:00:00] [e(0)] core: Log Line 72
    [00/00/0000 00:00:00] [e(0)] core: Log Line 73
    [00/00/0000 00:00:00] [e(0)] core: Log Line 74
    [00/00/0000 00:00:00] [e(0)] core: Log Line 75
    [00/00/0000 00:00:00] [e(0)] core: Log Line 76
    [00/00/0000 00:00:00] [e(0)] core: Log Line 77
    [00/00/0000 00:00:00] [e(0)] core: Log Line 78
    [00/00/0000 00:00:00] [e(0)] core: Log Line 79
    [00/00/0000 00:00:00] [e(0)] core: Log Line 80
    [00/00/0000 00:00:00] [e(0)] core: Log Line 81
    [00/00/0000 00:00:00] [e(0)] core: Log Line 82
    [00/00/0000 00:00:00] [e(0)] core: Log Line 83
    [00/00/0000 00:00:00] [e(0)] core: Log Line 84
    [00/00/0000 00:00:00] [e(0)] core: Log Line 85
    [00/00/0000 00:00:00] [e(0)] core: Log Line 86
    [00/00/0000 00:00:00] [e(0)] core: Log Line 87
    [00/00/0000 00:00:00] [e(0)] core: Log Line 88
    [00/00/0000 00:00:00] [e(0)] core: Log Line 89
    [00/00/0000 00:00:00] [e(0)] core: Log Line 90
    [00/00/0000 00:00:00] [e(0)] core: Log Line 91
    [00/00/0000 00:00:00] [e(0)] core: Log Line 92
    [00/00/0000 00:00:00] [e(0)] core: Log Line 93
    [00/00/0000 00:00:00] [e(0)] core: Log Line 94
    [00/00/0000 00:00:00] [e(0)] core: Log Line 95
    [00/00/0000 00:00:00] [e(0)] core: Log Line 96
    [00/00/0000 00:00:00] [e(0)] core: Log Line 97
    [00/00/0000 00:00:00] [e(0)] core: Log Line 98
    [00/00/0000 00:00:00] [e(0)] core: Log Line 99
    [00/00/0000 00:00:00] [e(0)] core: Log Line 100
    ```
    
    </details>
    
    
    ##  %grnWeb Service Logs%clr
    
    The following web service logs were recorded before the issue occurred:
    <details>
    <summary>Collapse</summary>
    
    ```
    [-] core: Log Line 151
    [-] core: Log Line 152
    [-] core: Log Line 153
    [-] core: Log Line 154
    [-] core: Log Line 155
    [-] core: Log Line 156
    [-] core: Log Line 157
    [-] core: Log Line 158
    [-] core: Log Line 159
    [-] core: Log Line 160
    [-] core: Log Line 161
    [-] core: Log Line 162
    [-] core: Log Line 163
    [-] core: Log Line 164
    [-] core: Log Line 165
    [-] core: Log Line 166
    [-] core: Log Line 167
    [-] core: Log Line 168
    [-] core: Log Line 169
    [-] core: Log Line 170
    [-] core: Log Line 171
    [-] core: Log Line 172
    [-] core: Log Line 173
    [-] core: Log Line 174
    [-] core: Log Line 175
    [-] core: Log Line 176
    [-] core: Log Line 177
    [-] core: Log Line 178
    [-] core: Log Line 179
    [-] core: Log Line 180
    [-] core: Log Line 181
    [-] core: Log Line 182
    [-] core: Log Line 183
    [-] core: Log Line 184
    [-] core: Log Line 185
    [-] core: Log Line 186
    [-] core: Log Line 187
    [-] core: Log Line 188
    [-] core: Log Line 189
    [-] core: Log Line 190
    [-] core: Log Line 191
    [-] core: Log Line 192
    [-] core: Log Line 193
    [-] core: Log Line 194
    [-] core: Log Line 195
    [-] core: Log Line 196
    [-] core: Log Line 197
    [-] core: Log Line 198
    [-] core: Log Line 199
    [-] core: Log Line 200
    [-] core: Log Line 201
    [-] core: Log Line 202
    [-] core: Log Line 203
    [-] core: Log Line 204
    [-] core: Log Line 205
    [-] core: Log Line 206
    [-] core: Log Line 207
    [-] core: Log Line 208
    [-] core: Log Line 209
    [-] core: Log Line 210
    [-] core: Log Line 211
    [-] core: Log Line 212
    [-] core: Log Line 213
    [-] core: Log Line 214
    [-] core: Log Line 215
    [-] core: Log Line 216
    [-] core: Log Line 217
    [-] core: Log Line 218
    [-] core: Log Line 219
    [-] core: Log Line 220
    [-] core: Log Line 221
    [-] core: Log Line 222
    [-] core: Log Line 223
    [-] core: Log Line 224
    [-] core: Log Line 225
    [-] core: Log Line 226
    [-] core: Log Line 227
    [-] core: Log Line 228
    [-] core: Log Line 229
    [-] core: Log Line 230
    [-] core: Log Line 231
    [-] core: Log Line 232
    [-] core: Log Line 233
    [-] core: Log Line 234
    [-] core: Log Line 235
    [-] core: Log Line 236
    [-] core: Log Line 237
    [-] core: Log Line 238
    [-] core: Log Line 239
    [-] core: Log Line 240
    [-] core: Log Line 241
    [-] core: Log Line 242
    [-] core: Log Line 243
    [-] core: Log Line 244
    [-] core: Log Line 245
    [-] core: Log Line 246
    [-] core: Log Line 247
    [-] core: Log Line 248
    [-] core: Log Line 249
    [-] core: Log Line 250
    [-] core: Log Line 251
    [-] core: Log Line 252
    [-] core: Log Line 253
    [-] core: Log Line 254
    [-] core: Log Line 255
    [-] core: Log Line 256
    [-] core: Log Line 257
    [-] core: Log Line 258
    [-] core: Log Line 259
    [-] core: Log Line 260
    [-] core: Log Line 261
    [-] core: Log Line 262
    [-] core: Log Line 263
    [-] core: Log Line 264
    [-] core: Log Line 265
    [-] core: Log Line 266
    [-] core: Log Line 267
    [-] core: Log Line 268
    [-] core: Log Line 269
    [-] core: Log Line 270
    [-] core: Log Line 271
    [-] core: Log Line 272
    [-] core: Log Line 273
    [-] core: Log Line 274
    [-] core: Log Line 275
    [-] core: Log Line 276
    [-] core: Log Line 277
    [-] core: Log Line 278
    [-] core: Log Line 279
    [-] core: Log Line 280
    [-] core: Log Line 281
    [-] core: Log Line 282
    [-] core: Log Line 283
    [-] core: Log Line 284
    [-] core: Log Line 285
    [-] core: Log Line 286
    [-] core: Log Line 287
    [-] core: Log Line 288
    [-] core: Log Line 289
    [-] core: Log Line 290
    [-] core: Log Line 291
    [-] core: Log Line 292
    [-] core: Log Line 293
    [-] core: Log Line 294
    [-] core: Log Line 295
    [-] core: Log Line 296
    [-] core: Log Line 297
    [-] core: Log Line 298
    [-] core: Log Line 299
    [-] core: Log Line 300
    ```
    
    </details>


    E_LOG

    expect(subject.logs).to eql(error_log_output)
  end

  it 'log parsing correctly retrieves and parses an empty log file' do
    allow(::Msf::Config).to receive(:log_directory).and_return(File.join(file_fixtures_path, 'debug', 'framework_logs', 'empty'))

    error_log_output = <<~E_LOG
      ##  %grnFramework Logs%clr

      The following framework logs were recorded before the issue occurred:
      <details>
      <summary>Collapse</summary>
      
      ```
      
      ```
      
      </details>
      
      
      ##  %grnWeb Service Logs%clr
      
      The following web service logs were recorded before the issue occurred:
      <details>
      <summary>Collapse</summary>
      
      ```
      
      ```
      
      </details>


    E_LOG

    expect(subject.logs).to eql(error_log_output)
  end

  it 'log parsing correctly retrieves and returns a missing log file message' do
    allow(::Msf::Config).to receive(:log_directory).and_return('FAKE_PATH')

    error_log_output = <<~E_LOG
      ##  %grnFramework Logs%clr
      
      The following framework logs were recorded before the issue occurred:
      <details>
      <summary>Collapse</summary>
      
      ```
      framework.log does not exist.
      ```
      
      </details>
      
      
      ##  %grnWeb Service Logs%clr
      
      The following web service logs were recorded before the issue occurred:
      <details>
      <summary>Collapse</summary>
      
      ```
      msf-ws.log does not exist.
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
      connection_established?: true
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
      Session Type: Connected to db_name. Connection type: http.
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
      driver: 'local'
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

    allow(::ApplicationRecord).to receive(:connection_pool).and_return(connection_pool)
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
      Session Type: Connected to current_db_connection. Connection type: local.
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
