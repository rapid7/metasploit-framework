# frozen_string_literal: true

require 'rubocop/cop/lint/detect_outdated_cmd_exec_api'
require 'rubocop/rspec/support'

RSpec.describe RuboCop::Cop::Lint::DetectOutdatedCmdExecApi, :config do
  subject(:cop) { described_class.new(config) }

  let(:config) { RuboCop::Config.new }

  it 'registers an offense when cmd_exec is called with separate arguments' do
    expect_offense(<<~RUBY)
      cmd_exec('cmd.exe', '/c echo hello')
      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/DetectOutdatedCmdExecApi: Do not use cmd_exec with separate arguments. Use create_process with an args array instead, see https://docs.metasploit.com/docs/development/developing-modules/libraries/post-mixins.html#msfpostcommon
    RUBY
  end

  it 'registers an offense when cmd_exec is called with variable arguments' do
    expect_offense(<<~RUBY)
      cmd_exec(binary, args, timeout)
      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/DetectOutdatedCmdExecApi: Do not use cmd_exec with separate arguments. Use create_process with an args array instead, see https://docs.metasploit.com/docs/development/developing-modules/libraries/post-mixins.html#msfpostcommon
    RUBY
  end

  it 'registers an offense when cmd_exec is called with command and args string' do
    expect_offense(<<~RUBY)
      cmd_exec("ls", "-la /tmp")
      ^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/DetectOutdatedCmdExecApi: Do not use cmd_exec with separate arguments. Use create_process with an args array instead, see https://docs.metasploit.com/docs/development/developing-modules/libraries/post-mixins.html#msfpostcommon
    RUBY
  end

  it 'registers an offense when cmd_exec is called with command and timeout without explicit nil' do
    expect_offense(<<~RUBY)
      cmd_exec('cmd.exe', "/c \#{rasdial_cmd}", 60)
      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/DetectOutdatedCmdExecApi: Do not use cmd_exec with separate arguments. Use create_process with an args array instead, see https://docs.metasploit.com/docs/development/developing-modules/libraries/post-mixins.html#msfpostcommon
    RUBY
  end

  it 'does not register an offense when cmd_exec is called with a single static command' do
    expect_no_offenses(<<~RUBY)
      cmd_exec('id -u')
    RUBY
  end

  it 'does not register an offense when cmd_exec is called with a single command string' do
    expect_no_offenses(<<~RUBY)
      cmd_exec('hostname')
    RUBY
  end

  it 'does not register an offense when cmd_exec is called with a single interpolated command' do
    expect_no_offenses(<<~RUBY)
      cmd_exec("echo $PPID")
    RUBY
  end

  it 'does not register an offense when cmd_exec is called with nil as second argument' do
    expect_no_offenses(<<~RUBY)
      cmd_exec(cmd, nil, timeout)
    RUBY
  end

  it 'does not register an offense when cmd_exec is called with explicit nil args and timeout' do
    expect_no_offenses(<<~RUBY)
      cmd_exec("./\#{exploit_name} \#{arg}", nil, timeout)
    RUBY
  end

  it 'does not register an offense for create_process calls' do
    expect_no_offenses(<<~RUBY)
      create_process('cmd.exe', args: ['/c', 'echo', 'hello'])
    RUBY
  end

  it 'does not register an offense for create_process with variable args' do
    expect_no_offenses(<<~RUBY)
      create_process(binary, args: args_array, time_out: timeout)
    RUBY
  end
end

