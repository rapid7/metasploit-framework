require 'spec_helper'

require 'readline'

RSpec.describe Msf::Ui::Console::CommandDispatcher::Core do
  include_context 'Msf::DBManager'
  include_context 'Msf::UIDriver'

  subject(:core) do
    described_class.new(driver)
  end

  it { is_expected.to respond_to :cmd_get }
  it { is_expected.to respond_to :cmd_getg }
  it { is_expected.to respond_to :cmd_set_tabs }
  it { is_expected.to respond_to :cmd_setg_tabs }

  def set_and_test_variable(name, framework_value, module_value, framework_re, module_re)
    # the specified global value
    core.cmd_setg(name, framework_value) if framework_value
    # set the specified local value
    core.cmd_set(name, module_value) if module_value

    # test the global value if specified
    if framework_re
      @output = []
      core.cmd_getg(name)
      expect(@output.join).to match framework_re
    end

    # test the local value if specified
    if module_re
      @output = []
      core.cmd_get(name)
      expect(@output.join).to match module_re
    end
  end

  describe "#cmd_get and #cmd_getg" do
    context "without arguments" do
      it "should show the correct help message" do
        core.cmd_get
        expect(@output.join).to match /Usage: get /
        @output = []
        core.cmd_getg
        expect(@output.join).to match /Usage: getg /
      end
    end

    context "with arguments" do
      let(:name) { ::Rex::Text.rand_text_alpha(10).upcase }

      context "with an active module" do
        let(:mod) do
          mod = ::Msf::Module.new
          mod.send(:initialize, {})
          mod
        end

        before(:each) do
          allow(core).to receive(:active_module).and_return(mod)
          allow(core).to receive(:tab_complete_option_names).and_return([ name ])
          allow(driver).to receive(:on_variable_set).and_return(true)
        end

        it "should show no value if not set in the framework or module" do
          set_and_test_variable(name, nil, nil, /^#{name} => $/, /^#{name} => $/)
        end

        it "should show the correct value when only the module has this variable" do
          set_and_test_variable(name, nil, 'MODULE', /^#{name} => $/, /^#{name} => MODULE$/)
        end

        it "should show the correct value when only the framework has this variable" do
          set_and_test_variable(name, 'FRAMEWORK', nil, /^#{name} => FRAMEWORK$/, /^#{name} => $/)
        end

        it "should show the correct value when both the module and the framework have this variable" do
          set_and_test_variable(name, 'FRAMEWORK', 'MODULE', /^#{name} => FRAMEWORK$/, /^#{name} => MODULE$/)
        end

      end
    end
  end

  describe '#cmd_set' do
    let(:mod) { nil }

    before(:each) do
      allow(subject).to receive(:active_module).and_return(mod)
      allow(driver).to receive(:on_variable_set)
    end

    context 'with an exploit active module' do
      let(:mod) do
        mod_klass = Class.new(Msf::Exploit) do
          def initialize
            super

            register_options(
              [
                Msf::OptString.new(
                  'foo',
                  [true, 'Foo option', 'default_foo_value']
                )
              ]
            )
          end
        end
        mod = mod_klass.new
        allow(mod).to receive(:framework).and_return(framework)
        mod
      end

      context 'when no arguments are supplied' do
        before(:each) do
          subject.cmd_set
        end

        it 'should output the datastore value' do
          expect(@output.join).to match /foo                     default_foo_value/
        end
      end

      context 'when setting the module datastore value' do
        before(:each) do
          subject.cmd_set('foo', 'bar')
        end

        it 'should not set the framework datastore' do
          expect(framework.datastore['foo']).to eq nil
        end

        it 'should allow lookup via the active module' do
          expect(mod.datastore['foo']).to eq 'bar'
        end
      end

      context 'when setting the global datastore value' do
        before(:each) do
          subject.cmd_set('-g', 'foo', 'bar')
        end

        it 'should set the framework datastore' do
          expect(framework.datastore['foo']).to eq 'bar'
        end

        it 'should allow lookup via the active module' do
          expect(mod.datastore['foo']).to eq 'bar'
        end
      end

      context 'when setting the global datastore value to nil' do
        before(:each) do
          framework.datastore['foo'] = 'global value'
          subject.cmd_set('--clear', 'foo', 'ignored_value')
        end

        it 'should not set the framework datastore' do
          expect(framework.datastore['foo']).to eq 'global value'
        end

        it 'should set the datastore value to nil' do
          expect(mod.datastore['foo']).to eq nil
        end
      end

      context 'when setting the module datastore value to nil' do
        before(:each) do
          framework.datastore['foo'] = 'global value'
          subject.cmd_set('--clear', 'foo', 'ignored_value')
        end

        it 'should not set the framework datastore' do
          expect(framework.datastore['foo']).to eq 'global value'
        end

        it 'should set the datastore value to nil' do
          expect(mod.datastore['foo']).to eq nil
        end
      end
    end
  end

  describe '#cmd_setg' do
    before(:each) do
      allow(subject).to receive(:cmd_set)
    end

    it 'should call cmd_set when no arguments are present' do
      subject.cmd_setg
      expect(subject).to have_received(:cmd_set).with('-g')
    end

    it 'should call cmd_set when no arguments present' do
      subject.cmd_setg('foo', 'bar')
      expect(subject).to have_received(:cmd_set).with('-g', 'foo', 'bar')
    end
  end

  describe '#cmd_unset' do
    let(:mod) { nil }

    before(:each) do
      allow(subject).to receive(:active_module).and_return(mod)
      allow(driver).to receive(:on_variable_unset)
    end

    context 'with an exploit active module' do
      let(:mod) do
        mod_klass = Class.new(Msf::Exploit) do
          def initialize
            super

            register_options(
              [
                Msf::OptString.new(
                  'foo',
                  [true, 'Foo option', 'default_foo_value']
                ),
                Msf::OptString.new(
                  'SMBDomain',
                  [ false, 'The Windows domain to use for authentication', 'WORKGROUP'],
                  fallbacks: ['DOMAIN']
                ),
              ]
            )
          end
        end
        mod = mod_klass.new
        allow(mod).to receive(:framework).and_return(framework)
        mod
      end

      context 'when no arguments are supplied' do
        before(:each) do
          subject.cmd_unset
        end

        it 'should output the help information' do
          expect(@output.join).to match /The unset command is used to .*/
        end
      end

      context 'when unsetting a module datastore value without a registered option' do
        before(:each) do
          mod.datastore['PAYLOAD'] = 'linux/x86/meterpreter/reverse_tcp'
          subject.cmd_unset('PAYLOAD')
        end

        it 'should reset the value' do
          expect(mod.datastore['PAYLOAD']).to eq nil
        end

        it 'should output a message to the user' do
          expect(@combined_output.join).to eq 'Unsetting PAYLOAD...'
        end
      end

      context 'when unsetting a module datastore value with an existing default' do
        before(:each) do
          mod.datastore['foo'] = 'user_defined'
          subject.cmd_unset('foo')
        end

        it 'should reset the value' do
          expect(mod.datastore['foo']).to eq 'default_foo_value'
        end

        it 'should output an extra message indicating a default value will be used' do
          expect(@combined_output.join).to match /Unsetting foo.../
          expect(@combined_output.join).to match /"foo" unset - but will use a default value still/
        end
      end

      context 'when unsetting a module datastore value with a fallback' do
        before(:each) do
          mod.datastore['domain'] = 'user_defined'
          subject.cmd_unset('SMBDomain')
        end

        it 'should continue to fallback' do
          expect(mod.datastore['SMBDomain']).to eq 'user_defined'
        end

        it 'should output an extra message indicating a fallback value will be used' do
          expect(@combined_output.join).to match /Unsetting SMBDomain.../
          expect(@combined_output.join).to match /Variable "SMBDomain" unset - but will continue to use "DOMAIN" as a fallback/
        end
      end

      context 'when unsetting a module datastore value with a global value set' do
        before(:each) do
          mod.framework.datastore['foo'] = 'global_value'
          subject.cmd_unset('foo')
        end

        it 'should continue to use the global value' do
          expect(mod.datastore['foo']).to eq 'global_value'
        end

        it 'should output an extra message indicating a fallback value will be used' do
          expect(@combined_output.join).to match /Unsetting foo.../
          expect(@combined_output.join).to match /Variable "foo" unset - but will continue to use the globally set value/
        end
      end
    end
  end

  describe '#cmd_unsetg' do
    before(:each) do
      allow(subject).to receive(:cmd_unset)
    end

    it 'should call cmd_unset when no arguments are present' do
      subject.cmd_unsetg
      expect(subject).to have_received(:cmd_unset).with('-g')
    end

    it 'should call cmd_unset when no arguments present' do
      subject.cmd_unsetg('foo', 'bar')
      expect(subject).to have_received(:cmd_unset).with('-g', 'foo', 'bar')
    end
  end

  def set_tabs_test(option)
    allow(core).to receive(:active_module).and_return(mod)
    # always assume set variables validate (largely irrelevant because ours are random)
    allow(driver).to receive(:on_variable_set).and_return(true)

    double = double('framework')
    allow(double).to receive(:get).and_return(nil)
    allow(double).to receive(:sessions).and_return([])
    allow_any_instance_of(Msf::Post).to receive(:framework).and_return(double)

    # Test for setting incomplete option
    output = core.cmd_set_tabs(option, ["set"])
    expect(output).to be_kind_of(Array).or eq(nil)

    # Test for setting option
    output = core.cmd_set_tabs("", ["set", option])
    expect(output).to be_kind_of(Array).or eq(nil)
  end

  describe "#cmd_set_tabs" do
    # The options of all kinds of modules.
    all_options =  ::Msf::Exploit.new.datastore.keys   +
                   ::Msf::Post.new.datastore.keys      +
                   ::Msf::Auxiliary.new.datastore.keys
    all_options.uniq!

    context "with a Exploit active module" do
      let(:mod) do
        mod = ::Msf::Exploit.new
        mod.send(:initialize, {})
        mod
      end

      all_options.each do |option|
        context "with #{option} arguments" do
          it "should return array or nil" do
            set_tabs_test(option)
          end
        end
      end
    end

    context "with a Post active module" do
      let(:mod) do
        mod = ::Msf::Post.new
        mod.send(:initialize, {})
        mod
      end

      all_options.each do |option|
        describe "with #{option} arguments" do
          it "should return array or nil" do
            set_tabs_test(option)
          end
        end
      end
    end

    context "with a Auxiliary active module" do
      let(:mod) do
        mod = ::Msf::Auxiliary.new
        mod.send(:initialize, {})
        mod
      end

      all_options.each do |option|
        describe "with #{option} arguments" do
          it "should return array or nil" do
            set_tabs_test(option)
          end
        end
      end
    end
  end

  describe '#cmd_sessions' do
    before(:each) do
      allow(driver).to receive(:active_session=)
      allow(framework).to receive(:sessions).and_return(sessions)
    end

    context 'with no sessions' do
      let(:sessions) { [] }
      it 'When the user does not enter a search term' do
        core.cmd_sessions
        expect(@combined_output.join("\n")).to match_table <<~TABLE
          Active sessions
          ===============

          No active sessions.
        TABLE
      end

      it 'When the user searches for a session' do
        core.cmd_sessions('--search', 'session_id:1')
        expect(@combined_output.join("\n")).to match_table <<~TABLE
          No matching sessions.
        TABLE
      end
    end

    context 'with sessions' do
      let(:sessions) do
        {
          1 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: Time.now, type: 'meterpreter', sid: 1, sname: 'sesh1', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel')
        }
      end

      it 'When the user searches for an invalid field' do
        core.cmd_sessions('--search', 'not_a_term:1')
        expect(@combined_output.join("\n")).to match_table <<~TABLE
          Please provide valid search term. Given: not_a_term. Supported keywords are: last_checkin, session_id, session_type
        TABLE
      end
    end

    context 'searching for sessions with different ids' do
      let(:sessions) do
        {
          1 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: Time.now, type: 'meterpreter', sid: 1, sname: 'session1', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel'),
          2 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: Time.now, type: 'meterpreter', sid: 2, sname: 'session2', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel')
        }
      end

      it 'When the user searches for a specific id' do
        core.cmd_sessions('--search', 'session_id:1')
        expect(@output.join("\n")).to match_table <<~TABLE
          Active sessions
          ===============

            Id  Name      Type         Information  Connection
            --  ----      ----         -----------  ----------
            1   session1  meterpreter  info         tunnel (127.0.0.1)
        TABLE
      end

      it 'When the user searches for a session id that does not exist' do
        core.cmd_sessions('--search', 'session_id:6')
        expect(@combined_output.join("\n")).to match_table <<~TABLE
          No matching sessions.
        TABLE
      end

      it 'When the user searches for multiple ids' do
        core.cmd_sessions('--search', 'session_id:2 session_id:1')
        expect(@output.join("\n")).to match_table <<~TABLE
          Active sessions
          ===============

            Id  Name      Type         Information  Connection
            --  ----      ----         -----------  ----------
            1   session1  meterpreter  info         tunnel (127.0.0.1)
            2   session2  meterpreter  info         tunnel (127.0.0.1)
        TABLE
      end

      it 'When the user searches for multiple ids and only some match' do
        core.cmd_sessions('--search', 'session_id:2 session_id:6')
        expect(@output.join("\n")).to match_table <<~TABLE
          Active sessions
          ===============

            Id  Name      Type         Information  Connection
            --  ----      ----         -----------  ----------
            2   session2  meterpreter  info         tunnel (127.0.0.1)
        TABLE
      end
    end

    context 'searches with sessions with different session types' do
      let(:sessions) do
        {
          1 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: Time.now, type: 'cmd_shell', sid: 1, sname: 'session1', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel'),
          2 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: Time.now, type: 'meterpreter', sid: 2, sname: 'session2', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel'),
          3 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: Time.now, type: 'java', sid: 3, sname: 'session3', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel')
        }
      end

      it 'returns session match by type' do
        core.cmd_sessions('--search', 'session_type:meterpreter')
        expect(@output.join("\n")).to match_table <<~TABLE
          Active sessions
          ===============

            Id  Name      Type         Information  Connection
            --  ----      ----         -----------  ----------
            2   session2  meterpreter  info         tunnel (127.0.0.1)
        TABLE
      end

      it 'filters by multiple session types' do
        core.cmd_sessions('--search', 'session_type:meterpreter session_type:java')
        expect(@output.join("\n")).to match_table <<~TABLE
          Active sessions
          ===============

            Id  Name      Type         Information  Connection
            --  ----      ----         -----------  ----------
            2   session2  meterpreter  info         tunnel (127.0.0.1)
            3   session3  java         info         tunnel (127.0.0.1)
        TABLE
      end
    end

    context 'searches with sessions with different checkin values' do
      before(:all) do
        Timecop.freeze(Time.parse('Dec 18, 2022 12:33:40.000000000 GMT'))
      end

      after(:all) do
        Timecop.return
      end

      let(:sessions) do
        {
          1 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: Time.now, type: 'meterpreter', sid: 1, sname: 'session1', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel'),
          2 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: (Time.now - 90), type: 'meterpreter', sid: 2, sname: 'session2', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel'),
          3 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: (Time.now - 20000), type: 'meterpreter', sid: 3, sname: 'session3', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel')
        }
      end

      it 'When the user searches using fractions of a second' do
        core.cmd_sessions('--search', 'last_checkin:less_than:100.5s')
        expect(@output.join("\n")).to match_table <<~TABLE
          Active sessions
          ===============

            Id  Name      Type         Information  Connection
            --  ----      ----         -----------  ----------
            1   session1  meterpreter  info         tunnel (127.0.0.1)
            2   session2  meterpreter  info         tunnel (127.0.0.1)
        TABLE
      end

      it 'When the user searches using multiple units with fractional seconds' do
        core.cmd_sessions('--search', 'last_checkin:less_than:1m40.5s')
        expect(@output.join("\n")).to match_table <<~TABLE
          Active sessions
          ===============

            Id  Name      Type         Information  Connection
            --  ----      ----         -----------  ----------
            1   session1  meterpreter  info         tunnel (127.0.0.1)
            2   session2  meterpreter  info         tunnel (127.0.0.1)
        TABLE
      end

      it 'When the user searches using fractions of a minute' do
        core.cmd_sessions('--search', 'last_checkin:greater_than:0.5m1s')
        expect(@output.join("\n")).to match_table <<~TABLE
          Active sessions
          ===============

            Id  Name      Type         Information  Connection
            --  ----      ----         -----------  ----------
            2   session2  meterpreter  info         tunnel (127.0.0.1)
            3   session3  meterpreter  info         tunnel (127.0.0.1)
        TABLE
      end

      it 'When the user searches using capital letters' do
        core.cmd_sessions('--search', 'last_checkin:greater_than:31S')
        expect(@combined_output.join("\n")).to match_table <<~TABLE
          Active sessions
          ===============

            Id  Name      Type         Information  Connection
            --  ----      ----         -----------  ----------
            2   session2  meterpreter  info         tunnel (127.0.0.1)
            3   session3  meterpreter  info         tunnel (127.0.0.1)
        TABLE
      end

      it 'When the user searches using an invalid checkin parameter' do
        core.cmd_sessions('--search', 'last_checkin:something:10s')
        expect(@combined_output.join("\n")).to match_table <<~TABLE
          Please specify less_than or greater_than for checkin query. Ex: last_checkin:less_than:1m30s. Given: something
        TABLE
      end

      it 'When the user searches using duplicated time units' do
        core.cmd_sessions('--search', 'last_checkin:less_than:10s10s')
        expect(@combined_output.join("\n")).to match_table <<~TABLE
          Please do not provide duplicate time units in your query
        TABLE
      end

      it 'When the user properly specifies both less_than and greater_than checkin ranges' do
        core.cmd_sessions('--search', 'last_checkin:less_than:200s last_checkin:greater_than:30s')
        expect(@output.join("\n")).to match_table <<~TABLE
          Active sessions
          ===============

            Id  Name      Type         Information  Connection
            --  ----      ----         -----------  ----------
            2   session2  meterpreter  info         tunnel (127.0.0.1)
        TABLE
      end

      it 'When the user specifies a greater_than time that is larger than the less_than time' do
        core.cmd_sessions('--search', 'last_checkin:greater_than:200s last_checkin:less_than:30s')
        expect(@combined_output.join("\n")).to match_table <<~TABLE
          After value must be a larger duration than the before value.
        TABLE
      end

      it 'When the user uses two before arguments with last checkin' do
        core.cmd_sessions('--search', 'last_checkin:greater_than:200s last_checkin:greater_than:30s')
        expect(@combined_output.join("\n")).to match_table <<~TABLE
          Cannot search for last_checkin with two greater_than arguments.
        TABLE
      end
    end

    context 'Searches with sessions that have different checkins and types' do
      before(:all) do
        Timecop.freeze(Time.parse('Dec 18, 2022 12:33:40.000000000 GMT'))
      end

      after(:all) do
        Timecop.return
      end

      let(:sessions) do
        {
          1 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: Time.now, type: 'meterpreter', sid: 1, sname: 'session1', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel'),
          2 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: (Time.now - 90), type: 'java', sid: 2, sname: 'session2', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel'),
          3 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: (Time.now - 20000), type: 'cmd_shell', sid: 3, sname: 'session3', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel')
        }
      end

      it 'When the user specifies both type and checkin' do
        core.cmd_sessions('--search', 'last_checkin:less_than:1m40.5s session_type:meterpreter')
        expect(@output.join("\n")).to match_table <<~TABLE
          Active sessions
          ===============

            Id  Name      Type         Information  Connection
            --  ----      ----         -----------  ----------
            1   session1  meterpreter  info         tunnel (127.0.0.1)
        TABLE
      end

      it 'When the user specifies both type and checkin but there are only partial matches' do
        core.cmd_sessions('--search', 'last_checkin:less_than:1m40.5s session_type:something')
        expect(@combined_output.join("\n")).to match_table <<~TABLE
          No matching sessions.
        TABLE
      end
    end

    context 'Searches with sessions that have different ids and types' do
      let(:sessions) do
        {
          1 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: Time.now, type: 'meterpreter', sid: 1, sname: 'session1', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel'),
          2 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: (Time.now - 90), type: 'java', sid: 2, sname: 'session2', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel'),
          3 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: (Time.now - 20000), type: 'cmd_shell', sid: 3, sname: 'session3', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel')
        }
      end

      it 'When the user specifies both type and checkin' do
        core.cmd_sessions('--search', 'session_id:1 session_type:meterpreter')
        expect(@output.join("\n")).to match_table <<~TABLE
          Active sessions
          ===============

            Id  Name      Type         Information  Connection
            --  ----      ----         -----------  ----------
            1   session1  meterpreter  info         tunnel (127.0.0.1)
        TABLE
      end

      it 'When the user specifies both type and checkin but there are only partial matches' do
        core.cmd_sessions('--search', 'session_id:1 session_type:something')
        expect(@combined_output.join("\n")).to match_table <<~TABLE
          No matching sessions.
        TABLE
      end
    end

    context 'searches for checkin with sessions that do not respond to checkin' do
      let(:sessions) do
        {
          1 => instance_double(::Msf::Sessions::CommandShell, type: 'cmd_shell', sid: 1, sname: 'session1', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel')
        }
      end

      it 'When the user searches for checkin values' do
        core.cmd_sessions('--search', 'last_checkin:less_than:6s')
        expect(@combined_output.join("\n")).to match_table <<~TABLE
          No matching sessions.
        TABLE
      end
    end

    context 'with other flags' do
      let(:sessions) do
        {
          1 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: Time.now, type: 'meterpreter', sid: 1, sname: 'session1', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel'),
          2 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: Time.now, type: 'meterpreter', sid: 2, sname: 'session2', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel'),
          3 => instance_double(::Msf::Sessions::Meterpreter_x64_Win, last_checkin: Time.now, type: 'meterpreter', sid: 3, sname: 'session3', info: 'info', session_host: '127.0.0.1', tunnel_to_s: 'tunnel')
        }
      end
      it 'When the user tries to kill all matching sessions but there are no matches' do
        core.cmd_sessions('--search', 'session_id:5', '-K')
        expect(@combined_output).to eq([
          'No matching sessions.'
        ])
      end

      it 'When the user tries to kill all matching sessions and there are matches' do
        expect(sessions[1]).not_to receive(:kill)
        expect(sessions[2]).to receive(:kill)
        expect(sessions[3]).to receive(:kill)
        core.cmd_sessions('--search', 'session_id:2 session_id:3', '-K')
        expect(@output.join("\n")).to match_table <<~TABLE
          Killing matching sessions...
          Active sessions
          ===============

            Id  Name      Type         Information  Connection
            --  ----      ----         -----------  ----------
            2   session2  meterpreter  info         tunnel (127.0.0.1)
            3   session3  meterpreter  info         tunnel (127.0.0.1)
        TABLE
      end
    end
  end

  describe '#parse_duration' do
    {
      '1s' => 1,
      '2s' => 2,
      '3.5s' => 3,
      '1.5m' => 90,
      '1.5d' => 129600,
      '1d1h1m1s' => 90061,
      '1.5d1.5h1.5m1.5s' => 135091,
      '1.75m70s' => 175
    }.each do |input, expected|
      it "returns #{expected} seconds for the input #{input}" do
        expect(core.parse_duration(input)).to eq(expected)
      end
    end
  end
end
