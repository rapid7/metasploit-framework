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

  describe '#cmd_set', if: ENV['DATASTORE_FALLBACKS'] do
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

  describe '#cmd_unset', if: ENV['DATASTORE_FALLBACKS'] do
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

    # Test for setting uncomplete option
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
end
