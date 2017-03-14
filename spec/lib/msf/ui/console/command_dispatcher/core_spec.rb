require 'spec_helper'

require 'msf/ui'
require 'msf/ui/console/module_command_dispatcher'
require 'msf/ui/console/command_dispatcher/core'

RSpec.describe Msf::Ui::Console::CommandDispatcher::Core do
  include_context 'Msf::DBManager'
  include_context 'Msf::UIDriver'

  subject(:core) do
    described_class.new(driver)
  end

  it { is_expected.to respond_to :cmd_get }
  it { is_expected.to respond_to :cmd_getg }

  def set_and_test_variable(name, framework_value, module_value, framework_re, module_re)
    # set the current module
    allow(core).to receive(:active_module).and_return(mod)
    # always assume set variables validate (largely irrelevant because ours are random)
    allow(driver).to receive(:on_variable_set).and_return(true)
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
    describe "without arguments" do
      it "should show the correct help message" do
        core.cmd_get
        expect(@output.join).to match /Usage: get /
        @output = []
        core.cmd_getg
        expect(@output.join).to match /Usage: getg /
      end
    end

    describe "with arguments" do
      let(:name) { ::Rex::Text.rand_text_alpha(10).upcase }

      context "with an active module" do
        let(:mod) do
          mod = ::Msf::Module.new
          mod.send(:initialize, {})
          mod
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
end
