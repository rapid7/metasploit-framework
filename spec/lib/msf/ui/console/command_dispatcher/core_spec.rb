require 'spec_helper'

require 'msf/ui'
require 'msf/ui/console/module_command_dispatcher'
require 'msf/ui/console/command_dispatcher/core'

describe Msf::Ui::Console::CommandDispatcher::Core do
  include_context 'Msf::DBManager'
  include_context 'Msf::UIDriver'

  subject(:core) do
    described_class.new(driver)
  end

  context '#search_modules_sql' do
    def search_modules_sql
      core.search_modules_sql(match)
    end

    let(:match) do
      ''
    end

    it 'should generate Matching Modules table' do
      core.should_receive(:generate_module_table).with('Matching Modules').and_call_original

      search_modules_sql
    end

    it 'should call Msf::DBManager#search_modules' do
      db_manager.should_receive(:search_modules).with(match).and_return([])

      search_modules_sql
    end

    context 'with matching Mdm::Module::Details' do
      let(:match) do
        module_detail.fullname
      end

      let!(:module_detail) do
        FactoryGirl.create(:mdm_module_detail)
      end

      context 'printed table' do
        def cell(table, row, column)
          row_line_number = 6 + row
          line_number     = 0

          cell = nil

          table.each_line do |line|
            if line_number == row_line_number
              # strip prefix and postfix
              padded_cells = line[3...-1]
              cells        = padded_cells.split(/\s{2,}/)

              cell = cells[column]
              break
            end

            line_number += 1
          end

          cell
        end

        let(:printed_table) do
          table = ''

          core.stub(:print_line) do |string|
            table = string
          end

          search_modules_sql

          table
        end

        it 'should have fullname in first column' do
          cell(printed_table, 0, 0).should include(module_detail.fullname)
        end

        it 'should have disclosure date in second column' do
          cell(printed_table, 0, 1).should include(module_detail.disclosure_date.strftime("%Y-%m-%d"))
        end

        it 'should have rank name in third column' do
          cell(printed_table, 0, 2).should include(Msf::RankingName[module_detail.rank])
        end

        it 'should have name in fourth column' do
          cell(printed_table, 0, 3).should include(module_detail.name)
        end
      end
    end
  end

  it { is_expected.to respond_to :cmd_get }
  it { is_expected.to respond_to :cmd_getg }

  describe "#cmd_get" do
    describe "without arguments" do
      it "should show a help message" do
        core.cmd_get
        @output.join.should =~ /Usage: get /
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
          allow(core).to receive(:active_module).and_return(mod)
          allow(driver).to receive(:on_variable_set).and_return(true)
          core.cmd_get(name)
          @output.join.should =~ /^#{name} => $/
        end

        it "should show no value when only the framework has this variable" do
          allow(core).to receive(:active_module).and_return(mod)
          allow(driver).to receive(:on_variable_set).and_return(true)
          core.cmd_setg(name, 'FRAMEWORK')
          @output = []
          core.cmd_get(name)
          @output.join.should =~ /^#{name} => $/
        end

        it "should show the module's value when only the module has this variable" do
          allow(core).to receive(:active_module).and_return(mod)
          allow(driver).to receive(:on_variable_set).and_return(true)
          core.cmd_set(name, 'MODULE')
          @output = []
          core.cmd_get(name)
          @output.join.should =~ /^#{name} => MODULE$/
        end

        it "should show the module's value when both the module and the framework have this variable" do
          allow(core).to receive(:active_module).and_return(mod)
          allow(driver).to receive(:on_variable_set).and_return(true)
          core.cmd_setg(name, 'FRAMEWORK')
          core.cmd_set(name, 'MODULE')
          @output = []
          core.cmd_get(name)
          @output.join.should =~ /^#{name} => MODULE$/
        end
      end
    end
  end

  describe "#cmd_getg" do
    describe "without arguments" do
      it "should show a help message" do
        core.cmd_getg
        @output.join.should =~ /Usage: getg /
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
          allow(core).to receive(:active_module).and_return(mod)
          allow(driver).to receive(:on_variable_set).and_return(true)
          core.cmd_getg(name)
          @output.join.should =~ /^#{name} => $/
        end

        it "should show no value when only the module has this variable" do
          allow(core).to receive(:active_module).and_return(mod)
          allow(driver).to receive(:on_variable_set).and_return(true)
          core.cmd_set(name, 'MODULE')
          @output = []
          core.cmd_getg(name)
          @output.join.should =~ /^#{name} => $/
        end

        it "should show the framework's value when only the framework has this variable" do
          allow(core).to receive(:active_module).and_return(mod)
          allow(driver).to receive(:on_variable_set).and_return(true)
          core.cmd_setg(name, 'FRAMEWORK')
          @output = []
          core.cmd_getg(name)
          @output.join.should =~ /^#{name} => FRAMEWORK$/
        end

        it "should show the framework's value when both the module and the framework have this variable" do
          allow(core).to receive(:active_module).and_return(mod)
          allow(driver).to receive(:on_variable_set).and_return(true)
          core.cmd_setg(name, 'FRAMEWORK')
          core.cmd_set(name, 'MODULE')
          @output = []
          core.cmd_getg(name)
          @output.join.should =~ /^#{name} => FRAMEWORK$/
        end
      end
    end
  end
end
