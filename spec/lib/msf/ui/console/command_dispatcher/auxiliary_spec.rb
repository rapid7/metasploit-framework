require 'spec_helper'

RSpec.describe Msf::Ui::Console::CommandDispatcher::Auxiliary do
  include_context 'Msf::DBManager'
  include_context 'Msf::UIDriver'
  include_context 'Rex::Job#start run inline'
  include_context 'Msf::Framework#threads cleaner', verify_cleanup_required: false

  let(:aux_mod) do
    mod_klass = Class.new(Msf::Auxiliary) do
      def initialize
        super(
          'Name' => 'mock module',
          'Description' => 'mock module',
          'Author' => ['Unknown'],
          'License' => MSF_LICENSE
        )

        register_options(
          [
            Msf::Opt::RHOSTS,
            Msf::Opt::RPORT(3000),
            Msf::OptFloat.new('FloatValue', [false, 'A FloatValue which should be normalized before framework runs this module', 3.5])
          ]
        )
      end

      def check
        print_status("Checking for target #{datastore['RHOSTS']}:#{datastore['RPORT']} with normalized datastore value #{datastore['FloatValue'].inspect}")
      end

      def run
        print_status("Running for target #{datastore['RHOSTS']}:#{datastore['RPORT']} with normalized datastore value #{datastore['FloatValue'].inspect}")
      end

      def cleanup
        print_status("Cleanup for target #{datastore['RHOSTS']}:#{datastore['RPORT']}")
      end
    end

    mod = mod_klass.new
    datastore = Msf::ModuleDataStore.new(mod)
    allow(mod).to receive(:framework).and_return(framework)
    mod.send(:datastore=, datastore)
    datastore.import_options(mod.options)
    Msf::Simple::Framework.simplify_module(mod)
    mod
  end

  let(:smb_scanner_run_host_mod) do
    mod_klass = Class.new(Msf::Auxiliary) do
      include Msf::Exploit::Remote::DCERPC
      include Msf::Exploit::Remote::SMB::Client

      # Scanner mixin should be near last
      include Msf::Auxiliary::Scanner
      include Msf::Auxiliary::Report

      def initialize
        super(
          'Name' => 'mock smb module',
          'Description' => 'mock smb module',
          'Author' => ['Unknown'],
          'License' => MSF_LICENSE
        )

        register_options(
          [
            Msf::Opt::RPORT(445),
            Msf::OptFloat.new('FloatValue', [false, 'A FloatValue which should be normalized before framework runs this module', 3.5])
          ]
        )
      end

      def check_host(_ip)
        print_status("Checking for target #{datastore['RHOSTS']}:#{datastore['RPORT']} with normalized datastore value #{datastore['FloatValue'].inspect}")
      end

      def run_host(_ip)
        print_status("Running for target #{datastore['RHOSTS']}:#{datastore['RPORT']} with normalized datastore value #{datastore['FloatValue'].inspect}")
      end

      def cleanup
        print_status("Cleanup for target #{datastore['RHOSTS']}:#{datastore['RPORT']}")
      end
    end

    mod = mod_klass.new
    datastore = Msf::ModuleDataStore.new(mod)
    allow(mod).to receive(:framework).and_return(framework)
    mod.send(:datastore=, datastore)
    datastore.import_options(mod.options)
    Msf::Simple::Framework.simplify_module(mod)
    mod
  end

  let(:smb_scanner_run_batch_mod) do
    mod_klass = Class.new(Msf::Auxiliary) do
      include Msf::Exploit::Remote::DCERPC
      include Msf::Exploit::Remote::SMB::Client

      # Scanner mixin should be near last
      include Msf::Auxiliary::Scanner
      include Msf::Auxiliary::Report

      def initialize
        super(
          'Name' => 'mock smb module',
          'Description' => 'mock smb module',
          'Author' => ['Unknown'],
          'License' => MSF_LICENSE
        )

        register_options(
          [
            Msf::Opt::RPORT(445),
            Msf::OptFloat.new('FloatValue', [false, 'A FloatValue which should be normalized before framework runs this module', 3.5])
          ]
        )
      end

      def check_host(_ip)
        print_status("Checking for target #{datastore['RHOSTS']}:#{datastore['RPORT']} with normalized datastore value #{datastore['FloatValue'].inspect}")
      end

      def run_batch(batch)
        print_status("Running batch #{batch.inspect}:#{datastore['RPORT']} with normalized datastore value #{datastore['FloatValue'].inspect}")
      end

      def run_batch_size
        2
      end

      def cleanup
        print_status("Cleanup for target #{datastore['RHOSTS']}:#{datastore['RPORT']}")
      end
    end

    mod = mod_klass.new
    datastore = Msf::ModuleDataStore.new(mod)
    allow(mod).to receive(:framework).and_return(framework)
    mod.send(:datastore=, datastore)
    datastore.import_options(mod.options)
    Msf::Simple::Framework.simplify_module(mod)
    mod
  end

  subject do
    instance = described_class.new(driver)
    instance
  end

  before(:each) do
    run_rex_jobs_inline!
    allow(driver).to receive(:input).and_return(driver_input)
    allow(driver).to receive(:output).and_return(driver_output)
    current_mod.init_ui(driver_input, driver_output)
    allow(subject).to receive(:mod).and_return(current_mod)
  end

  describe '#cmd_check' do
    context 'when running a run_host scanner module' do
      let(:current_mod) { smb_scanner_run_host_mod }

      it 'reports missing RHOST values' do
        allow(current_mod).to receive(:run).and_call_original
        current_mod.datastore['RHOSTS'] = ''

        subject.cmd_check
        expected_output = [
          'Msf::OptionValidateError The following options failed to validate: RHOSTS'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'runs a single RHOST value' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1'
        subject.cmd_check
        expected_output = [
          '192.0.2.1:445         - Checking for target 192.0.2.1:445 with normalized datastore value 3.5',
          '192.0.2.1:445         - Cleanup for target 192.0.2.1:445',
          '192.0.2.1:445 - Check failed: The state could not be determined.'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'runs multiple RHOST values' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1 192.0.2.2'
        subject.cmd_check
        expected_output = [
          '192.0.2.1:445         - Checking for target 192.0.2.1:445 with normalized datastore value 3.5',
          '192.0.2.1:445         - Cleanup for target 192.0.2.1:445',
          '192.0.2.1:445 - Check failed: The state could not be determined.',
          'Checked 1 of 2 hosts (050% complete)',
          '192.0.2.2:445         - Checking for target 192.0.2.2:445 with normalized datastore value 3.5',
          '192.0.2.2:445         - Cleanup for target 192.0.2.2:445',
          '192.0.2.2:445 - Check failed: The state could not be determined.',
          'Checked 2 of 2 hosts (100% complete)'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'normalizes the datastore before running' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1 192.0.2.2'
        current_mod.datastore.store('FloatValue', '5.0')
        subject.cmd_check
        expected_output = [
          '192.0.2.1:445         - Checking for target 192.0.2.1:445 with normalized datastore value 5.0',
          '192.0.2.1:445         - Cleanup for target 192.0.2.1:445',
          '192.0.2.1:445 - Check failed: The state could not be determined.',
          'Checked 1 of 2 hosts (050% complete)',
          '192.0.2.2:445         - Checking for target 192.0.2.2:445 with normalized datastore value 5.0',
          '192.0.2.2:445         - Cleanup for target 192.0.2.2:445',
          '192.0.2.2:445 - Check failed: The state could not be determined.',
          'Checked 2 of 2 hosts (100% complete)'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'supports inline options' do
        current_mod.datastore.store('FloatValue', '5.0')
        subject.cmd_check('RHOSTS=192.0.2.5', 'FloatValue=10.0')
        expected_output = [
          '192.0.2.5:445         - Checking for target 192.0.2.5:445 with normalized datastore value 10.0',
          '192.0.2.5:445         - Cleanup for target 192.0.2.5:445',
          '192.0.2.5:445 - Check failed: The state could not be determined.',
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'supports multiple RHOST inline options' do
        current_mod.datastore.store('FloatValue', '5.0')
        subject.cmd_check('RHOSTS=192.0.2.5 192.0.2.6', 'FloatValue=10.0')
        expected_output = [
          '192.0.2.5:445         - Checking for target 192.0.2.5:445 with normalized datastore value 10.0',
          '192.0.2.5:445         - Cleanup for target 192.0.2.5:445',
          '192.0.2.5:445 - Check failed: The state could not be determined.',
          'Checked 1 of 2 hosts (050% complete)',
          '192.0.2.6:445         - Checking for target 192.0.2.6:445 with normalized datastore value 10.0',
          '192.0.2.6:445         - Cleanup for target 192.0.2.6:445',
          '192.0.2.6:445 - Check failed: The state could not be determined.',
          'Checked 2 of 2 hosts (100% complete)'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'supports targeting a single host as an inline argument' do
        subject.cmd_check('192.0.2.5')
        expected_output = [
          '192.0.2.5:445         - Checking for target 192.0.2.5:445 with normalized datastore value 3.5',
          '192.0.2.5:445         - Cleanup for target 192.0.2.5:445',
          '192.0.2.5:445 - Check failed: The state could not be determined.'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'supports targeting multiple hosts as an inline argument' do
        subject.cmd_check('192.0.2.5', '192.0.2.6')

        expected_output = [
          '192.0.2.5:445         - Checking for target 192.0.2.5:445 with normalized datastore value 3.5',
          '192.0.2.5:445         - Cleanup for target 192.0.2.5:445',
          '192.0.2.5:445 - Check failed: The state could not be determined.',
          'Checked 1 of 2 hosts (050% complete)',
          '192.0.2.6:445         - Checking for target 192.0.2.6:445 with normalized datastore value 3.5',
          '192.0.2.6:445         - Cleanup for target 192.0.2.6:445',
          '192.0.2.6:445 - Check failed: The state could not be determined.',
          'Checked 2 of 2 hosts (100% complete)'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'correctly handles unknown flags' do
        allow(subject.mod).to receive(:run)
        current_mod.datastore['RHOSTS'] = '192.0.2.1'
        subject.cmd_check('-unknown-flag')
        # Ensure the help menu is present
        expect(@combined_output).to include(/Usage: check /)
        expect(subject.mod).not_to have_received(:run)
      end
    end

    context 'when running an auxiliary module' do
      let(:current_mod) { aux_mod }

      it 'reports missing RHOST values' do
        allow(current_mod).to receive(:run).and_call_original
        current_mod.datastore['RHOSTS'] = ''
        subject.cmd_check
        expected_output = [
          'Msf::OptionValidateError The following options failed to validate: RHOSTS'
        ]

        expect(@combined_output).to match_array(expected_output)
        expect(subject.mod).not_to have_received(:run)
      end

      it 'runs a single RHOST value' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1'
        subject.cmd_check
        expected_output = [
          'Checking for target 192.0.2.1:3000 with normalized datastore value 3.5',
          'Cleanup for target 192.0.2.1:3000',
          '192.0.2.1:3000 - Check failed: The state could not be determined.'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'runs multiple RHOST values' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1 192.0.2.2'
        subject.cmd_check
        expected_output = [
          'Checking for target 192.0.2.1:3000 with normalized datastore value 3.5',
          'Cleanup for target 192.0.2.1:3000',
          '192.0.2.1:3000 - Check failed: The state could not be determined.',
          'Checking for target 192.0.2.2:3000 with normalized datastore value 3.5',
          'Cleanup for target 192.0.2.2:3000',
          '192.0.2.2:3000 - Check failed: The state could not be determined.'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'normalizes the datastore before running' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1 192.0.2.2'
        current_mod.datastore.store('FloatValue', '5.0')
        subject.cmd_check
        expected_output = [
          'Checking for target 192.0.2.1:3000 with normalized datastore value 5.0',
          'Cleanup for target 192.0.2.1:3000',
          '192.0.2.1:3000 - Check failed: The state could not be determined.',
          'Checking for target 192.0.2.2:3000 with normalized datastore value 5.0',
          'Cleanup for target 192.0.2.2:3000',
          '192.0.2.2:3000 - Check failed: The state could not be determined.'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'supports inline options' do
        current_mod.datastore.store('FloatValue', '5.0')
        subject.cmd_check('RHOSTS=192.0.2.5', 'FloatValue=10.0')
        expected_output = [
          'Checking for target 192.0.2.5:3000 with normalized datastore value 10.0',
          'Cleanup for target 192.0.2.5:3000',
          '192.0.2.5:3000 - Check failed: The state could not be determined.',
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'supports multiple inlined RHOST values' do
        current_mod.datastore.store('FloatValue', '5.0')
        subject.cmd_check('RHOSTS=192.0.2.5 192.0.2.6', 'FloatValue=10.0')
        expected_output = [
          'Checking for target 192.0.2.5:3000 with normalized datastore value 10.0',
          'Cleanup for target 192.0.2.5:3000',
          '192.0.2.5:3000 - Check failed: The state could not be determined.',
          'Checking for target 192.0.2.6:3000 with normalized datastore value 10.0',
          'Cleanup for target 192.0.2.6:3000',
          '192.0.2.6:3000 - Check failed: The state could not be determined.',
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'ignores the -j flag, and the module is not run as a job' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1'
        subject.cmd_check('-j')
        expected_output = [
          'Checking for target 192.0.2.1:3000 with normalized datastore value 3.5',
          'Cleanup for target 192.0.2.1:3000',
          '192.0.2.1:3000 - Check failed: The state could not be determined.'
        ]

        expect(@combined_output).to match_array(expected_output)
      end
    end
  end

  describe '#cmd_run' do
    context 'when running a scanner run_host module' do
      let(:current_mod) { smb_scanner_run_host_mod }

      it 'reports missing RHOST values' do
        allow(current_mod).to receive(:run).and_call_original
        current_mod.datastore['RHOSTS'] = ''

        subject.cmd_run
        expected_output = [
          'Msf::OptionValidateError The following options failed to validate: RHOSTS'
        ]

        expect(@combined_output).to match_array(expected_output)
        expect(subject.mod).not_to have_received(:run)
      end

      it 'runs a single RHOST value' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1'
        subject.cmd_run
        expected_output = [
          '192.0.2.1:445         - Running for target 192.0.2.1:445 with normalized datastore value 3.5',
          '192.0.2.1:445         - Cleanup for target 192.0.2.1:445',
          '192.0.2.1:445         - Scanned 1 of 1 hosts (100% complete)',
          '192.0.2.1:445         - Cleanup for target 192.0.2.1:445',
          'Auxiliary module execution completed'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'runs multiple RHOST values' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1 192.0.2.2'
        subject.cmd_run
        expected_output = [
          '192.0.2.1:445         - Running for target 192.0.2.1:445 with normalized datastore value 3.5',
          '192.0.2.1:445         - Cleanup for target 192.0.2.1:445',
          'Scanned 1 of 2 hosts (50% complete)',
          '192.0.2.2:445         - Running for target 192.0.2.2:445 with normalized datastore value 3.5',
          '192.0.2.2:445         - Cleanup for target 192.0.2.2:445',
          'Scanned 2 of 2 hosts (100% complete)',
          'Cleanup for target 192.0.2.1 192.0.2.2:445',
          'Auxiliary module execution completed'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'normalizes the datastore before running' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1 192.0.2.2'
        current_mod.datastore.store('FloatValue', '5.0')
        subject.cmd_run
        expected_output = [
          '192.0.2.1:445         - Running for target 192.0.2.1:445 with normalized datastore value 5.0',
          '192.0.2.1:445         - Cleanup for target 192.0.2.1:445',
          'Scanned 1 of 2 hosts (50% complete)',
          '192.0.2.2:445         - Running for target 192.0.2.2:445 with normalized datastore value 5.0',
          '192.0.2.2:445         - Cleanup for target 192.0.2.2:445',
          'Scanned 2 of 2 hosts (100% complete)',
          'Cleanup for target 192.0.2.1 192.0.2.2:445',
          'Auxiliary module execution completed'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'supports inline options' do
        current_mod.datastore.store('FloatValue', '5.0')
        subject.cmd_run('RHOSTS=192.0.2.5', 'FloatValue=10.0')
        expected_output = [
          '192.0.2.5:445         - Running for target 192.0.2.5:445 with normalized datastore value 10.0',
          '192.0.2.5:445         - Cleanup for target 192.0.2.5:445',
          '192.0.2.5:445         - Scanned 1 of 1 hosts (100% complete)',
          '192.0.2.5:445         - Cleanup for target 192.0.2.5:445',
          'Auxiliary module execution completed'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'supports multiple RHOST inline options' do
        current_mod.datastore.store('FloatValue', '5.0')
        subject.cmd_run('RHOSTS=192.0.2.5', 'RHOSTS=192.0.2.6', 'FloatValue=10.0')
        expected_output = [
          '192.0.2.5:445         - Running for target 192.0.2.5:445 with normalized datastore value 10.0',
          '192.0.2.5:445         - Cleanup for target 192.0.2.5:445',
          'Scanned 1 of 2 hosts (50% complete)',
          '192.0.2.6:445         - Running for target 192.0.2.6:445 with normalized datastore value 10.0',
          '192.0.2.6:445         - Cleanup for target 192.0.2.6:445',
          'Scanned 2 of 2 hosts (100% complete)',
          'Cleanup for target 192.0.2.5 192.0.2.6:445',
          'Auxiliary module execution completed'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'runs the scanner as a background job when the -j flag is used' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1'
        subject.cmd_run('-j')
        expected_output = [
          '192.0.2.1:445         - Running rex job 0 inline',
          '192.0.2.1:445         - Running for target 192.0.2.1:445 with normalized datastore value 3.5',
          '192.0.2.1:445         - Cleanup for target 192.0.2.1:445',
          '192.0.2.1:445         - Scanned 1 of 1 hosts (100% complete)',
          'Auxiliary module running as background job 0.'
        ]

        expect(@combined_output).to match_array(expected_output)
      end
    end

    context 'when running a scanner run_batch module' do
      let(:current_mod) { smb_scanner_run_batch_mod }

      it 'reports missing RHOST values' do
        allow(current_mod).to receive(:run).and_call_original
        current_mod.datastore['RHOSTS'] = ''

        subject.cmd_run
        expected_output = [
          'Msf::OptionValidateError The following options failed to validate: RHOSTS'
        ]

        expect(@combined_output).to match_array(expected_output)
        expect(subject.mod).not_to have_received(:run)
      end

      it 'runs a single RHOST value' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1'
        subject.cmd_run
        expected_output = [
          '192.0.2.1:445         - Running batch ["192.0.2.1"]:445 with normalized datastore value 3.5',
          '192.0.2.1:445         - Cleanup for target 192.0.2.1:445',
          '192.0.2.1:445         - Scanned 1 of 1 hosts (100% complete)',
          '192.0.2.1:445         - Cleanup for target 192.0.2.1:445',
          'Auxiliary module execution completed'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'runs multiple RHOST values' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1 192.0.2.2'
        subject.cmd_run
        expected_output = [
          'Running batch ["192.0.2.1", "192.0.2.2"]:445 with normalized datastore value 3.5',
          'Cleanup for target 192.0.2.1 192.0.2.2:445',
          'Scanned 2 of 2 hosts (100% complete)',
          'Cleanup for target 192.0.2.1 192.0.2.2:445',
          'Auxiliary module execution completed'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'normalizes the datastore before running' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1 192.0.2.2'
        current_mod.datastore.store('FloatValue', '5.0')
        subject.cmd_run
        expected_output = [
          'Running batch ["192.0.2.1", "192.0.2.2"]:445 with normalized datastore value 5.0',
          'Cleanup for target 192.0.2.1 192.0.2.2:445',
          'Scanned 2 of 2 hosts (100% complete)',
          'Cleanup for target 192.0.2.1 192.0.2.2:445',
          'Auxiliary module execution completed'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'supports inline options' do
        current_mod.datastore.store('FloatValue', '5.0')
        subject.cmd_run('RHOSTS=192.0.2.5', 'FloatValue=10.0')
        expected_output = [
          '192.0.2.5:445         - Running batch ["192.0.2.5"]:445 with normalized datastore value 10.0',
          '192.0.2.5:445         - Cleanup for target 192.0.2.5:445',
          '192.0.2.5:445         - Scanned 1 of 1 hosts (100% complete)',
          '192.0.2.5:445         - Cleanup for target 192.0.2.5:445',
          'Auxiliary module execution completed'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'supports multiple RHOST inline options' do
        current_mod.datastore.store('FloatValue', '5.0')
        subject.cmd_run('RHOSTS=192.0.2.5', 'RHOSTS=192.0.2.6', 'FloatValue=10.0')
        expected_output = [
          'Running batch ["192.0.2.5", "192.0.2.6"]:445 with normalized datastore value 10.0',
          'Cleanup for target 192.0.2.5 192.0.2.6:445',
          'Scanned 2 of 2 hosts (100% complete)',
          'Cleanup for target 192.0.2.5 192.0.2.6:445',
          'Auxiliary module execution completed'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'runs the scanner as a background job when the -j flag is used' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1'
        subject.cmd_run('-j')
        expected_output = [
          '192.0.2.1:445         - Running rex job 0 inline',
          '192.0.2.1:445         - Running batch ["192.0.2.1"]:445 with normalized datastore value 3.5',
          '192.0.2.1:445         - Cleanup for target 192.0.2.1:445',
          '192.0.2.1:445         - Scanned 1 of 1 hosts (100% complete)',
          'Auxiliary module running as background job 0.'
        ]

        expect(@combined_output).to match_array(expected_output)
      end
    end

    context 'when running an auxiliary module' do
      let(:current_mod) { aux_mod }

      it 'reports missing RHOST values' do
        allow(current_mod).to receive(:run).and_call_original
        current_mod.datastore['RHOSTS'] = ''
        subject.cmd_run
        expected_output = [
          'Msf::OptionValidateError The following options failed to validate: RHOSTS'
        ]

        expect(@combined_output).to match_array(expected_output)
        expect(subject.mod).not_to have_received(:run)
      end

      it 'runs a single RHOST value' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1'
        subject.cmd_run
        expected_output = [
          'Running module against 192.0.2.1',
          'Running for target 192.0.2.1:3000 with normalized datastore value 3.5',
          'Cleanup for target 192.0.2.1:3000',
          'Auxiliary module execution completed'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'runs multiple RHOST values' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1 192.0.2.2'
        subject.cmd_run
        expected_output = [
          'Running module against 192.0.2.1',
          'Running for target 192.0.2.1:3000 with normalized datastore value 3.5',
          'Cleanup for target 192.0.2.1:3000',
          'Running module against 192.0.2.2',
          'Running for target 192.0.2.2:3000 with normalized datastore value 3.5',
          'Cleanup for target 192.0.2.2:3000',
          'Auxiliary module execution completed'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'normalizes the datastore before running' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1 192.0.2.2'
        current_mod.datastore.store('FloatValue', '5.0')
        subject.cmd_run
        expected_output = [
          'Running module against 192.0.2.1',
          'Running for target 192.0.2.1:3000 with normalized datastore value 5.0',
          'Cleanup for target 192.0.2.1:3000',
          'Running module against 192.0.2.2',
          'Running for target 192.0.2.2:3000 with normalized datastore value 5.0',
          'Cleanup for target 192.0.2.2:3000',
          'Auxiliary module execution completed'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'supports inline options' do
        current_mod.datastore.store('FloatValue', '5.0')
        subject.cmd_run('RHOSTS=192.0.2.5', 'FloatValue=10.0')
        expected_output = [
          'Running module against 192.0.2.5',
          'Running for target 192.0.2.5:3000 with normalized datastore value 10.0',
          'Cleanup for target 192.0.2.5:3000',
          'Auxiliary module execution completed'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'supports multiple inlined RHOST values' do
        current_mod.datastore.store('FloatValue', '5.0')
        subject.cmd_run('RHOSTS=192.0.2.5 192.0.2.6', 'FloatValue=10.0')
        expected_output = [
          'Running module against 192.0.2.5',
          'Running for target 192.0.2.5:3000 with normalized datastore value 10.0',
          'Cleanup for target 192.0.2.5:3000',
          'Running module against 192.0.2.6',
          'Running for target 192.0.2.6:3000 with normalized datastore value 10.0',
          'Cleanup for target 192.0.2.6:3000',
          'Auxiliary module execution completed'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'supports multiple http RHOST inline options' do
        current_mod.datastore.store('FloatValue', '5.0')
        subject.cmd_run('rhosts=http://127.0.0.1:8080', 'rhosts=http://127.0.0.1', 'FloatValue=10.0')
        expected_output = [
          'Running module against 127.0.0.1',
          'Running for target 127.0.0.1:8080 with normalized datastore value 10.0',
          'Cleanup for target 127.0.0.1:8080',
          'Running module against 127.0.0.1',
          'Running for target 127.0.0.1:80 with normalized datastore value 10.0',
          'Cleanup for target 127.0.0.1:80',
          'Auxiliary module execution completed'
        ]

        expect(@combined_output).to match_array(expected_output)
      end

      it 'ignores the -j flag, and the module is not run as a job' do
        current_mod.datastore['RHOSTS'] = '192.0.2.1'
        subject.cmd_run('-j')
        expected_output = [
          'Running module against 192.0.2.1',
          'Running for target 192.0.2.1:3000 with normalized datastore value 3.5',
          'Cleanup for target 192.0.2.1:3000',
          'Auxiliary module execution completed'
        ]

        expect(@combined_output).to match_array(expected_output)
      end
    end
  end

  describe '#cmd_rerun' do
  end

  describe '#cmd_exploit' do
  end

  describe '#cmd_reload' do
  end
end
