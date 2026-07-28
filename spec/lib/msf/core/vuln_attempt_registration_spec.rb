# frozen_string_literal: true

require 'spec_helper'

# Integration-level specs verifying that vulns and vuln_attempts are correctly
# registered for auxiliary and exploit module execution scenarios.  These tests
# exercise the real framework plumbing (cmd_check / cmd_run via the console
# dispatchers, job_run_proc, report_failure, etc.)
RSpec.describe 'Vuln and VulnAttempt registration', if: !ENV['REMOTE_DB'] do
  include_context 'Msf::DBManager'
  include_context 'Msf::UIDriver'
  include_context 'Rex::Job#start run inline'
  include_context 'Msf::Framework#threads cleaner', verify_cleanup_required: false

  let(:check_detail_message) { 'Service is vulnerable to CVE-2025-99999' }
  let(:vulnerable_check_code) { Msf::Exploit::CheckCode::Vulnerable(check_detail_message) }
  let(:safe_check_code) { Msf::Exploit::CheckCode::Safe('Not vulnerable') }
  let(:appears_check_code) { Msf::Exploit::CheckCode::Appears('Likely vulnerable') }

  subject(:db) { Msf::Ui::Console::CommandDispatcher::Db.new(driver) }

  # Build a module from a class, wired to the test framework
  def build_module(klass)
    mod = klass.new
    allow(mod).to receive(:framework).and_return(framework)
    datastore = Msf::ModuleDataStore.new(mod)
    mod.send(:datastore=, datastore)
    datastore.import_options(mod.options)
    Msf::Simple::Framework.simplify_module(mod)
    mod
  end

  let(:aux_dispatcher) do
    Msf::Ui::Console::CommandDispatcher::Auxiliary.new(driver)
  end

  let(:exploit_dispatcher) do
    Msf::Ui::Console::CommandDispatcher::Exploit.new(driver)
  end

  before(:each) do
    run_rex_jobs_inline!
    allow(driver).to receive(:input).and_return(driver_input)
    allow(driver).to receive(:output).and_return(driver_output)
  end

  # ---------------------------------------------------------------------------
  # Scanner module classes used across multiple describe blocks
  # ---------------------------------------------------------------------------

  # Base scanner module class — uses class-level accessor so check_host
  # behavior survives module replication.
  let(:scanner_module_class) do
    klass = Class.new(Msf::Auxiliary) do
      include Msf::Exploit::Remote::Tcp
      include Msf::Auxiliary::Scanner
      include Msf::Auxiliary::Report

      class << self
        attr_accessor :injected_check_code
      end

      def initialize(info = {})
        super(
          update_info(
            info,
            'Name'        => 'Test Module',
            'Description' => 'Test',
            'Author'      => ['test'],
            'License'     => MSF_LICENSE,
            'References'  => [['CVE', '2025-99999']],
            'Notes'       => { 'SideEffects' => [], 'Stability' => [], 'Reliability' => [] }
          )
        )
        register_options([Msf::Opt::RPORT(1234)])
      end

      def check_host(_ip)
        self.class.injected_check_code
      end

      def run_host(_ip)
        raise 'should be stubbed'
      end

      def cleanup; end
    end
    klass.refname = 'scanner/test/test_module'
    klass
  end

  # Scanner whose check_host calls report_vuln before returning a CheckCode,
  # mimicking modules like ms12_020_check that call report_goods.
  let(:check_reporting_scanner_class) do
    klass = Class.new(Msf::Auxiliary) do
      include Msf::Exploit::Remote::Tcp
      include Msf::Auxiliary::Scanner
      include Msf::Auxiliary::Report

      class << self
        attr_accessor :injected_check_code
      end

      def initialize(info = {})
        super(
          update_info(
            info,
            'Name'        => 'Test Check Reporter',
            'Description' => 'Scanner whose check_host calls report_vuln',
            'Author'      => ['test'],
            'License'     => MSF_LICENSE,
            'References'  => [['CVE', '2025-99999']],
            'Notes'       => { 'SideEffects' => [], 'Stability' => [], 'Reliability' => [] }
          )
        )
        register_options([Msf::Opt::RPORT(1234)])
      end

      def check_host(_ip)
        report_vuln(
          host: datastore['RHOST'],
          port: rport,
          proto: 'tcp',
          name: self.name,
          info: 'Response indicates a missing patch',
          refs: self.references
        )
        self.class.injected_check_code
      end

      def run_host(_ip)
        raise 'should not be called during check'
      end

      def cleanup; end
    end
    klass.refname = 'scanner/test/check_reporter'
    klass
  end

  # Scanner whose run_host calls report_vuln with a check_code.
  let(:vuln_reporting_scanner_class) do
    klass = Class.new(Msf::Auxiliary) do
      include Msf::Exploit::Remote::Tcp
      include Msf::Auxiliary::Scanner
      include Msf::Auxiliary::Report

      class << self
        attr_accessor :injected_check_code
      end

      def initialize(info = {})
        super(
          update_info(
            info,
            'Name'        => 'Test Vuln Scanner',
            'Description' => 'Scanner that reports vulns from run_host',
            'Author'      => ['test'],
            'License'     => MSF_LICENSE,
            'References'  => [['CVE', '2025-99999']],
            'Notes'       => { 'SideEffects' => [], 'Stability' => [], 'Reliability' => [] }
          )
        )

        register_options([Msf::Opt::RPORT(22)])
      end

      def run_host(ip)
        report_vuln(
          host: ip,
          port: rport,
          proto: 'tcp',
          name: name,
          refs: self.references,
          info: "SSH Host Key Encryption ecdsa-sha2-nistp256 is available, but should be deprecated",
          check_code: self.class.injected_check_code
        )
      end

      def cleanup; end
    end
    klass.refname = 'scanner/test/vuln_scanner'
    klass
  end

  # Scanner whose run_host does NOT call report_vuln.
  let(:clean_scanner_class) do
    klass = Class.new(Msf::Auxiliary) do
      include Msf::Exploit::Remote::Tcp
      include Msf::Auxiliary::Scanner
      include Msf::Auxiliary::Report

      def initialize(info = {})
        super(
          update_info(
            info,
            'Name'        => 'Test Clean Scanner',
            'Description' => 'Scanner that does not report vulns',
            'Author'      => ['test'],
            'License'     => MSF_LICENSE,
            'References'  => [['CVE', '2025-99999']],
            'Notes'       => { 'SideEffects' => [], 'Stability' => [], 'Reliability' => [] }
          )
        )

        register_options([Msf::Opt::RPORT(22)])
      end

      def run_host(_ip)
        print_status("Scanned #{datastore['RHOST']}")
      end

      def cleanup; end
    end
    klass.refname = 'scanner/test/clean_scanner'
    klass
  end

  # Scanner that only reports a vuln for hosts in the vulnerable_hosts set.
  let(:selective_scanner_class) do
    klass = Class.new(Msf::Auxiliary) do
      include Msf::Exploit::Remote::Tcp
      include Msf::Auxiliary::Scanner
      include Msf::Auxiliary::Report

      class << self
        attr_accessor :vulnerable_hosts, :injected_check_code
      end

      def initialize(info = {})
        super(
          update_info(
            info,
            'Name'        => 'Test Selective Scanner',
            'Description' => 'Reports vulns only for selected hosts',
            'Author'      => ['test'],
            'License'     => MSF_LICENSE,
            'References'  => [['CVE', '2025-99999']],
            'Notes'       => { 'SideEffects' => [], 'Stability' => [], 'Reliability' => [] }
          )
        )

        register_options([Msf::Opt::RPORT(22)])
      end

      def run_host(ip)
        return unless self.class.vulnerable_hosts&.include?(ip)

        report_vuln(
          host: ip,
          port: rport,
          proto: 'tcp',
          name: name,
          refs: self.references,
          info: "Deprecated algorithm on #{ip}",
          check_code: self.class.injected_check_code
        )
      end

      def cleanup; end
    end
    klass.refname = 'scanner/test/selective_scanner'
    klass
  end

  # Non-scanner auxiliary module class for AutoCheck scenarios.
  # Uses class-level accessors so behavior survives replication.
  let(:simple_module_class) do
    Class.new(Msf::Auxiliary) do
      include Msf::Exploit::Remote::Tcp
      include Msf::Auxiliary::Report

      class << self
        attr_accessor :injected_check_code, :run_called
      end

      def initialize(info = {})
        super(
          update_info(
            info,
            'Name'        => 'Test AutoCheck Module',
            'Description' => 'Test',
            'Author'      => ['test'],
            'License'     => MSF_LICENSE,
            'References'  => [['CVE', '2025-99999']],
            'Notes'       => { 'SideEffects' => [], 'Stability' => [], 'Reliability' => [] }
          )
        )
        register_options([Msf::Opt::RHOSTS, Msf::Opt::RPORT(1234)])
      end

      def check
        self.class.injected_check_code
      end

      def run
        self.class.run_called = true
      end
    end
  end

  # Exploit module class for AutoCheck scenarios.
  # Uses class-level accessors so behavior survives replication.
  let(:exploit_module_class) do
    klass = Class.new(Msf::Exploit) do
      include Msf::Exploit::Remote::Tcp
      include Msf::Auxiliary::Report

      class << self
        attr_accessor :injected_check_code, :exploit_called
      end

      def initialize(info = {})
        super(
          update_info(
            info,
            'Name'        => 'Test Exploit Module',
            'Description' => 'Test exploit for vuln attempt registration',
            'Author'      => ['test'],
            'License'     => MSF_LICENSE,
            'References'  => [['CVE', '2025-99999']],
            'Targets'     => [['Automatic', {}]],
            'DefaultTarget' => 0,
            'Arch'        => ARCH_CMD,
            'Platform'    => ['unix'],
            'DisclosureDate' => '2025-01-01',
            'Notes'       => { 'SideEffects' => [], 'Stability' => [], 'Reliability' => [] }
          )
        )
        register_options([Msf::Opt::RHOSTS, Msf::Opt::RPORT(1234)])
      end

      def check
        self.class.injected_check_code
      end

      def exploit
        self.class.exploit_called = true
      end
    end
    klass.refname = 'test/test_exploit_module'
    klass
  end


  context 'when running an auxiliary module' do
    # ---------------------------------------------------------------------------
    # cmd_check — scanner module
    # ---------------------------------------------------------------------------
    describe 'cmd_check on a scanner module' do
      let(:current_mod) do
        scanner_module_class.injected_check_code = nil
        build_module(scanner_module_class)
      end

      before(:each) do
        current_mod.init_ui(driver_input, driver_output)
        allow(aux_dispatcher).to receive(:mod).and_return(current_mod)
      end

      context 'when check returns Vulnerable' do
        before do
          scanner_module_class.injected_check_code = vulnerable_check_code
          current_mod.datastore['RHOSTS'] = '192.0.2.1'
          aux_dispatcher.cmd_check
        end

        it 'creates exactly one vuln' do
          expect(Mdm::Vuln.count).to eq(1)
        end

        it 'creates exactly one vuln attempt' do
          expect(Mdm::VulnAttempt.count).to eq(1)
        end

        it 'sets check_code to vulnerable on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_code).to eq('vulnerable')
        end

        it 'sets check_detail on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_detail).to eq(check_detail_message)
        end

        it 'does not set exploited on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.exploited).to eq(false)
        end

        it 'sets fail_reason to none' do
          expect(Mdm::VulnAttempt.last.fail_reason).to eq(Msf::Module::Failure::None)
        end

        it 'displays check details in vulns -v' do
          vuln = Mdm::Vuln.last
          vuln_attempt = Mdm::VulnAttempt.last
          service_str = vuln.service.present? ? "#{vuln.service.name} (port: #{vuln.service.port}, resource: #{vuln.service.resource.to_json})" : ''
          @output = []
          db.cmd_vulns "-v"
          expect(@output.join("\n")).to match_table <<~TABLE
            Vulnerabilities
            ===============
              0. Vuln ID: #{vuln.id}
                 Timestamp: #{vuln.created_at}
                 Host: 192.0.2.1
                 Name: Test Module
                 References: CVE-2025-99999
                 Information: Vulnerability confirmed by check of auxiliary/scanner/test/test_module.
                 Resource: {}
                 Service: #{service_str}
                 Vuln attempts:
                 0. ID: #{vuln_attempt.id}
                    Vuln ID: #{vuln.id}
                    Timestamp: #{vuln_attempt.attempted_at}
                    Exploit: false
                    Fail reason: none
                    Username: #{vuln_attempt.username}
                    Module: auxiliary/scanner/test/test_module
                    Session ID: nil
                    Loot ID: nil
                    Fail Detail: nil
                    Check Code: vulnerable
                    Check Detail: #{check_detail_message}
          TABLE
        end
      end

      context 'when check returns Safe' do
        before do
          scanner_module_class.injected_check_code = safe_check_code
          current_mod.datastore['RHOSTS'] = '192.0.2.1'
          aux_dispatcher.cmd_check
        end

        it 'does not create a vuln' do
          expect(Mdm::Vuln.count).to eq(0)
        end

        it 'does not create a vuln attempt' do
          expect(Mdm::VulnAttempt.count).to eq(0)
        end
      end

      context 'when check returns Appears' do
        before do
          scanner_module_class.injected_check_code = appears_check_code
          current_mod.datastore['RHOSTS'] = '192.0.2.1'
          aux_dispatcher.cmd_check
        end

        it 'creates exactly one vuln' do
          expect(Mdm::Vuln.count).to eq(1)
        end

        it 'creates exactly one vuln attempt' do
          expect(Mdm::VulnAttempt.count).to eq(1)
        end

        it 'sets check_code to appears on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_code).to eq('appears')
        end

        it 'sets check_detail on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_detail).to eq('Likely vulnerable')
        end
      end
    end

    # ---------------------------------------------------------------------------
    # cmd_check — port-specific vuln registration
    # ---------------------------------------------------------------------------
    describe 'cmd_check with different ports on the same host' do
      let(:current_mod) do
        scanner_module_class.injected_check_code = nil
        build_module(scanner_module_class)
      end

      before(:each) do
        current_mod.init_ui(driver_input, driver_output)
        allow(aux_dispatcher).to receive(:mod).and_return(current_mod)
      end

      context 'when check returns Vulnerable on two different ports' do
        before do
          scanner_module_class.injected_check_code = vulnerable_check_code

          current_mod.datastore['RHOSTS'] = '192.0.2.1'
          current_mod.datastore['RPORT'] = 80
          aux_dispatcher.cmd_check

          current_mod.datastore['RPORT'] = 8080
          aux_dispatcher.cmd_check
        end

        it 'creates two separate vulns (one per port)' do
          expect(Mdm::Vuln.count).to eq(2)
        end

        it 'creates two vuln attempts (one per vuln)' do
          expect(Mdm::VulnAttempt.count).to eq(2)
        end

        it 'associates each vuln with a different service port' do
          ports = Mdm::Vuln.all.map { |v| v.service&.port }.compact.sort
          expect(ports).to eq([80, 8080])
        end
      end

      context 'when check returns Vulnerable on the same port twice' do
        before do
          scanner_module_class.injected_check_code = vulnerable_check_code

          current_mod.datastore['RHOSTS'] = '192.0.2.1'
          current_mod.datastore['RPORT'] = 80
          aux_dispatcher.cmd_check
          aux_dispatcher.cmd_check
        end

        it 'creates only one vuln (deduplicates by host+port+name)' do
          expect(Mdm::Vuln.count).to eq(1)
        end

        it 'creates two vuln attempts against the same vuln' do
          expect(Mdm::VulnAttempt.count).to eq(2)
          expect(Mdm::VulnAttempt.pluck(:vuln_id).uniq.size).to eq(1)
        end
      end

      context 'when check returns Vulnerable on one port and Safe on another' do
        before do
          current_mod.datastore['RHOSTS'] = '192.0.2.1'

          # First check on port 9200 — vulnerable
          current_mod.datastore['RPORT'] = 9200
          scanner_module_class.injected_check_code = vulnerable_check_code
          aux_dispatcher.cmd_check

          # Second check on port 80 — safe (different service entirely)
          current_mod.datastore['RPORT'] = 80
          scanner_module_class.injected_check_code = safe_check_code
          aux_dispatcher.cmd_check
        end

        it 'creates only one vuln (for the vulnerable port)' do
          expect(Mdm::Vuln.count).to eq(1)
        end

        it 'creates only one vuln attempt (Safe check on a different port does not attach to the existing vuln)' do
          expect(Mdm::VulnAttempt.count).to eq(1)
        end

        it 'associates the vuln with the vulnerable port' do
          expect(Mdm::Vuln.last.service.port).to eq(9200)
        end

        it 'sets check_code to vulnerable on the single vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_code).to eq('vulnerable')
        end
      end
    end

    # ---------------------------------------------------------------------------
    # cmd_check — scanner replicant check flow (ms12_020-style)
    #
    # When check_host calls report_vuln internally, MultipleTargetHosts#check
    # creates a replicant.  The last_vuln_attempt must propagate back
    # so report_failure does not create a duplicate.
    # ---------------------------------------------------------------------------
    describe 'cmd_check — scanner replicant check flow (report_vuln inside check_host)' do
      before(:each) do
        current_mod.init_ui(driver_input, driver_output)
        allow(aux_dispatcher).to receive(:mod).and_return(current_mod)
      end

      context 'when check_host reports a vuln and returns Vulnerable' do
        let(:current_mod) do
          check_reporting_scanner_class.injected_check_code = vulnerable_check_code
          build_module(check_reporting_scanner_class)
        end

        before do
          current_mod.datastore['RHOSTS'] = '192.0.2.1'
          aux_dispatcher.cmd_check
        end

        it 'creates exactly one vuln' do
          expect(Mdm::Vuln.count).to eq(1)
        end

        it 'creates exactly one vuln attempt (no duplicate from report_failure)' do
          expect(Mdm::VulnAttempt.count).to eq(1)
        end

        it 'sets check_code to vulnerable on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_code).to eq('vulnerable')
        end

        it 'sets check_detail on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_detail).to eq(check_detail_message)
        end

        it 'sets fail_reason to none (not Untried)' do
          expect(Mdm::VulnAttempt.last.fail_reason).to eq(Msf::Module::Failure::None)
        end

        it 'clears the placeholder fail_detail' do
          expect(Mdm::VulnAttempt.last.fail_detail).to be_nil
        end

        it 'does not set exploited on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.exploited).to be_falsey
        end
      end

      context 'when check_host reports a vuln and returns Appears' do
        let(:current_mod) do
          check_reporting_scanner_class.injected_check_code = appears_check_code
          build_module(check_reporting_scanner_class)
        end

        before do
          current_mod.datastore['RHOSTS'] = '192.0.2.1'
          aux_dispatcher.cmd_check
        end

        it 'creates exactly one vuln' do
          expect(Mdm::Vuln.count).to eq(1)
        end

        it 'creates exactly one vuln attempt' do
          expect(Mdm::VulnAttempt.count).to eq(1)
        end

        it 'sets check_code to appears on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_code).to eq('appears')
        end

        it 'sets check_detail on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_detail).to eq('Likely vulnerable')
        end

        it 'sets fail_reason to none' do
          expect(Mdm::VulnAttempt.last.fail_reason).to eq(Msf::Module::Failure::None)
        end
      end

      context 'when check_host returns Safe (no report_vuln call)' do
        let(:safe_scanner_class) do
          klass = Class.new(Msf::Auxiliary) do
            include Msf::Exploit::Remote::Tcp
            include Msf::Auxiliary::Scanner
            include Msf::Auxiliary::Report

            def initialize(info = {})
              super(
                update_info(
                  info,
                  'Name'        => 'Test Safe Check Reporter',
                  'Description' => 'Scanner whose check_host returns Safe',
                  'Author'      => ['test'],
                  'License'     => MSF_LICENSE,
                  'References'  => [['CVE', '2025-99999']],
                  'Notes'       => { 'SideEffects' => [], 'Stability' => [], 'Reliability' => [] }
                )
              )
              register_options([Msf::Opt::RPORT(1234)])
            end

            def check_host(_ip)
              Msf::Exploit::CheckCode::Safe('Not vulnerable')
            end

            def run_host(_ip)
              raise 'should not be called during check'
            end

            def cleanup; end
          end
          klass.refname = 'scanner/test/safe_check_reporter'
          klass
        end

        let(:current_mod) { build_module(safe_scanner_class) }

        before do
          current_mod.datastore['RHOSTS'] = '192.0.2.1'
          aux_dispatcher.cmd_check
        end

        it 'does not create a vuln' do
          expect(Mdm::Vuln.count).to eq(0)
        end

        it 'does not create a vuln attempt' do
          expect(Mdm::VulnAttempt.count).to eq(0)
        end
      end

      context 'when check_host reports a vuln on two different ports' do
        let(:current_mod) do
          check_reporting_scanner_class.injected_check_code = vulnerable_check_code
          build_module(check_reporting_scanner_class)
        end

        before do
          current_mod.datastore['RHOSTS'] = '192.0.2.1'

          current_mod.datastore['RPORT'] = 3389
          aux_dispatcher.cmd_check

          current_mod.datastore['RPORT'] = 3390
          aux_dispatcher.cmd_check
        end

        it 'creates two separate vulns (one per port)' do
          expect(Mdm::Vuln.count).to eq(2)
        end

        it 'creates two vuln attempts (one per vuln)' do
          expect(Mdm::VulnAttempt.count).to eq(2)
        end

        it 'associates each vuln attempt with the correct port' do
          Mdm::VulnAttempt.find_each do |attempt|
            vuln_port = attempt.vuln.service&.port
            expect([3389, 3390]).to include(vuln_port)
          end
        end

        it 'sets check_code on both vuln attempts' do
          Mdm::VulnAttempt.find_each do |attempt|
            expect(attempt.check_code).to eq('vulnerable')
          end
        end

        it 'sets check_detail on both vuln attempts' do
          Mdm::VulnAttempt.find_each do |attempt|
            expect(attempt.check_detail).to eq(check_detail_message)
          end
        end

        it 'sets fail_reason to none on both vuln attempts' do
          Mdm::VulnAttempt.find_each do |attempt|
            expect(attempt.fail_reason).to eq(Msf::Module::Failure::None)
          end
        end
      end
    end

    # ---------------------------------------------------------------------------
    # cmd_run — scanner module calls report_vuln from run_host
    # ---------------------------------------------------------------------------
    describe 'cmd_run — scanner replicant flow (report_vuln on replicant, report_failure on parent)' do
      before(:each) do
        current_mod.init_ui(driver_input, driver_output)
        allow(aux_dispatcher).to receive(:mod).and_return(current_mod)
      end

      context 'when run_host reports a vuln with Appears check code on a single host' do
        let(:current_mod) do
          vuln_reporting_scanner_class.injected_check_code = appears_check_code
          build_module(vuln_reporting_scanner_class)
        end

        before do
          current_mod.datastore['RHOSTS'] = '192.0.2.1'
          aux_dispatcher.cmd_run
        end

        it 'creates exactly one vuln' do
          expect(Mdm::Vuln.count).to eq(1)
        end

        it 'creates exactly one vuln attempt (no duplicate from report_failure)' do
          expect(Mdm::VulnAttempt.count).to eq(1)
        end

        it 'sets check_code to appears on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_code).to eq('appears')
        end

        it 'sets check_detail on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_detail).to eq('Likely vulnerable')
        end
      end

      context 'when run_host reports a vuln with Vulnerable check code on a single host' do
        let(:current_mod) do
          vuln_reporting_scanner_class.injected_check_code = vulnerable_check_code
          build_module(vuln_reporting_scanner_class)
        end

        before do
          current_mod.datastore['RHOSTS'] = '192.0.2.1'
          aux_dispatcher.cmd_run
        end

        it 'creates exactly one vuln' do
          expect(Mdm::Vuln.count).to eq(1)
        end

        it 'creates exactly one vuln attempt (no duplicate from report_failure)' do
          expect(Mdm::VulnAttempt.count).to eq(1)
        end

        it 'sets check_code to vulnerable on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_code).to eq('vulnerable')
        end

        it 'sets check_detail on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_detail).to eq(check_detail_message)
        end

        it 'displays check details in vulns -v' do
          vuln = Mdm::Vuln.last
          vuln_attempt = Mdm::VulnAttempt.last
          @output = []
          db.cmd_vulns "-v"
          expect(@output.join("\n")).to match_table <<~TABLE
            Vulnerabilities
            ===============
              0. Vuln ID: #{vuln.id}
                 Timestamp: #{vuln.created_at}
                 Host: 192.0.2.1
                 Name: Test Vuln Scanner
                 References: CVE-2025-99999
                 Information: SSH Host Key Encryption ecdsa-sha2-nistp256 is available, but should be deprecated
                 Resource: {}
                 Service:  (port: 22, resource: {})
                 Vuln attempts:
                 0. ID: #{vuln_attempt.id}
                    Vuln ID: #{vuln.id}
                    Timestamp: #{vuln_attempt.attempted_at}
                    Exploit: #{vuln_attempt.exploited}
                    Fail reason: #{vuln_attempt.fail_reason}
                    Username: #{vuln_attempt.username}
                    Module: #{vuln_attempt.module}
                    Session ID: nil
                    Loot ID: nil
                    Fail Detail: #{vuln_attempt.fail_detail || 'nil'}
                    Check Code: vulnerable
                    Check Detail: #{check_detail_message}
          TABLE
        end
      end

      context 'when run_host reports vulns on multiple hosts' do
        let(:current_mod) do
          vuln_reporting_scanner_class.injected_check_code = appears_check_code
          build_module(vuln_reporting_scanner_class)
        end

        before do
          current_mod.datastore['RHOSTS'] = '192.0.2.1 192.0.2.2'
          aux_dispatcher.cmd_run
        end

        it 'creates one vuln per host' do
          expect(Mdm::Vuln.count).to eq(2)
        end

        it 'creates one vuln attempt per host (no extra from report_failure)' do
          expect(Mdm::VulnAttempt.count).to eq(2)
        end

        it 'sets check_code on all vuln attempts' do
          Mdm::VulnAttempt.find_each do |attempt|
            expect(attempt.check_code).to eq('appears')
          end
        end
      end

      context 'when run_host does not report a vuln' do
        let(:current_mod) { build_module(clean_scanner_class) }

        before do
          current_mod.datastore['RHOSTS'] = '192.0.2.1'
          aux_dispatcher.cmd_run
        end

        it 'does not create a vuln' do
          expect(Mdm::Vuln.count).to eq(0)
        end

        it 'does not create a vuln attempt' do
          expect(Mdm::VulnAttempt.count).to eq(0)
        end
      end

      context 'when only one of two hosts has a vuln' do
        let(:current_mod) do
          selective_scanner_class.vulnerable_hosts = ['192.0.2.1']
          selective_scanner_class.injected_check_code = appears_check_code
          build_module(selective_scanner_class)
        end

        before do
          current_mod.datastore['RHOSTS'] = '192.0.2.1 192.0.2.2'
          aux_dispatcher.cmd_run
        end

        it 'creates exactly one vuln (for the vulnerable host only)' do
          expect(Mdm::Vuln.count).to eq(1)
        end

        it 'creates exactly one vuln attempt (no spurious attempt for the clean host)' do
          expect(Mdm::VulnAttempt.count).to eq(1)
        end

        it 'associates the vuln with the correct host' do
          expect(Mdm::Vuln.last.host.address).to eq('192.0.2.1')
        end
      end
    end

    # ---------------------------------------------------------------------------
    # cmd_run — non-scanner auxiliary with prepend AutoCheck
    # ---------------------------------------------------------------------------
    describe 'cmd_run with prepend AutoCheck' do
      let(:auto_check_module_class) do
        Class.new(simple_module_class) do
          prepend Msf::Exploit::Remote::AutoCheck
        end
      end

      let(:current_mod) do
        auto_check_module_class.injected_check_code = nil
        auto_check_module_class.run_called = false
        build_module(auto_check_module_class)
      end

      before(:each) do
        current_mod.init_ui(driver_input, driver_output)
        allow(aux_dispatcher).to receive(:mod).and_return(current_mod)
      end

      context 'when check returns Vulnerable' do
        before do
          auto_check_module_class.injected_check_code = vulnerable_check_code
          auto_check_module_class.run_called = false
          current_mod.datastore['RHOSTS'] = '192.0.2.1'
          aux_dispatcher.cmd_run
        end

        it 'creates exactly one vuln' do
          expect(Mdm::Vuln.count).to eq(1)
        end

        it 'creates exactly one vuln attempt' do
          expect(Mdm::VulnAttempt.count).to eq(1)
        end

        it 'sets check_code on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_code).to eq('vulnerable')
        end

        it 'sets check_detail on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_detail).to eq(check_detail_message)
        end

        it 'does not set exploited on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.exploited).to be_falsey
        end

        it 'calls the original run method' do
          expect(auto_check_module_class.run_called).to eq(true)
        end

        it 'displays vuln attempt with check details in vulns -v' do
          vuln = Mdm::Vuln.last
          vuln_attempt = Mdm::VulnAttempt.last
          service_str = vuln.service.present? ? "#{vuln.service.name} (port: #{vuln.service.port}, resource: #{vuln.service.resource.to_json})" : ''
          @output = []
          db.cmd_vulns "-v"
          expect(@output.join("\n")).to match_table <<~TABLE
            Vulnerabilities
            ===============
              0. Vuln ID: #{vuln.id}
                 Timestamp: #{vuln.created_at}
                 Host: 192.0.2.1
                 Name: #{vuln.name}
                 References: CVE-2025-99999
                 Information: #{vuln.info}
                 Resource: {}
                 Service: #{service_str}
                 Vuln attempts:
                 0. ID: #{vuln_attempt.id}
                    Vuln ID: #{vuln.id}
                    Timestamp: #{vuln_attempt.attempted_at}
                    Exploit: #{vuln_attempt.exploited}
                    Fail reason: #{vuln_attempt.fail_reason || 'nil'}
                    Username: #{vuln_attempt.username}
                    Module: #{vuln_attempt.module}
                    Session ID: nil
                    Loot ID: nil
                    Fail Detail: #{vuln_attempt.fail_detail || 'nil'}
                    Check Code: vulnerable
                    Check Detail: #{check_detail_message}
          TABLE
        end
      end

      context 'when check returns Safe' do
        before do
          auto_check_module_class.injected_check_code = safe_check_code
          auto_check_module_class.run_called = false
          current_mod.datastore['RHOSTS'] = '192.0.2.1'
          current_mod.datastore['ForceExploit'] = false
        end

        it 'does not call the original run method' do
          aux_dispatcher.cmd_run
          expect(auto_check_module_class.run_called).to eq(false)
        end

        it 'does not create a vuln' do
          aux_dispatcher.cmd_run
          expect(Mdm::Vuln.count).to eq(0)
        end
      end
    end
  end

  context 'when running an exploit module' do
    # ---------------------------------------------------------------------------
    # cmd_exploit — exploit module with prepend AutoCheck
    # ---------------------------------------------------------------------------
    describe 'exploit module with prepend AutoCheck' do
      let(:auto_check_exploit_class) do
        Class.new(exploit_module_class) do
          prepend Msf::Exploit::Remote::AutoCheck
        end
      end

      let(:current_mod) do
        auto_check_exploit_class.injected_check_code = nil
        auto_check_exploit_class.exploit_called = false
        build_module(auto_check_exploit_class)
      end

      before(:each) do
        framework.modules.add_module_path(File.join(FILE_FIXTURES_PATH, 'modules'))
        framework.modules.refresh_cache_from_module_files
        current_mod.init_ui(driver_input, driver_output)
        allow(exploit_dispatcher).to receive(:mod).and_return(current_mod)
        current_mod.datastore['PAYLOAD'] = 'generic/no_session_payload'
        current_mod.datastore['LHOST'] = '127.0.0.1'
      end

      context 'when check returns Vulnerable and exploit runs' do
        before do
          auto_check_exploit_class.injected_check_code = vulnerable_check_code
          auto_check_exploit_class.exploit_called = false
          current_mod.datastore['RHOSTS'] = '192.0.2.1'
          exploit_dispatcher.cmd_exploit
        end

        it 'creates exactly one vuln' do
          expect(Mdm::Vuln.count).to eq(1)
        end

        it 'creates exactly one vuln attempt' do
          expect(Mdm::VulnAttempt.count).to eq(1)
        end

        it 'sets check_code on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_code).to eq('vulnerable')
        end

        it 'sets check_detail on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_detail).to eq(check_detail_message)
        end

        it 'does not set exploited on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.exploited).to be_falsey
        end

        it 'calls the original exploit method' do
          expect(auto_check_exploit_class.exploit_called).to eq(true)
        end
      end

      context 'when check returns Appears and exploit runs' do
        before do
          auto_check_exploit_class.injected_check_code = appears_check_code
          auto_check_exploit_class.exploit_called = false
          current_mod.datastore['RHOSTS'] = '192.0.2.1'
          exploit_dispatcher.cmd_exploit
        end

        it 'creates exactly one vuln' do
          expect(Mdm::Vuln.count).to eq(1)
        end

        it 'creates exactly one vuln attempt' do
          expect(Mdm::VulnAttempt.count).to eq(1)
        end

        it 'sets check_code to appears on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_code).to eq('appears')
        end

        it 'sets check_detail on the vuln attempt' do
          expect(Mdm::VulnAttempt.last.check_detail).to eq('Likely vulnerable')
        end
      end

      context 'when check returns Safe' do
        before do
          auto_check_exploit_class.injected_check_code = safe_check_code
          auto_check_exploit_class.exploit_called = false
          current_mod.datastore['RHOSTS'] = '192.0.2.1'
          current_mod.datastore['ForceExploit'] = false
        end

        it 'does not call the original exploit method' do
          exploit_dispatcher.cmd_exploit
          expect(auto_check_exploit_class.exploit_called).to eq(false)
        end

        it 'does not create a vuln' do
          exploit_dispatcher.cmd_exploit
          expect(Mdm::Vuln.count).to eq(0)
        end
      end
    end
  end
end
