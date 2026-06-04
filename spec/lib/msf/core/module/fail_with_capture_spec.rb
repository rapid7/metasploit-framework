# frozen_string_literal: true

require 'spec_helper'

# Every +fail_with+ override records a +Mdm::ModuleExecutionError+
# row via +Execution.record_failure!+ and marks the raised exception
# so the surrounding +handle_exception+ / simple-wrapper rescue does
# not write a second row.
RSpec.describe 'Msf::Module#fail_with reporting integration' do
  let(:execution) { double('Mdm::ModuleExecution', id: 11, kind: 'run') }

  before do
    allow(Msf::Reporting::CurrentExecution).to receive(:current).and_return(execution)
  end

  # Build a barebones instance of +klass+ via +.allocate+ so the
  # parent +Msf::Module+ initializer (which requires a framework) is
  # bypassed. The module's own +fail_with+ method is exercised
  # directly.
  def allocate_module(klass)
    mod = klass.allocate
    mod.instance_variable_set(:@fail_reason, Msf::Module::Failure::None)
    mod.instance_variable_set(:@fail_detail, nil)
    mod
  end

  shared_examples 'a fail_with override that records and marks the failure' do |raised_class|
    it "records the failure_reason and message before raising #{raised_class}" do
      reason = Msf::Module::Failure::NoAccess
      message = 'Unable to log in'

      expect(Msf::Reporting::Execution).to receive(:record_failure!).with(
        mod_instance,
        failure_reason: reason,
        message: message
      )

      raised = nil
      begin
        mod_instance.fail_with(reason, message)
      rescue raised_class => e
        raised = e
      end

      expect(raised).to be_a(raised_class)
      expect(Msf::Reporting::Execution.exception_recorded?(raised)).to be(true)
    end
  end

  describe 'Msf::Exploit#fail_with' do
    let(:mod_instance) { allocate_module(Msf::Exploit) }

    include_examples 'a fail_with override that records and marks the failure',
                     Msf::Exploit::Failed
  end

  describe 'Msf::Auxiliary#fail_with' do
    let(:mod_instance) { allocate_module(Msf::Auxiliary) }

    include_examples 'a fail_with override that records and marks the failure',
                     Msf::Auxiliary::Failed
  end

  describe 'Msf::Post#fail_with' do
    let(:mod_instance) { allocate_module(Msf::Post) }

    include_examples 'a fail_with override that records and marks the failure',
                     Msf::Post::Failed
  end

  describe 'Msf::Evasion#fail_with' do
    let(:mod_instance) { allocate_module(Msf::Evasion) }

    include_examples 'a fail_with override that records and marks the failure',
                     Msf::Evasion::Failed
  end

  describe 'Msf::Auxiliary::Scanner#fail_with' do
    let(:scanner) do
      klass = Class.new(Msf::Auxiliary) do
        include Msf::Auxiliary::Scanner
      end
      allocate_module(klass)
    end

    it 'records the failure and raises AttemptFailed by default' do
      expect(Msf::Reporting::Execution).to receive(:record_failure!).with(
        scanner,
        failure_reason: Msf::Module::Failure::Unreachable,
        message: 'down'
      )

      raised = nil
      begin
        scanner.fail_with(Msf::Module::Failure::Unreachable, 'down')
      rescue Msf::Auxiliary::Scanner::AttemptFailed => e
        raised = e
      end

      expect(raised).to be_a(Msf::Auxiliary::Scanner::AttemptFailed)
      expect(Msf::Reporting::Execution.exception_recorded?(raised)).to be(true)
    end

    it 'records the failure and raises Failed when abort: true' do
      expect(Msf::Reporting::Execution).to receive(:record_failure!).with(
        scanner,
        failure_reason: Msf::Module::Failure::Unreachable,
        message: 'down'
      )

      raised = nil
      begin
        scanner.fail_with(Msf::Module::Failure::Unreachable, 'down', abort: true)
      rescue Msf::Auxiliary::Failed => e
        raised = e
      end

      expect(raised).to be_a(Msf::Auxiliary::Failed)
      expect(Msf::Reporting::Execution.exception_recorded?(raised)).to be(true)
    end
  end

  describe 'Msf::Module#fail_with (base)' do
    let(:base_mod) { allocate_module(Msf::Module) }

    it 'records the failure and raises RuntimeError' do
      expect(Msf::Reporting::Execution).to receive(:record_failure!).with(
        base_mod,
        failure_reason: 'no-access',
        message: 'denied'
      )

      raised = nil
      begin
        base_mod.fail_with('no-access', 'denied')
      rescue RuntimeError => e
        raised = e
      end

      expect(raised).to be_a(RuntimeError)
      expect(Msf::Reporting::Execution.exception_recorded?(raised)).to be(true)
    end
  end

  describe 'Msf::Exploit#handle_exception with a fail_with-raised Failed' do
    let(:exploit) do
      mod = allocate_module(Msf::Exploit)
      mod.instance_variable_set(
        :@framework,
        double('framework', events: double('events', on_module_error: nil))
      )
      allow(mod).to receive(:framework).and_return(mod.instance_variable_get(:@framework))
      allow(mod).to receive(:refname).and_return('windows/test')
      allow(mod).to receive(:print_error)
      allow(mod).to receive(:report_failure)
      allow(mod).to receive(:interrupt_handler)
      allow(mod).to receive(:elog)
      mod
    end

    it 'does not invoke capture_exception! when fail_with raised the exception' do
      err = Msf::Exploit::Failed.new('login failed')
      Msf::Reporting::Execution.mark_exception_recorded(err)
      exploit.fail_reason = Msf::Module::Failure::NoAccess

      expect(Msf::Reporting::Execution).not_to receive(:capture_exception!)
      exploit.handle_exception(err)
    end
  end
end
