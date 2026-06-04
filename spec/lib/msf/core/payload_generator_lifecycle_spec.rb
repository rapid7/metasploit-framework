# frozen_string_literal: true

require 'spec_helper'

# Verifies the +wrap_with_execution_lifecycle+ helper so standalone
# encoder/NOP invocations are bracketed in an +Mdm::ModuleExecution+,
# while nested invocations (e.g. from inside another module's
# execution) re-use the existing row instead of double-counting.
RSpec.describe Msf::PayloadGenerator, '#wrap_with_execution_lifecycle' do
  let(:framework) { double('framework') }
  let(:mod) do
    instance_double(
      'Msf::Module',
      fullname: 'encoder/x86/shikata_ga_nai',
      refname: 'x86/shikata_ga_nai',
      type: 'encoder',
      datastore: {}
    )
  end
  let(:execution) { double('execution', id: 17) }

  # Reach the private helper without instantiating the full generator,
  # which would require a fully wired payload module.
  let(:generator) do
    obj = Msf::PayloadGenerator.allocate
    obj.instance_variable_set(:@framework, framework)
    obj
  end

  before { Msf::Reporting::CurrentExecution.clear }
  after { Msf::Reporting::CurrentExecution.clear }

  it 'starts an execution, exposes it as current, and finalizes success on a clean run' do
    expect(Msf::Reporting::Execution).to receive(:start!).with(
      hash_including(framework: framework, mod: mod, originating_ui: 'console', kind: 'run')
    ).and_return(execution)
    expect(Msf::Reporting::Execution).to receive(:finalize!).with(
      execution,
      terminal_status: 'success'
    )

    yielded = false
    generator.send(:wrap_with_execution_lifecycle, mod) do
      yielded = true
      expect(Msf::Reporting::CurrentExecution.current).to be(execution)
    end
    expect(yielded).to be(true)
    expect(Msf::Reporting::CurrentExecution.current).to be_nil
  end

  it 'finalizes unhandled_exception and re-raises when the block raises' do
    allow(Msf::Reporting::Execution).to receive(:start!).and_return(execution)
    expect(Msf::Reporting::Execution).to receive(:finalize!).with(
      execution,
      terminal_status: 'unhandled_exception'
    )

    expect do
      generator.send(:wrap_with_execution_lifecycle, mod) { raise 'kaboom' }
    end.to raise_error('kaboom')
  end

  it 'skips lifecycle calls when already inside another execution (nested guard)' do
    outer = double('outer_execution', id: 5)
    expect(Msf::Reporting::Execution).not_to receive(:start!)
    expect(Msf::Reporting::Execution).not_to receive(:finalize!)

    Msf::Reporting::CurrentExecution.with(outer) do
      result = generator.send(:wrap_with_execution_lifecycle, mod) do
        expect(Msf::Reporting::CurrentExecution.current).to be(outer)
        :nested_value
      end
      expect(result).to eq(:nested_value)
    end
  end

  it 'still yields the block when start! returns nil (graceful degradation)' do
    allow(Msf::Reporting::Execution).to receive(:start!).and_return(nil)
    expect(Msf::Reporting::Execution).not_to receive(:finalize!)

    yielded = false
    generator.send(:wrap_with_execution_lifecycle, mod) { yielded = true }
    expect(yielded).to be(true)
  end
end
