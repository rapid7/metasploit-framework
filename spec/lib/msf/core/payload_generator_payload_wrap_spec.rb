# frozen_string_literal: true

require 'spec_helper'

# Standalone +msfvenom+ payload generation (i.e.
# +PayloadGenerator#generate_raw_payload+) brackets the
# +payload_module.generate_simple+ call in
# +wrap_with_execution_lifecycle+ so that +fail_with+ raised from
# inside the payload's +generate+ method records a row against the
# transient execution.
RSpec.describe Msf::PayloadGenerator, '#generate_raw_payload execution wrap' do
  let(:framework) { double('framework') }
  let(:payload_module) do
    double(
      'payload_module',
      fullname: 'payload/test/raw',
      refname: 'test/raw',
      type: 'payload',
      datastore: {}
    )
  end

  let(:generator) do
    obj = Msf::PayloadGenerator.allocate
    obj.instance_variable_set(:@framework, framework)
    obj.instance_variable_set(:@payload, 'test/raw')
    obj.instance_variable_set(:@datastore, {})
    obj.instance_variable_set(:@space, 1024)
    allow(obj).to receive(:payload_module).and_return(payload_module)
    allow(obj).to receive(:choose_platform).and_return(double('platform', platforms: [:linux]))
    allow(obj).to receive(:choose_arch).and_return(:x86)
    obj
  end

  before { Msf::Reporting::CurrentExecution.clear }
  after { Msf::Reporting::CurrentExecution.clear }

  it 'wraps payload_module.generate_simple in wrap_with_execution_lifecycle' do
    expect(generator).to receive(:wrap_with_execution_lifecycle).with(payload_module).and_yield
    expect(payload_module).to receive(:generate_simple).and_return('shellcode')

    expect(generator.generate_raw_payload).to eq('shellcode')
  end
end
