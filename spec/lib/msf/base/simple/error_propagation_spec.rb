# frozen_string_literal: true

require 'spec_helper'
require 'msf/base/simple/exploit'
require 'msf/base/simple/evasion'

# On a pre-launch failure, exploit_simple / Evasion.run_simple must record the
# error on the original module instance so an out-of-process caller (the RPC
# service) can report why the module never started. These specs drive each
# wrapper to the rescue arm and assert the error propagates.
RSpec.describe 'Msf::Simple pre-launch failure propagation' do
  before do
    # The rescue arm prints through the formatter; stub it so no UI is needed.
    allow(Msf::Ui::Formatter::OptionValidateError).to receive(:print_error)
    # simplify_module mutates the replicant; irrelevant to this path.
    allow(Msf::Simple::Framework).to receive(:simplify_module)
  end

  let(:validate_error) { Msf::OptionValidateError.new(['RHOSTS']) }

  describe 'Msf::Simple::Exploit.exploit_simple' do
    let(:replicant) do
      double('ExploitReplicant', _import_extra_options: nil, init_ui: nil).tap do |r|
        allow(r).to receive(:error=)
        allow(r).to receive(:validate).and_raise(validate_error)
      end
    end
    let(:original) { double('Exploit', replicant: replicant) }

    it 'records the validation error on the original instance and returns false' do
      allow(original).to receive(:error=)

      result = Msf::Simple::Exploit.exploit_simple(
        original, { 'Payload' => 'generic/shell_reverse_tcp', 'Quiet' => true }
      )

      expect(result).to eq(false)
      expect(original).to have_received(:error=).with(validate_error)
    end
  end

  describe 'Msf::Simple::Evasion.run_simple' do
    let(:options) { double('OptionContainer') }
    let(:replicant) do
      double('EvasionReplicant', _import_extra_options: nil, datastore: {}, options: options).tap do |r|
        allow(r).to receive(:error=)
      end
    end
    let(:original) { double('Evasion', replicant: replicant) }

    before do
      allow(options).to receive(:validate).and_raise(validate_error)
    end

    it 'records the validation error on the original instance' do
      allow(original).to receive(:error=)

      Msf::Simple::Evasion.run_simple(original, { 'Payload' => 'generic/shell_reverse_tcp' })

      expect(original).to have_received(:error=).with(validate_error)
    end
  end
end
