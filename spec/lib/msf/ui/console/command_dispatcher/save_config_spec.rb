# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Ui::Console::CommandDispatcher::Core do
  describe '#cmd_save' do
    subject(:dispatcher) { described_class.allocate }

    it 'stops after failing to save the console configuration' do
      driver = Msf::Ui::Console::Driver.allocate
      feature_manager = Msf::FeatureManager.instance
      framework = object_double(Msf::Framework.allocate.extend(Msf::Simple::Framework), save_config: nil, dns_resolver: nil)
      allow(dispatcher).to receive_messages(driver: driver, framework: framework, active_module: nil)
      allow(driver).to receive_messages(get_config: {}, framework: framework)
      allow(driver).to receive(:print_error)
      allow(dispatcher).to receive(:log_error)
      allow(dispatcher).to receive(:print_line)
      allow(feature_manager).to receive(:save_config)
      allow(Msf::Config).to receive(:save).and_raise(Errno::EIO)

      expect(dispatcher.cmd_save).to be false
      expect(feature_manager).not_to have_received(:save_config)
      expect(framework).not_to have_received(:save_config)
      expect(dispatcher).to have_received(:log_error).with(/Save failed/)
      expect(dispatcher).not_to have_received(:print_line).with(/Saved configuration/)
    end
  end
end
