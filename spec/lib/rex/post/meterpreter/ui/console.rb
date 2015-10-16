# -*- coding:binary -*-
require 'spec_helper'

require 'rex/post/meterpreter/ui/console'

RSpec.describe Rex::Post::Meterpreter::Ui::Console do

  subject(:console) do
    Rex::Post::Meterpreter::Ui::Console.new(nil)
  end

  describe "#run_command" do
    let(:dispatcher) do
      double
    end

    it "logs error when Rex::AddressInUse is raised" do
      allow(dispatcher).to receive(:cmd_address_in_use) do
        raise Rex::AddressInUse, "0.0.0.0:80"
      end

      expect(subject).to receive(:log_error).with("The address is already in use (0.0.0.0:80).")
      subject.run_command(dispatcher, "address_in_use", nil)
    end
  end

end
