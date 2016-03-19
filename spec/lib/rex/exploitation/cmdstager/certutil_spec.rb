# -*- coding:binary -*-
require 'spec_helper'

require 'rex/exploitation/cmdstager'

RSpec.describe Rex::Exploitation::CmdStagerCertutil do

  let(:exe) { "MZ" }

  subject(:cmd_stager) do
    described_class.new(exe)
  end

  describe '#generate' do
    it "returns an array of commands" do
      result = cmd_stager.generate

      expect(result).to be_kind_of(Array)
      expect(result).to_not be_empty
    end
  end

end
