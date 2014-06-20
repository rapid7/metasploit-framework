# -*- coding:binary -*-
require 'spec_helper'

require 'rex/exploitation/cmdstager'

describe Rex::Exploitation::CmdStagerBase do

  let(:exe) { "MZ" }

  subject(:cmd_stager) do
    described_class.new(exe)
  end

  describe '#cmd_concat_operator' do
    it "returns nil" do
      expect(cmd_stager.cmd_concat_operator).to be_nil
    end
  end

  describe '#generate' do
    it "returns an empty array" do
      expect(cmd_stager.generate).to eq([])
    end
  end

end
