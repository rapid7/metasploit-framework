# -*- coding:binary -*-
require 'spec_helper'

require 'rex/exploitation/cmdstager'

describe Rex::Exploitation::CmdStagerBourne do

  let(:exe) { "MZ" }

  subject(:cmd_stager) do
    cmd_stager = Rex::Exploitation::CmdStagerBourne.new(exe)
    cmd_stager
  end

  describe '#cmd_concat_operator' do
    it "returns ;" do
      expect(cmd_stager.cmd_concat_operator).to eq(" ; ")
    end
  end

  describe '#generate' do
    it "returns an array of commands" do
      expect(cmd_stager.generate).to_not be_empty
    end
  end

end
