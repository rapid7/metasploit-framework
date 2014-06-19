# -*- coding:binary -*-
require 'spec_helper'

require 'rex/exploitation/cmdstager'

describe Rex::Exploitation::CmdStagerTFTP do

  let(:exe) { "MZ" }

  subject(:cmd_stager) do
    cmd_stager = Rex::Exploitation::CmdStagerTFTP.new(exe)
    cmd_stager
  end

  describe '#cmd_concat_operator' do
    it "returns nil" do
      expect(cmd_stager.cmd_concat_operator).to be_nil
    end
  end

  describe '#generate' do
    it "returns an array of commands" do
      expect(cmd_stager.generate).to_not be_empty
    end
  end

end
