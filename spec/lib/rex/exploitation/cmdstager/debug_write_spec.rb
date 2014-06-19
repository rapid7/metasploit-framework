# -*- coding:binary -*-
require 'spec_helper'

require 'rex/exploitation/cmdstager'

describe Rex::Exploitation::CmdStagerDebugWrite do

  let(:exe) { "MZ" }

  subject(:cmd_stager) do
    cmd_stager = Rex::Exploitation::CmdStagerDebugWrite.new(exe)
    cmd_stager
  end

  describe '#cmd_concat_operator' do
    it "returns &" do
      expect(cmd_stager.cmd_concat_operator).to eq(" & ")
    end
  end

  describe '#generate' do
    let(:opts) do
      {
        :decoder => File.join(Msf::Config.data_directory, "exploits", "cmdstager", "debug_write")
      }
    end

    it "returns an array of commands" do
      expect(cmd_stager.generate(opts)).to_not be_empty
    end
  end

end
