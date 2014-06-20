# -*- coding:binary -*-
require 'spec_helper'

require 'rex/exploitation/cmdstager'

describe Rex::Exploitation::CmdStagerDebugWrite do

  let(:exe) { "MZ" }

  subject(:cmd_stager) do
    described_class.new(exe)
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
      result = cmd_stager.generate(opts)

      expect(result).to be_kind_of(Array)
      expect(result).to_not be_empty
    end
  end

end
