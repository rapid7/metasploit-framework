# -*- coding:binary -*-
require 'spec_helper'

require 'rex/exploitation/powershell'

describe Rex::Exploitation::Powershell do

  describe "::read_script" do
    it 'should create a script from a string input' do
      script = described_class.read_script("parp")
      script.should be_a_kind_of Rex::Exploitation::Powershell::Script
    end
  end

end

