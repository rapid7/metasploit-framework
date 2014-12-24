# -*- coding:binary -*-
require 'spec_helper'

require 'rex/exploitation/powershell'

describe Rex::Exploitation::Powershell do

  let(:example_script) do
    """function DumpHashes
{
    LoadApi
    $bootkey = Get-BootKey;
    $hbootKey = Get-HBootKey $bootkey;
    Get-UserKeys | %{
        $hashes = Get-UserHashes $_ $hBootKey;
        \"{0}:{1}:{2}:{3}:::\" -f ($_.UserName,$_.Rid,
            [BitConverter]::ToString($hashes[0]).Replace(\"-\",\"\").ToLower(),
            [BitConverter]::ToString($hashes[1]).Replace(\"-\",\"\").ToLower());
    }
}
DumpHashes"""
  end

  describe "::read_script" do
    it 'should create a script from a string input' do
      script = described_class.read_script(example_script)
      script.should be_a_kind_of Rex::Exploitation::Powershell::Script
    end
  end

  describe "::process_subs" do
    it 'should create an array of substitutions to process' do
      subs = described_class.process_subs("BitConverter,ParpConverter;$bootkey,$parpkey;")
      subs.should eq [['BitConverter','ParpConverter'],['$bootkey','$parpkey']]
    end
  end

  describe "::make_subs" do
    it 'should substitute values in script' do
      script = described_class.make_subs(example_script,[['BitConverter','ParpConverter']])
      script.include?('BitConverter').should be_falsey
      script.include?('ParpConverter').should be_truthy
    end
  end

end

