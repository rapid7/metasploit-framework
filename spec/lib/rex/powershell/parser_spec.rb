# -*- coding:binary -*-
require 'spec_helper'

require 'rex/powershell'

RSpec.describe Rex::Powershell::Parser do

  let(:example_script) do
"""
function Find-4624Logons
{
    $some_literal = @\"
  using System;
  using System.Runtime.InteropServices;
  namespace $kernel32 {
    public class func {
      [Flags] public enum AllocationType { Commit = 0x1000, Reserve = 0x2000 }
      [Flags] public enum MemoryProtection { ExecuteReadWrite = 0x40 }
      [Flags] public enum Time : uint { Infinite = 0xFFFFFFFF }
      [DllImport(\"kernel32.dll\")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
      [DllImport(\"kernel32.dll\")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
      [DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject(IntPtr hHandle, Time dwMilliseconds);
    }
  }
\"@
   if (-not ($NewLogonAccountDomain -cmatch \"NT\\sAUTHORITY\" -or $NewLogonAccountDomain -cmatch \"Window\\sManager\"))
        {
            $Key = $AccountName + $AccountDomain + $NewLogonAccountName + $NewLogonAccountDomain + $LogonType + $WorkstationName + $SourceNetworkAddress + $SourcePort
            if (-not $ReturnInfo.ContainsKey($Key))
            {
                $Properties = @{
                    LogType = 4624
                    LogSource = \"Security\"
                    SourceAccountName = $AccountName
                    SourceDomainName = $AccountDomain
                    NewLogonAccountName = $NewLogonAccountName
                    NewLogonAccountDomain = $NewLogonAccountDomain
                    LogonType = $LogonType
                    WorkstationName = $WorkstationName
                    SourceNetworkAddress = $SourceNetworkAddress
                    SourcePort = $SourcePort
                    Count = 1
                    Times = @($Logon.TimeGenerated)
                }
                $literal2 = @\"parp\"@
                $ResultObj = New-Object PSObject -Property $Properties
                $ReturnInfo.Add($Key, $ResultObj)
            }
            else
            {
                $ReturnInfo[$Key].Count++
                $ReturnInfo[$Key].Times += ,$Logon.TimeGenerated
            }
        }
    }
}"""

  end

  let(:subject) do
    Rex::Powershell::Script.new(example_script)
  end

  describe "::get_var_names" do
    it 'should return some variable names' do
      vars = subject.get_var_names
      expect(vars).to be
      expect(vars).to be_kind_of Array
      expect(vars.length).to be > 0
      expect(vars.include?('$ResultObj')).to be_truthy
    end

    it 'should not match upper or lowercase reserved names' do
      initial_vars = subject.get_var_names
      subject.code << "\r\n$SHELLID"
      subject.code << "\r\n$ShellId"
      subject.code << "\r\n$shellid"
      after_vars = subject.get_var_names
      expect(initial_vars).to eq after_vars
    end
  end

  describe "::get_func_names" do
    it 'should return some function names' do
      funcs = subject.get_func_names
      expect(funcs).to be
      expect(funcs).to be_kind_of Array
      expect(funcs.length).to be > 0
      expect(funcs.include?('Find-4624Logons')).to be_truthy
    end
  end

  describe "::get_string_literals" do
    it 'should return some string literals' do
      literals = subject.get_string_literals
      expect(literals).to be
      expect(literals).to be_kind_of Array
      expect(literals.length).to be > 0
      expect(literals[0].include?('parp')).to be_falsey
    end
  end

  describe "::scan_with_index" do
    it 'should scan code and return the items with an index' do
      scan = subject.scan_with_index('DllImport')
      expect(scan).to be
      expect(scan).to be_kind_of Array
      expect(scan.length).to be > 0
      expect(scan[0]).to be_kind_of Array
      expect(scan[0][0]).to be_kind_of String
      expect(scan[0][1]).to be_kind_of Integer
    end
  end

  describe "::match_start" do
    it 'should match the correct brackets' do
      expect(subject.match_start('{')).to eq '}'
      expect(subject.match_start('(')).to eq ')'
      expect(subject.match_start('[')).to eq ']'
      expect(subject.match_start('<')).to eq '>'
      expect { subject.match_start('p') }.to raise_exception(ArgumentError)
    end
  end

  describe "::block_extract" do
    it 'should extract a block between brackets given an index' do
      idx = subject.code.index('{')
      block = subject.block_extract(idx)
      expect(block).to be
      expect(block).to be_kind_of String
    end

    it 'should raise a runtime error if given an invalid index' do
      expect { subject.block_extract(nil) }.to raise_error(ArgumentError)
      expect { subject.block_extract(-1) }.to raise_error(ArgumentError)
      expect { subject.block_extract(subject.code.length) }.to raise_error(ArgumentError)
      expect { subject.block_extract(59) }.to raise_error(ArgumentError)
    end
  end

  describe "::get_func" do
    it 'should extract a function from the code' do
      function = subject.get_func('Find-4624Logons')
      expect(function).to be
      expect(function).to be_kind_of Rex::Powershell::Function
    end

    it 'should return nil if function doesnt exist' do
      function = subject.get_func(Rex::Text.rand_text_alpha(5))
      expect(function).to be_nil
    end

    it 'should delete the function if delete is true' do
      function = subject.get_func('Find-4624Logons', true)
      expect(subject.code.include?('DllImport')).to be_falsey
    end
  end
end

