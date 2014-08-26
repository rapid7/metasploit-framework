# -*- coding:binary -*-
require 'spec_helper'

require 'rex/exploitation/powershell'

describe Rex::Exploitation::Powershell::Parser do

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
    Rex::Exploitation::Powershell::Script.new(example_script)
  end

  describe "::get_var_names" do
    it 'should return some variable names' do
      vars = subject.get_var_names
      vars.should be
      vars.should be_kind_of Array
      vars.length.should be > 0
      vars.include?('$ResultObj').should be_truthy
    end

    it 'should not match upper or lowercase reserved names' do
      initial_vars = subject.get_var_names
      subject.code << "\r\n$SHELLID"
      subject.code << "\r\n$ShellId"
      subject.code << "\r\n$shellid"
      after_vars = subject.get_var_names
      initial_vars.should eq after_vars
    end
  end

  describe "::get_func_names" do
    it 'should return some function names' do
      funcs = subject.get_func_names
      funcs.should be
      funcs.should be_kind_of Array
      funcs.length.should be > 0
      funcs.include?('Find-4624Logons').should be_truthy
    end
  end

  describe "::get_string_literals" do
    it 'should return some string literals' do
      literals = subject.get_string_literals
      literals.should be
      literals.should be_kind_of Array
      literals.length.should be > 0
      literals[0].include?('parp').should be_falsey
    end
  end

  describe "::scan_with_index" do
    it 'should scan code and return the items with an index' do
      scan = subject.scan_with_index('DllImport')
      scan.should be
      scan.should be_kind_of Array
      scan.length.should be > 0
      scan[0].should be_kind_of Array
      scan[0][0].should be_kind_of String
      scan[0][1].should be_kind_of Integer
    end
  end

  describe "::match_start" do
    it 'should match the correct brackets' do
      subject.match_start('{').should eq '}'
      subject.match_start('(').should eq ')'
      subject.match_start('[').should eq ']'
      subject.match_start('<').should eq '>'
      expect { subject.match_start('p') }.to raise_exception(ArgumentError)
    end
  end

  describe "::block_extract" do
    it 'should extract a block between brackets given an index' do
      idx = subject.code.index('{')
      block = subject.block_extract(idx)
      block.should be
      block.should be_kind_of String
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
      function.should be
      function.should be_kind_of Rex::Exploitation::Powershell::Function
    end

    it 'should return nil if function doesnt exist' do
      function = subject.get_func(Rex::Text.rand_text_alpha(5))
      function.should be_nil
    end

    it 'should delete the function if delete is true' do
      function = subject.get_func('Find-4624Logons', true)
      subject.code.include?('DllImport').should be_falsey
    end
  end
end

