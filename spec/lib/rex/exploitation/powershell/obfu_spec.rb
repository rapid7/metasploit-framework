# -*- coding:binary -*-
require 'spec_helper'

require 'rex/exploitation/powershell'

describe Rex::Exploitation::Powershell::Obfu do

  let(:example_script_without_literal) do
"""
function Find-4624Logons
{

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

  let(:subject_no_literal) do
    Rex::Exploitation::Powershell::Script.new(example_script_without_literal)
  end

  describe "::sub_map_generate" do
    it 'should return some unique variable names' do
      map = subject.sub_map_generate(['blah','parp'])
      map.should be
      map.should be_kind_of Hash
      map.empty?.should be_false
      map.should eq map.uniq
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

end

