# -*- coding:binary -*-
require 'spec_helper'

require 'rex/exploitation/powershell'

describe Rex::Exploitation::Powershell::Obfu do

  let(:example_script_without_literal) do
"""
function Find-4624Logons
{

<#

multiline_comment

#>
\r\n\r\n\r\n
\r\n

lots \t of   whitespace

\n\n\n\n\n
\n\n


# single_line_comment1
    # single_line_comment2
    #
    # single_line_comment3    
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

<#

multiline_comment

#>
\r\n\r\n\r\n
\r\n

lots \t of   whitespace

\n\n\n\n\n
\n\n


# single_line_comment1
    # single_line_comment2
    #
    # single_line_comment3    
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

  describe "::strip_comments" do
    it 'should strip a multiline comment' do
      subject.strip_comments
      subject.code.should be
      subject.code.should be_kind_of String
      subject.code.include?('comment').should be_false
    end

    it 'should strip a single line comment' do
      subject.strip_comments
      subject.code.should be
      subject.code.should be_kind_of String
      subject.code.include?('#').should be_false
    end
  end

  describe "::strip_empty_lines" do
    it 'should strip extra windows new lines' do
      subject.strip_empty_lines
      subject.code.should be
      subject.code.should be_kind_of String
      res = (subject.code =~ /\r\n\r\n/)
      res.should be_false
    end

    it 'should strip extra unix new lines' do
      subject.strip_empty_lines
      subject.code.should be
      subject.code.should be_kind_of String
      res = (subject.code =~ /\n\n/)
      res.should be_false
    end
  end

  describe "::strip_whitespace" do
    it 'should strip additional whitespace' do
      subject.strip_whitespace
      subject.code.should be
      subject.code.should be_kind_of String
      subject.code.include?('lots of whitespace').should be_true
    end
  end

  describe "::sub_vars" do
    it 'should replace variables with unique names' do
      subject.sub_vars
      subject.code.should be
      subject.code.should be_kind_of String
      subject.code.include?('$kernel32').should be_false
      subject.code.include?('$Logon').should be_false
    end
  end

  describe "::sub_funcs" do
    it 'should replace functions with unique names' do
      subject.sub_funcs
      subject.code.should be
      subject.code.should be_kind_of String
      subject.code.include?('Find-4624Logons').should be_false
    end
  end

  describe "::standard_subs" do
    it 'should run all substitutions on a script with no literals' do
      subject_no_literal.standard_subs
      subject_no_literal.code.should be
      subject_no_literal.code.should be_kind_of String
      subject_no_literal.code.include?('Find-4624Logons').should be_false
      subject_no_literal.code.include?('lots of whitespace').should be_true
      subject_no_literal.code.include?('$kernel32').should be_false
      subject_no_literal.code.include?('comment').should be_false
      res = (subject_no_literal.code =~ /\r\n\r\n/)
      res.should be_false
    end

    it 'should run all substitutions except strip whitespace when literals are present' do
      subject.standard_subs
      subject.code.should be
      subject.code.should be_kind_of String
      subject.code.include?('Find-4624Logons').should be_false
      subject.code.include?('lots of whitespace').should be_false
      subject.code.include?('$kernel32').should be_false
      subject.code.include?('comment').should be_false
      res = (subject.code =~ /\r\n\r\n/)
      res.should be_false
    end
  end
end

