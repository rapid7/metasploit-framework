require 'windows/api'

# Functions and constants from tlhelp32.h

module Windows
  module ToolHelper
    API.auto_namespace = 'Windows::ToolHelper'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    TH32CS_SNAPHEAPLIST = 0x00000001 
    TH32CS_SNAPPROCESS  = 0x00000002 
    TH32CS_SNAPTHREAD   = 0x00000004 
    TH32CS_SNAPMODULE   = 0x00000008 
    TH32CS_SNAPMODULE32 = 0x00000010 
    TH32CS_INHERIT      = 0x80000000
    TH32CS_SNAPALL = TH32CS_SNAPHEAPLIST | TH32CS_SNAPMODULE |
       TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD
    
    API.new('CreateToolhelp32Snapshot', 'LL', 'L')
    API.new('Heap32First', 'PLL', 'B')
    API.new('Heap32ListFirst', 'LP', 'B')
    API.new('Heap32ListNext', 'LP', 'B')
    API.new('Heap32Next', 'P', 'B')
    API.new('Module32First', 'LP', 'B')
    API.new('Module32Next', 'LP', 'B')
    API.new('Process32First', 'LP', 'B')
    API.new('Process32Next', 'LP', 'B')
    API.new('Thread32First', 'LP', 'B')
    API.new('Thread32Next', 'LP', 'B')
    API.new('Toolhelp32ReadProcessMemory', 'LLPLL', 'B')
  end
end
