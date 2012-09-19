require 'windows/api'

module Windows
   module Debug
      API.auto_namespace = 'Windows::Debug'
      API.auto_constant  = true
      API.auto_method    = true
      API.auto_unicode   = false

      private

      API.new('ContinueDebugEvent', 'LLL', 'B')
      API.new('DebugActiveProcess', 'L', 'B')
      API.new('DebugBreak', 'V', 'V')
      API.new('FatalExit', 'I', 'V')
      API.new('FlushInstructionCache', 'LLL', 'B')
      API.new('GetThreadContext', 'LP', 'B')
      API.new('GetThreadSelectorEntry', 'LLP', 'B')
      API.new('IsDebuggerPresent', 'V', 'B')
      API.new('OutputDebugString', 'P', 'V')
      API.new('ReadProcessMemory', 'LLPLP', 'B')
      API.new('SetThreadContext', 'LP', 'B')
      API.new('WaitForDebugEvent', 'PL', 'B')
      API.new('WriteProcessMemory', 'LLPLP', 'B')

      begin
         API.new('CheckRemoteDebuggerPresent', 'LP', 'B')
         API.new('DebugActiveProcessStop', 'L', 'B')
         API.new('DebugBreakProcess', 'L', 'B')
         API.new('DebugSetProcessKillOnExit', 'I', 'B')
      rescue Win32::API::LoadLibraryError
         # Windows XP or later
      end
   end
end
