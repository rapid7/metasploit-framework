require 'windows/api'

module Windows
  module Pipe
    API.auto_namespace = 'Windows::Pipe'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    NMPWAIT_NOWAIT           = 0x00000001
    NMPWAIT_WAIT_FOREVER     = 0xffffffff
    NMPWAIT_USE_DEFAULT_WAIT = 0x00000000

    PIPE_WAIT             = 0x00000000
    PIPE_NOWAIT           = 0x00000001
    PIPE_ACCESS_INBOUND   = 0x00000001
    PIPE_ACCESS_OUTBOUND  = 0x00000002
    PIPE_ACCESS_DUPLEX    = 0x00000003
    PIPE_TYPE_BYTE        = 0x00000000
    PIPE_TYPE_MESSAGE     = 0x00000004
    PIPE_READMODE_BYTE    = 0x00000000
    PIPE_READMODE_MESSAGE = 0x00000002
    PIPE_CLIENT_END       = 0x00000000
    PIPE_SERVER_END       = 0x00000001
    
    PIPE_UNLIMITED_INSTANCES = 255

    API.new('CallNamedPipe', 'PPLPLPL', 'B')
    API.new('ConnectNamedPipe', 'LP', 'B')
    API.new('CreateNamedPipe', 'PLLLLLLL', 'L')
    API.new('CreatePipe', 'PPPL', 'B')
    API.new('DisconnectNamedPipe', 'L', 'B')
    API.new('GetNamedPipeHandleState', 'LPPPPPL', 'B')
    API.new('GetNamedPipeInfo', 'LPPPP', 'B')
    API.new('PeekNamedPipe', 'LPLPPP', 'B')
    API.new('SetNamedPipeHandleState', 'LPPP', 'B')
    API.new('TransactNamedPipe', 'LPLPLPP', 'B')
    API.new('WaitNamedPipe', 'PL', 'B')
  end
end
