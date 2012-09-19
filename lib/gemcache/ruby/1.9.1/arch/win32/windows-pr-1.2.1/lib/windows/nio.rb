require 'windows/api'

module Windows
  module NIO
    API.auto_namespace = 'Windows::NIO'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = false

    private

    # OpenFile() constants

    OF_READ             = 0x00000000
    OF_WRITE            = 0x00000001
    OF_READWRITE        = 0x00000002
    OF_SHARE_COMPAT     = 0x00000000
    OF_SHARE_EXCLUSIVE  = 0x00000010
    OF_SHARE_DENY_WRITE = 0x00000020
    OF_SHARE_DENY_READ  = 0x00000030
    OF_SHARE_DENY_NONE  = 0x00000040
    OF_PARSE            = 0x00000100
    OF_DELETE           = 0x00000200
    OF_VERIFY           = 0x00000400
    OF_CANCEL           = 0x00000800
    OF_CREATE           = 0x00001000
    OF_PROMPT           = 0x00002000
    OF_EXIST            = 0x00004000
    OF_REOPEN           = 0x00008000

    API.new('CancelIo', 'L', 'B')
    API.new('CreateIoCompletionPort', 'LLPL', 'L')
    API.new('FlushFileBuffers', 'L', 'B')
    API.new('GetQueuedCompletionStatus', 'LPPPL', 'B')
    API.new('OpenFile', 'PPI', 'L')
    API.new('PostQueuedCompletionStatus', 'LLPP', 'B')
    API.new('ReadFileScatter', 'LPLPP', 'B')
    API.new('SetEndOfFile', 'L', 'B')
    API.new('SetFilePointer', 'LLPL', 'L')
    API.new('SetFilePointerEx', 'LLPL', 'B')
    API.new('WriteFileGather', 'LPLPP', 'B')

    begin
      API.new('CancelIoEx', 'LP', 'B')
      API.new('CancelSynchronousIo', 'L', 'B')
    rescue Win32::API::LoadLibraryError
      # Windows Vista or later
    end
  end
end
