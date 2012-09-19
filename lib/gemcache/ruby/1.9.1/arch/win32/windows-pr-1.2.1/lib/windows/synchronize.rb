require 'windows/api'

module Windows
  module Synchronize
    API.auto_namespace = 'Windows::Synchronize'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    INFINITE         = 0xFFFFFFFF
    WAIT_OBJECT_0    = 0
    WAIT_TIMEOUT     = 0x102
    WAIT_ABANDONED   = 128
    WAIT_ABANDONED_0 = WAIT_ABANDONED
    WAIT_FAILED      = 0xFFFFFFFF
    
    STATUS_WAIT_0           =  0    
    STATUS_ABANDONED_WAIT_0 =  128    
    STATUS_USER_APC         =  192    
    STATUS_TIMEOUT          =  258    
    STATUS_PENDING          =  259     
    
    # Wake mask constants

    QS_ALLEVENTS      = 0x04BF
    QS_ALLINPUT       = 0x04FF
    QS_ALLPOSTMESSAGE = 0x0100
    QS_HOTKEY         = 0x0080
    QS_INPUT          = 0x407
    QS_KEY            = 0x0001
    QS_MOUSE          = 0x0006
    QS_MOUSEBUTTON    = 0x0004
    QS_MOUSEMOVE      = 0x0002
    QS_PAINT          = 0x0020
    QS_POSTMESSAGE    = 0x0008
    QS_RAWINPUT       = 0x0400
    QS_SENDMESSAGE    = 0x0040
    QS_TIMER          = 0x0010
    
    # Wait type constants

    MWMO_ALERTABLE      = 0x0002
    MWMO_INPUTAVAILABLE = 0x0004
    MWMO_WAITALL        = 0x0001
    
    # Access rights
 
    EVENT_ALL_ACCESS       = 0x1F0003
    EVENT_MODIFY_STATE     = 0x0002
    MUTEX_ALL_ACCESS       = 0x1F0001
    MUTEX_MODIFY_STATE     = 0x0001
    SEMAPHORE_ALL_ACCESS   = 0x1F0003
    SEMAPHORE_MODIFY_STATE = 0x0002

    # Namespace flags

    PRIVATE_NAMESPACE_FLAG_DESTROY = 0x00000001

    # Functions

    API.new('CancelWaitableTimer', 'L', 'B')
    API.new('CreateEvent', 'PIIP', 'L')
    API.new('CreateMutex', 'PIP', 'L')
    API.new('CreateSemaphore', 'PLLP', 'L')
    API.new('CreateWaitableTimer', 'PIP', 'L')
    API.new('DeleteCriticalSection', 'P', 'V')
    API.new('EnterCriticalSection', 'P', 'V')
    API.new('GetOverlappedResult', 'LPPI', 'I')
    API.new('InitializeCriticalSection', 'P', 'V')
    API.new('InitializeCriticalSectionAndSpinCount', 'PL', 'B')
    API.new('LeaveCriticalSection', 'P', 'V')
    API.new('MsgWaitForMultipleObjects', 'LPILL', 'L', 'user32')
    API.new('MsgWaitForMultipleObjectsEx', 'LPLLL', 'L', 'user32')
    API.new('OpenEvent', 'LIP', 'L')
    API.new('OpenMutex', 'LIP', 'L')
    API.new('OpenSemaphore', 'LIP', 'L')
    API.new('OpenWaitableTimer', 'LIP', 'L')
    API.new('ReleaseMutex', 'L', 'B')
    API.new('ReleaseSemaphore', 'LLP', 'B')
    API.new('ResetEvent', 'L', 'B')
    API.new('SetCriticalSectionSpinCount', 'PL', 'V')
    API.new('SetWaitableTimer', 'LPLKPI', 'B')
    API.new('SetEvent', 'L', 'B')
    API.new('TryEnterCriticalSection', 'P', 'B')
    API.new('WaitForMultipleObjects', 'LPIL', 'L')
    API.new('WaitForMultipleObjectsEx', 'LPILI', 'L')
    API.new('WaitForSingleObject', 'LL', 'L')
    API.new('WaitForSingleObjectEx', 'LLI', 'L')
    
    # Macros
    
    def HasOverlappedIoCompleted(overlapped)
      overlapped[0,4].unpack('L')[0] != STATUS_PENDING
    end
    
    # This simulates the RUBY_CRITICAL macro from rubysig.h, although I've
    # added the begin/ensure wrapper to boot.
    #
    def RUBY_CRITICAL(&block)
      critical_section = [0].pack('L')
      begin
        InitializeCriticalSection(critical_section)
        EnterCriticalSection(critical_section)
        block.call
      ensure
        LeaveCriticalSection(critical_section)
      end
    end      

    # Vista or later

    begin
      API.new('AddSIDToBoundaryDescriptor', 'PP', 'B')
      API.new('ClosePrivateNamespace', 'LL', 'B')
      API.new('CreateBoundaryDescriptor', 'SL', 'L')
      API.new('DeleteBoundaryDescriptor', 'L', 'V')
      API.new('CreatePrivateNamespace', 'PLS', 'L')
      API.new('OpenPrivateNamespace', 'PS', 'L')
    rescue Win32::API::LoadLibraryError
      # Windows Vista or later
    end

    # Windows 7 or later

    begin
      API.new('AddIntegrityLabelToBoundaryDescriptor', 'PP', 'B')
    rescue Win32::API::LoadLibraryError
      # Windows 7 or later
    end
  end
end
