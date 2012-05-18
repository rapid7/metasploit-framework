require 'windows/api'

module Windows
  module EventLog
    API.auto_namespace = 'Windows::EventLog'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    EVENTLOG_SEQUENTIAL_READ = 0x0001
    EVENTLOG_SEEK_READ       = 0x0002
    EVENTLOG_FORWARDS_READ   = 0x0004
    EVENTLOG_BACKWARDS_READ  = 0x0008

    EVENTLOG_SUCCESS          = 0x0000
    EVENTLOG_ERROR_TYPE       = 0x0001
    EVENTLOG_WARNING_TYPE     = 0x0002
    EVENTLOG_INFORMATION_TYPE = 0x0004
    EVENTLOG_AUDIT_SUCCESS    = 0x0008
    EVENTLOG_AUDIT_FAILURE    = 0x0010

    EVENTLOG_FULL_INFO = 0

    API.new('BackupEventLog', 'LS', 'B', 'advapi32')
    API.new('ClearEventLog', 'LS', 'B', 'advapi32')
    API.new('CloseEventLog', 'L', 'B', 'advapi32')
    API.new('DeregisterEventSource', 'L', 'B', 'advapi32')
    API.new('GetEventLogInformation', 'LLPLP', 'B', 'advapi32')
    API.new('GetNumberOfEventLogRecords', 'LP', 'B', 'advapi32')
    API.new('GetOldestEventLogRecord', 'LP', 'B', 'advapi32')
    API.new('NotifyChangeEventLog', 'LL', 'B', 'advapi32')
    API.new('OpenBackupEventLog', 'SS', 'L', 'advapi32')
    API.new('OpenEventLog', 'SS', 'L', 'advapi32')
    API.new('ReadEventLog', 'LLLPLPP', 'B', 'advapi32')
    API.new('RegisterEventSource', 'SS', 'L', 'advapi32')
    API.new('ReportEvent', 'LIILPILPP', 'B', 'advapi32')

    begin
      API.new('EvtArchiveExportedLog', 'LPLL', 'B', 'wevtapi')
      API.new('EvtCancel', 'L', 'B', 'wevtapi')
      API.new('EvtClearLog', 'LPPL', 'B', 'wevtapi')
      API.new('EvtClose', 'L', 'B', 'wevtapi')
      API.new('EvtCreateBookmark', 'L', 'L', 'wevtapi')
      API.new('EvtCreateRenderContext', 'LPL', 'L', 'wevtapi')
      API.new('EvtExportLog', 'LPPPL', 'B', 'wevtapi')
      API.new('EvtFormatMessage', 'LLLLPLLPP', 'B', 'wevtapi')
      API.new('EvtGetChannelConfigProperty', 'LLLLPP', 'B', 'wevtapi')
      API.new('EvtGetEventInfo', 'LLLPP', 'B', 'wevtapi')
      API.new('EvtGetEventMetadataProperty', 'LLLLPP', 'B', 'wevtapi')
      API.new('EvtGetExtendedStatus', 'LPP', 'B', 'wevtapi')
      API.new('EvtGetLogInfo', 'LLLPP', 'B', 'wevtapi')
      API.new('EvtGetObjectArrayProperty', 'LLLLLPP', 'B', 'wevtapi')
      API.new('EvtGetObjectArraySize', 'LP', 'B', 'wevtapi')
      API.new('EvtGetPublisherMetadataProperty', 'LLLLPP', 'B', 'wevtapi')
      API.new('EvtGetQueryInfo', 'LLLPP', 'B', 'wevtapi')
      API.new('EvtNext', 'LLPLLP', 'B', 'wevtapi')
      API.new('EvtNextChannelPath', 'LLPP', 'B', 'wevtapi')
      API.new('EvtNextEventMetadata', 'LL', 'L', 'wevtapi')
      API.new('EvtNextPublisherId', 'LLPP', 'B', 'wevtapi')
      API.new('EvtOpenChannelConfig', 'LPL', 'L', 'wevtapi')
      API.new('EvtOpenChannelEnum', 'LL', 'L', 'wevtapi')
      API.new('EvtOpenEventMetadataEnum', 'LL', 'L', 'wevtapi')
      API.new('EvtOpenLog', 'LPL', 'L', 'wevtapi')
      API.new('EvtOpenPublisherEnum', 'LL', 'L', 'wevtapi')
      API.new('EvtOpenPublisherMetadata', 'LPPLL', 'L', 'wevtapi')
      API.new('EvtOpenSession', 'LLLL', 'L', 'wevtapi')
      API.new('EvtQuery', 'LPPL', 'L', 'wevtapi')
      API.new('EvtRender', 'LLLLPPP', 'B', 'wevtapi')
      API.new('EvtSaveChannelConfig', 'LL', 'B', 'wevtapi')
      API.new('EvtSeek', 'LLLLL', 'B', 'wevtapi')
      API.new('EvtSetChannelConfigProperty', 'LLLP', 'B', 'wevtapi')
      API.new('EvtSubscribe', 'LLPPLPKL', 'L', 'wevtapi')
      API.new('EvtUpdateBookmark', 'LL', 'B', 'wevtapi')
    rescue Win32::API::LoadLibraryError
      # Windows Vista or later
    end
  end
end
