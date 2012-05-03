require 'windows/api'

# In general you will want to use this module with Windows::National because
# it contains the various LOCALE and TIME constants.

module Windows
  module Time
    API.auto_namespace = 'Windows::Time'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private
    
    TIME_ZONE_ID_UNKNOWN  = 0
    TIME_ZONE_ID_STANDARD = 1
    TIME_ZONE_ID_DAYLIGHT = 2      

    API.new('CompareFileTime', 'PP', 'L')
    API.new('DosDateTimeToFileTime', 'IIP', 'B')
    API.new('FileTimeToDosDateTime', 'PPP', 'B')
    API.new('FileTimeToLocalFileTime', 'PP', 'B')
    API.new('FileTimeToSystemTime', 'PP', 'B')
    API.new('GetFileTime', 'LPPP', 'B')
    API.new('GetLocalTime', 'P')
    API.new('GetSystemTime', 'P')
    API.new('GetSystemTimeAdjustment', 'PPP', 'B')
    API.new('GetSystemTimeAsFileTime', 'P')
    API.new('GetTickCount')
    API.new('GetTimeFormat', 'ILPPPI', 'I')
    API.new('GetTimeZoneInformation', 'P', 'L')
    API.new('LocalFileTimeToFileTime', 'PP', 'B')
    API.new('SetFileTime', 'LPPP', 'B')
    API.new('SetLocalTime', 'P', 'B')
    API.new('SetSystemTime', 'P', 'B')
    API.new('SetTimeZoneInformation', 'P', 'B')
    API.new('SetSystemTimeAdjustment', 'LI', 'B')
    API.new('SystemTimeToFileTime', 'PP', 'B')
    API.new('SystemTimeToTzSpecificLocalTime', 'PPP', 'B')

    begin
      API.new('GetSystemTimes', 'PPP', 'B')
      API.new('TzSpecificLocalTimeToSystemTime', 'PPP', 'B')
    rescue Win32::API::LoadLibraryError
      # Windows XP or later
    end
  end
end
