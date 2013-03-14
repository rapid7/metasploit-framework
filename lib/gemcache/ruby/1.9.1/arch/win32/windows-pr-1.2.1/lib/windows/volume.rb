require 'windows/api'

module Windows
  module Volume
    API.auto_namespace = 'Windows::Volume'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    DRIVE_UNKNOWN     = 0
    DRIVE_NO_ROOT_DIR = 1
    DRIVE_REMOVABLE   = 2
    DRIVE_FIXED       = 3
    DRIVE_REMOTE      = 4
    DRIVE_CDROM       = 5
    DRIVE_RAMDISK     = 6
    
    API.new('DefineDosDevice', 'LSS', 'B')
    API.new('DeleteVolumeMountPoint', 'S', 'B')
    API.new('FindFirstVolume', 'PL', 'L')
    API.new('FindFirstVolumeMountPoint', 'SPL', 'L')
    API.new('FindNextVolume', 'LPL', 'B')
    API.new('FindNextVolumeMountPoint', 'LPL', 'B')
    API.new('FindVolumeClose', 'L', 'B')
    API.new('FindVolumeMountPointClose', 'L', 'B')
    API.new('GetDriveType', 'S', 'I')
    API.new('GetLogicalDrives', 'V', 'L')
    API.new('GetLogicalDriveStrings', 'LP', 'L')
    API.new('GetVolumeInformation', 'SPLPPPPL', 'B')      
    API.new('GetVolumeNameForVolumeMountPoint', 'SPL', 'B')
    API.new('GetVolumePathName', 'PPL', 'B')
    API.new('QueryDosDevice', 'SPL', 'L')
    API.new('SetVolumeLabel', 'SS', 'B')
    API.new('SetVolumeMountPoint', 'SS', 'B')

    begin
      API.new('GetVolumePathNamesForVolumeName', 'SPLL', 'B')
    rescue Win32::API::LoadLibraryError
      # Windows XP or later
    end

    begin
       API.new('GetVolumeInformationByHandleW', 'LPLPPPPL', 'B')
    rescue Win32::API::LoadLibraryError
       # Windows Vista or later
    end

    # Returns the volume type for +vol+ or the volume of the current
    # process if no volume is specified.
    #
    # Returns nil if the function fails for any reason.
    #
    def get_volume_type(vol = nil)
      buf = 0.chr * 256
      bool = GetVolumeInformation(vol, nil, nil, nil, nil, nil, buf, buf.size)
      bool ? buf.strip : nil
    end
  end
end
