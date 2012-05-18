require 'windows/api'

module Windows
  module FileSystem
    API.auto_namespace = 'Windows::FileSystem'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    API.new('GetDiskFreeSpace', 'SPPPP', 'B')
    API.new('GetDiskFreeSpaceEx', 'SPPP', 'B')
  end
end
