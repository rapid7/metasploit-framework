require 'windows/api'

# The Windows::Directory module contains functions that are used in directory
# management. Note that functions that could be applied to files or
# directories, such as CreateFile(), are probably in the Windows::File
# module.
#
module Windows
  module Directory
    API.auto_namespace = 'Windows::Directory'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = true

    private

    API.new('CreateDirectory', 'PP', 'B')
    API.new('CreateDirectoryEx', 'PPP', 'B')
    API.new('FindCloseChangeNotification', 'L', 'B')
    API.new('FindFirstChangeNotification', 'PIL', 'L')
    API.new('FindNextChangeNotification', 'PIL', 'B')
    API.new('GetCurrentDirectory', 'LP', 'L')
    API.new('ReadDirectoryChangesW', 'LPLILPPP', 'B') # No ANSI equivalent
    API.new('RemoveDirectory', 'P', 'B')
    API.new('SetCurrentDirectory', 'P', 'B')
  end
end
