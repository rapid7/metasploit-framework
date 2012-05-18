require 'windows/api'

module Windows
   module FileMapping     
      API.auto_namespace = 'Windows::FileMapping'
      API.auto_constant  = true
      API.auto_method    = true
      API.auto_unicode   = true

      private

      FILE_MAP_COPY       = 0x0001
      FILE_MAP_WRITE      = 0x0002
      FILE_MAP_READ       = 0x0004
      FILE_MAP_ALL_ACCESS = 983071
      
      API.new('CreateFileMapping', 'LPLLLP', 'L')
      API.new('FlushViewOfFile', 'PL', 'B')
      API.new('GetMappedFileName', 'LLPL', 'L', 'psapi')
      API.new('MapViewOfFile', 'LLLLL', 'L')
      API.new('MapViewOfFileEx', 'LLLLLL', 'L')
      API.new('OpenFileMapping', 'LIP', 'L')
      API.new('UnmapViewOfFile', 'P', 'B')
   end
end
