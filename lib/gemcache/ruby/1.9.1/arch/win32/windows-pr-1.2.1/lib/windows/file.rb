require 'windows/unicode'
require 'windows/security'

module Windows
   module File
      include Windows::Unicode
      include Windows::Security

      API.auto_namespace = 'Windows::File'
      API.auto_constant  = true
      API.auto_method    = true
      API.auto_unicode   = true

      private
      
      FILE_BEGIN   = 0
      FILE_CURRENT = 1
      FILE_END     = 2      
      
      # File Attributes

      FILE_ATTRIBUTE_READONLY      = 0x00000001  
      FILE_ATTRIBUTE_HIDDEN        = 0x00000002  
      FILE_ATTRIBUTE_SYSTEM        = 0x00000004  
      FILE_ATTRIBUTE_DIRECTORY     = 0x00000010  
      FILE_ATTRIBUTE_ARCHIVE       = 0x00000020  
      FILE_ATTRIBUTE_ENCRYPTED     = 0x00000040  
      FILE_ATTRIBUTE_NORMAL        = 0x00000080   
      FILE_ATTRIBUTE_TEMPORARY     = 0x00000100  
      FILE_ATTRIBUTE_SPARSE_FILE   = 0x00000200  
      FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400  
      FILE_ATTRIBUTE_COMPRESSED    = 0x00000800  
      FILE_ATTRIBUTE_OFFLINE       = 0x00001000  
      FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000
      
      # File types

      FILE_TYPE_UNKNOWN = 0x0000
      FILE_TYPE_DISK    = 0x0001
      FILE_TYPE_CHAR    = 0x0002
      FILE_TYPE_PIPE    = 0x0003
      FILE_TYPE_REMOTE  = 0x8000
      
      # File compression constants

      COMPRESSION_FORMAT_NONE      = 0
      COMPRESSION_FORMAT_DEFAULT   = 1
      COMPRESSION_FORMAT_LZNT1     = 2
      COMPRESSION_ENGINE_STANDARD  = 0
      COMPRESSION_ENGINE_MAXIMUM   = 256
      ANYSIZE_ARRAY                = 1

      # File security and access rights

      FILE_READ_DATA               = 1
      FILE_LIST_DIRECTORY          = 1
      FILE_WRITE_DATA              = 2
      FILE_ADD_FILE                = 2
      FILE_APPEND_DATA             = 4
      FILE_ADD_SUBDIRECTORY        = 4
      FILE_CREATE_PIPE_INSTANCE    = 4
      FILE_READ_EA                 = 8
      FILE_READ_PROPERTIES         = 8
      FILE_WRITE_EA                = 16
      FILE_WRITE_PROPERTIES        = 16
      FILE_EXECUTE                 = 32
      FILE_TRAVERSE                = 32
      FILE_DELETE_CHILD            = 64
      FILE_READ_ATTRIBUTES         = 128
      FILE_WRITE_ATTRIBUTES        = 256
	
      FILE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF
	
      FILE_GENERIC_READ = 
         STANDARD_RIGHTS_READ |
         FILE_READ_DATA |
         FILE_READ_ATTRIBUTES |
         FILE_READ_EA |
         SYNCHRONIZE
	                               
      FILE_GENERIC_WRITE = 
         STANDARD_RIGHTS_WRITE |
         FILE_WRITE_DATA |
         FILE_WRITE_ATTRIBUTES |
         FILE_WRITE_EA |
         FILE_APPEND_DATA |
         SYNCHRONIZE
	           
      FILE_GENERIC_EXECUTE = 
         STANDARD_RIGHTS_EXECUTE |
         FILE_READ_ATTRIBUTES |
         FILE_EXECUTE |
         SYNCHRONIZE
	         
      FILE_SHARE_READ                = 1
      FILE_SHARE_WRITE               = 2
      FILE_SHARE_DELETE              = 4
      FILE_NOTIFY_CHANGE_FILE_NAME   = 1
      FILE_NOTIFY_CHANGE_DIR_NAME    = 2
      FILE_NOTIFY_CHANGE_ATTRIBUTES  = 4
      FILE_NOTIFY_CHANGE_SIZE        = 8
      FILE_NOTIFY_CHANGE_LAST_WRITE  = 16
      FILE_NOTIFY_CHANGE_LAST_ACCESS = 32
      FILE_NOTIFY_CHANGE_CREATION    = 64
      FILE_NOTIFY_CHANGE_SECURITY    = 256
      FILE_CASE_SENSITIVE_SEARCH     = 1
      FILE_CASE_PRESERVED_NAMES      = 2
      FILE_UNICODE_ON_DISK           = 4
      FILE_PERSISTENT_ACLS           = 8
      FILE_FILE_COMPRESSION          = 16
      FILE_VOLUME_QUOTAS             = 32
      FILE_SUPPORTS_SPARSE_FILES     = 64
      FILE_SUPPORTS_REPARSE_POINTS   = 128
      FILE_SUPPORTS_REMOTE_STORAGE   = 256
      FILE_VOLUME_IS_COMPRESSED      = 0x8000
      FILE_SUPPORTS_OBJECT_IDS       = 0x10000  
      FILE_SUPPORTS_ENCRYPTION       = 0x20000
      
      # File flags

      FILE_FLAG_WRITE_THROUGH       = 0x80000000
      FILE_FLAG_OVERLAPPED          = 0x40000000
      FILE_FLAG_NO_BUFFERING        = 0x20000000
      FILE_FLAG_RANDOM_ACCESS       = 0x10000000
      FILE_FLAG_SEQUENTIAL_SCAN     = 0x08000000
      FILE_FLAG_DELETE_ON_CLOSE     = 0x04000000
      FILE_FLAG_BACKUP_SEMANTICS    = 0x02000000
      FILE_FLAG_POSIX_SEMANTICS     = 0x01000000
      FILE_FLAG_OPEN_REPARSE_POINT  = 0x00200000
      FILE_FLAG_OPEN_NO_RECALL      = 0x00100000
      FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
      
      # File creation disposition

      CREATE_NEW        = 1
      CREATE_ALWAYS     = 2
      OPEN_EXISTING     = 3
      OPEN_ALWAYS       = 4
      TRUNCATE_EXISTING = 5
      
      SECTION_QUERY       = 0x0001
      SECTION_MAP_WRITE   = 0x0002
      SECTION_MAP_READ    = 0x0004
      SECTION_MAP_EXECUTE = 0x0008
      SECTION_EXTEND_SIZE = 0x0010

      SECTION_ALL_ACCESS =
         STANDARD_RIGHTS_REQUIRED |
         SECTION_QUERY |
         SECTION_MAP_WRITE |
         SECTION_MAP_READ |
         SECTION_MAP_EXECUTE |
         SECTION_EXTEND_SIZE
           
      # Errors

      INVALID_FILE_ATTRIBUTES  = 0xFFFFFFFF
      INVALID_SET_FILE_POINTER = 0xFFFFFFFF
      INVALID_FILE_SIZE        = 0xFFFFFFFF
      
      # Defined in Windows::Handle as well. Here for convenience.
      
      INVALID_HANDLE_VALUE = 0xFFFFFFFF unless defined? INVALID_HANDLE_VALUE
      
      # Misc

      LOCKFILE_EXCLUSIVE_LOCK        = 0x00000001
      LOCKFILE_FAIL_IMMEDIATELY      = 0x00000002
      MOVEFILE_REPLACE_EXISTING      = 0x00000001
      MOVEFILE_COPY_ALLOWED          = 0x00000002
      MOVEFILE_DELAY_UNTIL_REBOOT    = 0x00000004
      MOVEFILE_WRITE_THROUGH         = 0x00000008
      MOVEFILE_CREATE_HARDLINK       = 0x00000010
      MOVEFILE_FAIL_IF_NOT_TRACKABLE = 0x00000020      
      SYMBOLIC_LINK_FLAG_DIRECTORY   = 0x1

      # FILE_INFO_BY_HANDLE_CLASS enum

      FileBasicInfo                  = 0
      FileStandardInfo               = 1
      FileNameInfo                   = 2
      FileRenameInfo                 = 3
      FileDispositionInfo            = 4
      FileAllocationInfo             = 5
      FileEndOfFileInfo              = 6
      FileStreamInfo                 = 7
      FileCompressionInfo            = 8
      FileAttributeTagInfo           = 9
      FileIdBothDirectoryInfo        = 10
      FileIdBothDirectoryRestartInfo = 11
      FileIoPriorityHintInfo         = 12
      MaximumFileInfoByHandleClass   = 13

      # Reparse point tags
      
      IO_REPARSE_TAG_DFS         = 0x8000000A
      IO_REPARSE_TAG_DFSR        = 0x80000012
      IO_REPARSE_TAG_HSM         = 0xC0000004
      IO_REPARSE_TAG_HSM2        = 0x80000006
      IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
      IO_REPARSE_TAG_SIS         = 0x80000007
      IO_REPARSE_TAG_SYMLINK     = 0xA000000C
     
      API.new('CopyFile', 'SSI', 'B')
      API.new('CopyFileEx', 'SSKPPL', 'B')
      API.new('CreateFile', 'SLLPLLL', 'L')
      API.new('CreateHardLink', 'SSP', 'B')
      API.new('DecryptFile', 'SL', 'B', 'advapi32')
      API.new('DeleteFile', 'S', 'B')
      API.new('EncryptFile', 'S', 'B', 'advapi32')
      API.new('FindClose', 'L', 'B')
      API.new('FindFirstFile', 'SP', 'L')
      API.new('FindFirstFileEx', 'SIPIII', 'L')
      API.new('FindNextFile', 'LP', 'B')
      API.new('FlushFileBuffers', 'L', 'B')
      API.new('GetBinaryType', 'SP', 'B')
      API.new('GetFileAttributes', 'S', 'L')
      API.new('GetFileAttributesEx', 'SPP', 'I')
      API.new('GetFileInformationByHandle', 'LP', 'B')
      API.new('GetFileSize', 'LP', 'L')
      API.new('GetFileSizeEx', 'LP', 'B')
      API.new('GetFileType', 'L', 'L')
      API.new('GetFullPathName', 'SLPP', 'L')
      API.new('GetLongPathName', 'SPL', 'L')
      API.new('GetShortPathName', 'SPL', 'L')
      API.new('LockFile', 'LLLLL', 'B')
      API.new('LockFileEx', 'LLLLLL', 'B')
      API.new('MoveFile', 'SS', 'B')
      API.new('MoveFileEx', 'SSL', 'B')
      API.new('ReadFile', 'LPLPP', 'B')
      API.new('ReadFileEx', 'LPLPK', 'B')
      API.new('SetEndOfFile', 'L', 'B')
      API.new('SetFileAttributes', 'SL', 'B')
      API.new('UnlockFile', 'LLLLL', 'B')
      API.new('UnlockFileEx', 'LLLLL', 'B')
      API.new('WriteFile', 'LPLPP', 'B')
      API.new('WriteFileEx', 'LPLPK', 'B')

      begin
         API.new('SetFileShortName', 'LP', 'B')
         API.new('SetFileValidData', 'LL', 'B')
      rescue Win32::API::LoadLibraryError
         # Windows XP or later
      end

      begin
         API.new('Wow64DisableWow64FsRedirection', 'P', 'B')
         API.new('Wow64EnableWow64FsRedirection', 'I', 'I')
         API.new('Wow64RevertWow64FsRedirection', 'L', 'B')
      rescue Win32::API::LoadLibraryError
         # Windows XP 64-bit and later
      end

      begin
         API.new('CreateSymbolicLink', 'SSL', 'B')
         API.new('CreateSymbolicLinkTransacted', 'SSLL', 'B')
         API.new('GetFileInformationByHandleEx', 'LLPL', 'B')
         API.new('GetFinalPathNameByHandle', 'LPLL', 'L')
         API.new('SetFileInformationByHandle', 'LLPL', 'B')
      rescue Win32::API::LoadLibraryError
         # Windows Vista
      end
   end
end
