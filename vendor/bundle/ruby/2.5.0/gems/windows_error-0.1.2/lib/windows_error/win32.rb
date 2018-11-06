module WindowsError

  # This module provides the namespace for all of the Win32
  # Error Codes. See [Win32 Error Codes](https://msdn.microsoft.com/en-us/library/cc231199.aspx) for
  # more details on this particular set of error codes.
  module Win32

    # Returns all the {WindowsError::ErrorCode} objects that match
    # the return value supplied.
    #
    # @param [Integer] retval the return value you want the error code for
    # @raise [ArgumentError] if something other than a Integer is supplied
    # @return [Array<WindowsError::ErrorCode>] all Win32 ErrorCodes that matched
    def self.find_by_retval(retval)
      raise ArgumentError, "Invalid Return Code!" unless retval.kind_of? Integer
      error_codes = []
      self.constants.each do |constant_name|
        error_code = self.const_get(constant_name)
        if error_code == retval
          error_codes << error_code
        end
      end
      error_codes
    end

    #
    # CONSTANTS
    #

    # (0x00000000) The operation completed successfully.
    ERROR_SUCCESS = WindowsError::ErrorCode.new("ERROR_SUCCESS",0x00000000,"The operation completed successfully.")

    # (0x00000001) Incorrect function.
    ERROR_INVALID_FUNCTION = WindowsError::ErrorCode.new("ERROR_INVALID_FUNCTION",0x00000001,"Incorrect function.")

    # (0x00000002) The system cannot find the file specified.
    ERROR_FILE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_FILE_NOT_FOUND",0x00000002,"The system cannot find the file specified.")

    # (0x00000003) The system cannot find the path specified.
    ERROR_PATH_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_PATH_NOT_FOUND",0x00000003,"The system cannot find the path specified.")

    # (0x00000004) The system cannot open the file.
    ERROR_TOO_MANY_OPEN_FILES = WindowsError::ErrorCode.new("ERROR_TOO_MANY_OPEN_FILES",0x00000004,"The system cannot open the file.")

    # (0x00000005) Access is denied.
    ERROR_ACCESS_DENIED = WindowsError::ErrorCode.new("ERROR_ACCESS_DENIED",0x00000005,"Access is denied.")

    # (0x00000006) The handle is invalid.
    ERROR_INVALID_HANDLE = WindowsError::ErrorCode.new("ERROR_INVALID_HANDLE",0x00000006,"The handle is invalid.")

    # (0x00000007) The storage control blocks were destroyed.
    ERROR_ARENA_TRASHED = WindowsError::ErrorCode.new("ERROR_ARENA_TRASHED",0x00000007,"The storage control blocks were destroyed.")

    # (0x00000008) Not enough storage is available to process this command.
    ERROR_NOT_ENOUGH_MEMORY = WindowsError::ErrorCode.new("ERROR_NOT_ENOUGH_MEMORY",0x00000008,"Not enough storage is available to process this command.")

    # (0x00000009) The storage control block address is invalid.
    ERROR_INVALID_BLOCK = WindowsError::ErrorCode.new("ERROR_INVALID_BLOCK",0x00000009,"The storage control block address is invalid.")

    # (0x0000000A) The environment is incorrect.
    ERROR_BAD_ENVIRONMENT = WindowsError::ErrorCode.new("ERROR_BAD_ENVIRONMENT",0x0000000A,"The environment is incorrect.")

    # (0x0000000B) An attempt was made to load a program with an incorrect format.
    ERROR_BAD_FORMAT = WindowsError::ErrorCode.new("ERROR_BAD_FORMAT",0x0000000B,"An attempt was made to load a program with an incorrect format.")

    # (0x0000000C) The access code is invalid.
    ERROR_INVALID_ACCESS = WindowsError::ErrorCode.new("ERROR_INVALID_ACCESS",0x0000000C,"The access code is invalid.")

    # (0x0000000D) The data is invalid.
    ERROR_INVALID_DATA = WindowsError::ErrorCode.new("ERROR_INVALID_DATA",0x0000000D,"The data is invalid.")

    # (0x0000000E) Not enough storage is available to complete this operation.
    ERROR_OUTOFMEMORY = WindowsError::ErrorCode.new("ERROR_OUTOFMEMORY",0x0000000E,"Not enough storage is available to complete this operation.")

    # (0x0000000F) The system cannot find the drive specified.
    ERROR_INVALID_DRIVE = WindowsError::ErrorCode.new("ERROR_INVALID_DRIVE",0x0000000F,"The system cannot find the drive specified.")

    # (0x00000010) The directory cannot be removed.
    ERROR_CURRENT_DIRECTORY = WindowsError::ErrorCode.new("ERROR_CURRENT_DIRECTORY",0x00000010,"The directory cannot be removed.")

    # (0x00000011) The system cannot move the file to a different disk drive.
    ERROR_NOT_SAME_DEVICE = WindowsError::ErrorCode.new("ERROR_NOT_SAME_DEVICE",0x00000011,"The system cannot move the file to a different disk drive.")

    # (0x00000012) There are no more files.
    ERROR_NO_MORE_FILES = WindowsError::ErrorCode.new("ERROR_NO_MORE_FILES",0x00000012,"There are no more files.")

    # (0x00000013) The media is write-protected.
    ERROR_WRITE_PROTECT = WindowsError::ErrorCode.new("ERROR_WRITE_PROTECT",0x00000013,"The media is write-protected.")

    # (0x00000014) The system cannot find the device specified.
    ERROR_BAD_UNIT = WindowsError::ErrorCode.new("ERROR_BAD_UNIT",0x00000014,"The system cannot find the device specified.")

    # (0x00000015) The device is not ready.
    ERROR_NOT_READY = WindowsError::ErrorCode.new("ERROR_NOT_READY",0x00000015,"The device is not ready.")

    # (0x00000016) The device does not recognize the command.
    ERROR_BAD_COMMAND = WindowsError::ErrorCode.new("ERROR_BAD_COMMAND",0x00000016,"The device does not recognize the command.")

    # (0x00000017) Data error (cyclic redundancy check).
    ERROR_CRC = WindowsError::ErrorCode.new("ERROR_CRC",0x00000017,"Data error (cyclic redundancy check).")

    # (0x00000018) The program issued a command but the command length is incorrect.
    ERROR_BAD_LENGTH = WindowsError::ErrorCode.new("ERROR_BAD_LENGTH",0x00000018,"The program issued a command but the command length is incorrect.")

    # (0x00000019) The drive cannot locate a specific area or track on the disk.
    ERROR_SEEK = WindowsError::ErrorCode.new("ERROR_SEEK",0x00000019,"The drive cannot locate a specific area or track on the disk.")

    # (0x0000001A) The specified disk cannot be accessed.
    ERROR_NOT_DOS_DISK = WindowsError::ErrorCode.new("ERROR_NOT_DOS_DISK",0x0000001A,"The specified disk cannot be accessed.")

    # (0x0000001B) The drive cannot find the sector requested.
    ERROR_SECTOR_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_SECTOR_NOT_FOUND",0x0000001B,"The drive cannot find the sector requested.")

    # (0x0000001C) The printer is out of paper.
    ERROR_OUT_OF_PAPER = WindowsError::ErrorCode.new("ERROR_OUT_OF_PAPER",0x0000001C,"The printer is out of paper.")

    # (0x0000001D) The system cannot write to the specified device.
    ERROR_WRITE_FAULT = WindowsError::ErrorCode.new("ERROR_WRITE_FAULT",0x0000001D,"The system cannot write to the specified device.")

    # (0x0000001E) The system cannot read from the specified device.
    ERROR_READ_FAULT = WindowsError::ErrorCode.new("ERROR_READ_FAULT",0x0000001E,"The system cannot read from the specified device.")

    # (0x0000001F) A device attached to the system is not functioning.
    ERROR_GEN_FAILURE = WindowsError::ErrorCode.new("ERROR_GEN_FAILURE",0x0000001F,"A device attached to the system is not functioning.")

    # (0x00000020) The process cannot access the file because it is being used by another process.
    ERROR_SHARING_VIOLATION = WindowsError::ErrorCode.new("ERROR_SHARING_VIOLATION",0x00000020,"The process cannot access the file because it is being used by another process.")

    # (0x00000021) The process cannot access the file because another process has locked a portion of the file.
    ERROR_LOCK_VIOLATION = WindowsError::ErrorCode.new("ERROR_LOCK_VIOLATION",0x00000021,"The process cannot access the file because another process has locked a portion of the file.")

    # (0x00000022) The wrong disk is in the drive. Insert %2 (Volume Serial Number: %3) into drive %1.
    ERROR_WRONG_DISK = WindowsError::ErrorCode.new("ERROR_WRONG_DISK",0x00000022,"The wrong disk is in the drive. Insert %2 (Volume Serial Number: %3) into drive %1.")

    # (0x00000024) Too many files opened for sharing.
    ERROR_SHARING_BUFFER_EXCEEDED = WindowsError::ErrorCode.new("ERROR_SHARING_BUFFER_EXCEEDED",0x00000024,"Too many files opened for sharing.")

    # (0x00000026) Reached the end of the file.
    ERROR_HANDLE_EOF = WindowsError::ErrorCode.new("ERROR_HANDLE_EOF",0x00000026,"Reached the end of the file.")

    # (0x00000027) The disk is full.
    ERROR_HANDLE_DISK_FULL = WindowsError::ErrorCode.new("ERROR_HANDLE_DISK_FULL",0x00000027,"The disk is full.")

    # (0x00000032) The request is not supported.
    ERROR_NOT_SUPPORTED = WindowsError::ErrorCode.new("ERROR_NOT_SUPPORTED",0x00000032,"The request is not supported.")

    # (0x00000033) Windows cannot find the network path. Verify that the network path is correct and the destination computer is not busy or turned off. If Windows still cannot find the network path, contact your network administrator.
    ERROR_REM_NOT_LIST = WindowsError::ErrorCode.new("ERROR_REM_NOT_LIST",0x00000033,"Windows cannot find the network path. Verify that the network path is correct and the destination computer is not busy or turned off. If Windows still cannot find the network path, contact your network administrator.")

    # (0x00000034) You were not connected because a duplicate name exists on the network. Go to System in Control Panel to change the computer name, and then try again.
    ERROR_DUP_NAME = WindowsError::ErrorCode.new("ERROR_DUP_NAME",0x00000034,"You were not connected because a duplicate name exists on the network. Go to System in Control Panel to change the computer name, and then try again.")

    # (0x00000035) The network path was not found.
    ERROR_BAD_NETPATH = WindowsError::ErrorCode.new("ERROR_BAD_NETPATH",0x00000035,"The network path was not found.")

    # (0x00000036) The network is busy.
    ERROR_NETWORK_BUSY = WindowsError::ErrorCode.new("ERROR_NETWORK_BUSY",0x00000036,"The network is busy.")

    # (0x00000037) The specified network resource or device is no longer available.
    ERROR_DEV_NOT_EXIST = WindowsError::ErrorCode.new("ERROR_DEV_NOT_EXIST",0x00000037,"The specified network resource or device is no longer available.")

    # (0x00000038) The network BIOS command limit has been reached.
    ERROR_TOO_MANY_CMDS = WindowsError::ErrorCode.new("ERROR_TOO_MANY_CMDS",0x00000038,"The network BIOS command limit has been reached.")

    # (0x00000039) A network adapter hardware error occurred.
    ERROR_ADAP_HDW_ERR = WindowsError::ErrorCode.new("ERROR_ADAP_HDW_ERR",0x00000039,"A network adapter hardware error occurred.")

    # (0x0000003A) The specified server cannot perform the requested operation.
    ERROR_BAD_NET_RESP = WindowsError::ErrorCode.new("ERROR_BAD_NET_RESP",0x0000003A,"The specified server cannot perform the requested operation.")

    # (0x0000003B) An unexpected network error occurred.
    ERROR_UNEXP_NET_ERR = WindowsError::ErrorCode.new("ERROR_UNEXP_NET_ERR",0x0000003B,"An unexpected network error occurred.")

    # (0x0000003C) The remote adapter is not compatible.
    ERROR_BAD_REM_ADAP = WindowsError::ErrorCode.new("ERROR_BAD_REM_ADAP",0x0000003C,"The remote adapter is not compatible.")

    # (0x0000003D) The print queue is full.
    ERROR_PRINTQ_FULL = WindowsError::ErrorCode.new("ERROR_PRINTQ_FULL",0x0000003D,"The print queue is full.")

    # (0x0000003E) Space to store the file waiting to be printed is not available on the server.
    ERROR_NO_SPOOL_SPACE = WindowsError::ErrorCode.new("ERROR_NO_SPOOL_SPACE",0x0000003E,"Space to store the file waiting to be printed is not available on the server.")

    # (0x0000003F) Your file waiting to be printed was deleted.
    ERROR_PRINT_CANCELLED = WindowsError::ErrorCode.new("ERROR_PRINT_CANCELLED",0x0000003F,"Your file waiting to be printed was deleted.")

    # (0x00000040) The specified network name is no longer available.
    ERROR_NETNAME_DELETED = WindowsError::ErrorCode.new("ERROR_NETNAME_DELETED",0x00000040,"The specified network name is no longer available.")

    # (0x00000041) Network access is denied.
    ERROR_NETWORK_ACCESS_DENIED = WindowsError::ErrorCode.new("ERROR_NETWORK_ACCESS_DENIED",0x00000041,"Network access is denied.")

    # (0x00000042) The network resource type is not correct.
    ERROR_BAD_DEV_TYPE = WindowsError::ErrorCode.new("ERROR_BAD_DEV_TYPE",0x00000042,"The network resource type is not correct.")

    # (0x00000043) The network name cannot be found.
    ERROR_BAD_NET_NAME = WindowsError::ErrorCode.new("ERROR_BAD_NET_NAME",0x00000043,"The network name cannot be found.")

    # (0x00000044) The name limit for the local computer network adapter card was exceeded.
    ERROR_TOO_MANY_NAMES = WindowsError::ErrorCode.new("ERROR_TOO_MANY_NAMES",0x00000044,"The name limit for the local computer network adapter card was exceeded.")

    # (0x00000045) The network BIOS session limit was exceeded.
    ERROR_TOO_MANY_SESS = WindowsError::ErrorCode.new("ERROR_TOO_MANY_SESS",0x00000045,"The network BIOS session limit was exceeded.")

    # (0x00000046) The remote server has been paused or is in the process of being started.
    ERROR_SHARING_PAUSED = WindowsError::ErrorCode.new("ERROR_SHARING_PAUSED",0x00000046,"The remote server has been paused or is in the process of being started.")

    # (0x00000047) No more connections can be made to this remote computer at this time because the computer has accepted the maximum number of connections.
    ERROR_REQ_NOT_ACCEP = WindowsError::ErrorCode.new("ERROR_REQ_NOT_ACCEP",0x00000047,"No more connections can be made to this remote computer at this time because the computer has accepted the maximum number of connections.")

    # (0x00000048) The specified printer or disk device has been paused.
    ERROR_REDIR_PAUSED = WindowsError::ErrorCode.new("ERROR_REDIR_PAUSED",0x00000048,"The specified printer or disk device has been paused.")

    # (0x00000050) The file exists.
    ERROR_FILE_EXISTS = WindowsError::ErrorCode.new("ERROR_FILE_EXISTS",0x00000050,"The file exists.")

    # (0x00000052) The directory or file cannot be created.
    ERROR_CANNOT_MAKE = WindowsError::ErrorCode.new("ERROR_CANNOT_MAKE",0x00000052,"The directory or file cannot be created.")

    # (0x00000053) Fail on INT 24.
    ERROR_FAIL_I24 = WindowsError::ErrorCode.new("ERROR_FAIL_I24",0x00000053,"Fail on INT 24.")

    # (0x00000054) Storage to process this request is not available.
    ERROR_OUT_OF_STRUCTURES = WindowsError::ErrorCode.new("ERROR_OUT_OF_STRUCTURES",0x00000054,"Storage to process this request is not available.")

    # (0x00000055) The local device name is already in use.
    ERROR_ALREADY_ASSIGNED = WindowsError::ErrorCode.new("ERROR_ALREADY_ASSIGNED",0x00000055,"The local device name is already in use.")

    # (0x00000056) The specified network password is not correct.
    ERROR_INVALID_PASSWORD = WindowsError::ErrorCode.new("ERROR_INVALID_PASSWORD",0x00000056,"The specified network password is not correct.")

    # (0x00000057) The parameter is incorrect.
    ERROR_INVALID_PARAMETER = WindowsError::ErrorCode.new("ERROR_INVALID_PARAMETER",0x00000057,"The parameter is incorrect.")

    # (0x00000058) A write fault occurred on the network.
    ERROR_NET_WRITE_FAULT = WindowsError::ErrorCode.new("ERROR_NET_WRITE_FAULT",0x00000058,"A write fault occurred on the network.")

    # (0x00000059) The system cannot start another process at this time.
    ERROR_NO_PROC_SLOTS = WindowsError::ErrorCode.new("ERROR_NO_PROC_SLOTS",0x00000059,"The system cannot start another process at this time.")

    # (0x00000064) Cannot create another system semaphore.
    ERROR_TOO_MANY_SEMAPHORES = WindowsError::ErrorCode.new("ERROR_TOO_MANY_SEMAPHORES",0x00000064,"Cannot create another system semaphore.")

    # (0x00000065) The exclusive semaphore is owned by another process.
    ERROR_EXCL_SEM_ALREADY_OWNED = WindowsError::ErrorCode.new("ERROR_EXCL_SEM_ALREADY_OWNED",0x00000065,"The exclusive semaphore is owned by another process.")

    # (0x00000066) The semaphore is set and cannot be closed.
    ERROR_SEM_IS_SET = WindowsError::ErrorCode.new("ERROR_SEM_IS_SET",0x00000066,"The semaphore is set and cannot be closed.")

    # (0x00000067) The semaphore cannot be set again.
    ERROR_TOO_MANY_SEM_REQUESTS = WindowsError::ErrorCode.new("ERROR_TOO_MANY_SEM_REQUESTS",0x00000067,"The semaphore cannot be set again.")

    # (0x00000068) Cannot request exclusive semaphores at interrupt time.
    ERROR_INVALID_AT_INTERRUPT_TIME = WindowsError::ErrorCode.new("ERROR_INVALID_AT_INTERRUPT_TIME",0x00000068,"Cannot request exclusive semaphores at interrupt time.")

    # (0x00000069) The previous ownership of this semaphore has ended.
    ERROR_SEM_OWNER_DIED = WindowsError::ErrorCode.new("ERROR_SEM_OWNER_DIED",0x00000069,"The previous ownership of this semaphore has ended.")

    # (0x0000006A) Insert the disk for drive %1.
    ERROR_SEM_USER_LIMIT = WindowsError::ErrorCode.new("ERROR_SEM_USER_LIMIT",0x0000006A,"Insert the disk for drive %1.")

    # (0x0000006B) The program stopped because an alternate disk was not inserted.
    ERROR_DISK_CHANGE = WindowsError::ErrorCode.new("ERROR_DISK_CHANGE",0x0000006B,"The program stopped because an alternate disk was not inserted.")

    # (0x0000006C) The disk is in use or locked by another process.
    ERROR_DRIVE_LOCKED = WindowsError::ErrorCode.new("ERROR_DRIVE_LOCKED",0x0000006C,"The disk is in use or locked by another process.")

    # (0x0000006D) The pipe has been ended.
    ERROR_BROKEN_PIPE = WindowsError::ErrorCode.new("ERROR_BROKEN_PIPE",0x0000006D,"The pipe has been ended.")

    # (0x0000006E) The system cannot open the device or file specified.
    ERROR_OPEN_FAILED = WindowsError::ErrorCode.new("ERROR_OPEN_FAILED",0x0000006E,"The system cannot open the device or file specified.")

    # (0x0000006F) The file name is too long.
    ERROR_BUFFER_OVERFLOW = WindowsError::ErrorCode.new("ERROR_BUFFER_OVERFLOW",0x0000006F,"The file name is too long.")

    # (0x00000070) There is not enough space on the disk.
    ERROR_DISK_FULL = WindowsError::ErrorCode.new("ERROR_DISK_FULL",0x00000070,"There is not enough space on the disk.")

    # (0x00000071) No more internal file identifiers are available.
    ERROR_NO_MORE_SEARCH_HANDLES = WindowsError::ErrorCode.new("ERROR_NO_MORE_SEARCH_HANDLES",0x00000071,"No more internal file identifiers are available.")

    # (0x00000072) The target internal file identifier is incorrect.
    ERROR_INVALID_TARGET_HANDLE = WindowsError::ErrorCode.new("ERROR_INVALID_TARGET_HANDLE",0x00000072,"The target internal file identifier is incorrect.")

    # (0x00000075) The Input Output Control (IOCTL) call made by the application program is not correct.
    ERROR_INVALID_CATEGORY = WindowsError::ErrorCode.new("ERROR_INVALID_CATEGORY",0x00000075,"The Input Output Control (IOCTL) call made by the application program is not correct.")

    # (0x00000076) The verify-on-write switch parameter value is not correct.
    ERROR_INVALID_VERIFY_SWITCH = WindowsError::ErrorCode.new("ERROR_INVALID_VERIFY_SWITCH",0x00000076,"The verify-on-write switch parameter value is not correct.")

    # (0x00000077) The system does not support the command requested.
    ERROR_BAD_DRIVER_LEVEL = WindowsError::ErrorCode.new("ERROR_BAD_DRIVER_LEVEL",0x00000077,"The system does not support the command requested.")

    # (0x00000078) This function is not supported on this system.
    ERROR_CALL_NOT_IMPLEMENTED = WindowsError::ErrorCode.new("ERROR_CALL_NOT_IMPLEMENTED",0x00000078,"This function is not supported on this system.")

    # (0x00000079) The semaphore time-out period has expired.
    ERROR_SEM_TIMEOUT = WindowsError::ErrorCode.new("ERROR_SEM_TIMEOUT",0x00000079,"The semaphore time-out period has expired.")

    # (0x0000007A) The data area passed to a system call is too small.
    ERROR_INSUFFICIENT_BUFFER = WindowsError::ErrorCode.new("ERROR_INSUFFICIENT_BUFFER",0x0000007A,"The data area passed to a system call is too small.")

    # (0x0000007B) The file name, directory name, or volume label syntax is incorrect.
    ERROR_INVALID_NAME = WindowsError::ErrorCode.new("ERROR_INVALID_NAME",0x0000007B,"The file name, directory name, or volume label syntax is incorrect.")

    # (0x0000007C) The system call level is not correct.
    ERROR_INVALID_LEVEL = WindowsError::ErrorCode.new("ERROR_INVALID_LEVEL",0x0000007C,"The system call level is not correct.")

    # (0x0000007D) The disk has no volume label.
    ERROR_NO_VOLUME_LABEL = WindowsError::ErrorCode.new("ERROR_NO_VOLUME_LABEL",0x0000007D,"The disk has no volume label.")

    # (0x0000007E) The specified module could not be found.
    ERROR_MOD_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_MOD_NOT_FOUND",0x0000007E,"The specified module could not be found.")

    # (0x0000007F) The specified procedure could not be found.
    ERROR_PROC_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_PROC_NOT_FOUND",0x0000007F,"The specified procedure could not be found.")

    # (0x00000080) There are no child processes to wait for.
    ERROR_WAIT_NO_CHILDREN = WindowsError::ErrorCode.new("ERROR_WAIT_NO_CHILDREN",0x00000080,"There are no child processes to wait for.")

    # (0x00000081) The %1 application cannot be run in Win32 mode.
    ERROR_CHILD_NOT_COMPLETE = WindowsError::ErrorCode.new("ERROR_CHILD_NOT_COMPLETE",0x00000081,"The %1 application cannot be run in Win32 mode.")

    # (0x00000082) Attempt to use a file handle to an open disk partition for an operation other than raw disk I/O.
    ERROR_DIRECT_ACCESS_HANDLE = WindowsError::ErrorCode.new("ERROR_DIRECT_ACCESS_HANDLE",0x00000082,"Attempt to use a file handle to an open disk partition for an operation other than raw disk I/O.")

    # (0x00000083) An attempt was made to move the file pointer before the beginning of the file.
    ERROR_NEGATIVE_SEEK = WindowsError::ErrorCode.new("ERROR_NEGATIVE_SEEK",0x00000083,"An attempt was made to move the file pointer before the beginning of the file.")

    # (0x00000084) The file pointer cannot be set on the specified device or file.
    ERROR_SEEK_ON_DEVICE = WindowsError::ErrorCode.new("ERROR_SEEK_ON_DEVICE",0x00000084,"The file pointer cannot be set on the specified device or file.")

    # (0x00000085) A JOIN or SUBST command cannot be used for a drive that contains previously joined drives.
    ERROR_IS_JOIN_TARGET = WindowsError::ErrorCode.new("ERROR_IS_JOIN_TARGET",0x00000085,"A JOIN or SUBST command cannot be used for a drive that contains previously joined drives.")

    # (0x00000086) An attempt was made to use a JOIN or SUBST command on a drive that has already been joined.
    ERROR_IS_JOINED = WindowsError::ErrorCode.new("ERROR_IS_JOINED",0x00000086,"An attempt was made to use a JOIN or SUBST command on a drive that has already been joined.")

    # (0x00000087) An attempt was made to use a JOIN or SUBST command on a drive that has already been substituted.
    ERROR_IS_SUBSTED = WindowsError::ErrorCode.new("ERROR_IS_SUBSTED",0x00000087,"An attempt was made to use a JOIN or SUBST command on a drive that has already been substituted.")

    # (0x00000088) The system tried to delete the JOIN of a drive that is not joined.
    ERROR_NOT_JOINED = WindowsError::ErrorCode.new("ERROR_NOT_JOINED",0x00000088,"The system tried to delete the JOIN of a drive that is not joined.")

    # (0x00000089) The system tried to delete the substitution of a drive that is not substituted.
    ERROR_NOT_SUBSTED = WindowsError::ErrorCode.new("ERROR_NOT_SUBSTED",0x00000089,"The system tried to delete the substitution of a drive that is not substituted.")

    # (0x0000008A) The system tried to join a drive to a directory on a joined drive.
    ERROR_JOIN_TO_JOIN = WindowsError::ErrorCode.new("ERROR_JOIN_TO_JOIN",0x0000008A,"The system tried to join a drive to a directory on a joined drive.")

    # (0x0000008B) The system tried to substitute a drive to a directory on a substituted drive.
    ERROR_SUBST_TO_SUBST = WindowsError::ErrorCode.new("ERROR_SUBST_TO_SUBST",0x0000008B,"The system tried to substitute a drive to a directory on a substituted drive.")

    # (0x0000008C) The system tried to join a drive to a directory on a substituted drive.
    ERROR_JOIN_TO_SUBST = WindowsError::ErrorCode.new("ERROR_JOIN_TO_SUBST",0x0000008C,"The system tried to join a drive to a directory on a substituted drive.")

    # (0x0000008D) The system tried to SUBST a drive to a directory on a joined drive.
    ERROR_SUBST_TO_JOIN = WindowsError::ErrorCode.new("ERROR_SUBST_TO_JOIN",0x0000008D,"The system tried to SUBST a drive to a directory on a joined drive.")

    # (0x0000008E) The system cannot perform a JOIN or SUBST at this time.
    ERROR_BUSY_DRIVE = WindowsError::ErrorCode.new("ERROR_BUSY_DRIVE",0x0000008E,"The system cannot perform a JOIN or SUBST at this time.")

    # (0x0000008F) The system cannot join or substitute a drive to or for a directory on the same drive.
    ERROR_SAME_DRIVE = WindowsError::ErrorCode.new("ERROR_SAME_DRIVE",0x0000008F,"The system cannot join or substitute a drive to or for a directory on the same drive.")

    # (0x00000090) The directory is not a subdirectory of the root directory.
    ERROR_DIR_NOT_ROOT = WindowsError::ErrorCode.new("ERROR_DIR_NOT_ROOT",0x00000090,"The directory is not a subdirectory of the root directory.")

    # (0x00000091) The directory is not empty.
    ERROR_DIR_NOT_EMPTY = WindowsError::ErrorCode.new("ERROR_DIR_NOT_EMPTY",0x00000091,"The directory is not empty.")

    # (0x00000092) The path specified is being used in a substitute.
    ERROR_IS_SUBST_PATH = WindowsError::ErrorCode.new("ERROR_IS_SUBST_PATH",0x00000092,"The path specified is being used in a substitute.")

    # (0x00000093) Not enough resources are available to process this command.
    ERROR_IS_JOIN_PATH = WindowsError::ErrorCode.new("ERROR_IS_JOIN_PATH",0x00000093,"Not enough resources are available to process this command.")

    # (0x00000094) The path specified cannot be used at this time.
    ERROR_PATH_BUSY = WindowsError::ErrorCode.new("ERROR_PATH_BUSY",0x00000094,"The path specified cannot be used at this time.")

    # (0x00000095) An attempt was made to join or substitute a drive for which a directory on the drive is the target of a previous substitute.
    ERROR_IS_SUBST_TARGET = WindowsError::ErrorCode.new("ERROR_IS_SUBST_TARGET",0x00000095,"An attempt was made to join or substitute a drive for which a directory on the drive is the target of a previous substitute.")

    # (0x00000096) System trace information was not specified in your CONFIG.SYS file, or tracing is disallowed.
    ERROR_SYSTEM_TRACE = WindowsError::ErrorCode.new("ERROR_SYSTEM_TRACE",0x00000096,"System trace information was not specified in your CONFIG.SYS file, or tracing is disallowed.")

    # (0x00000097) The number of specified semaphore events for DosMuxSemWait is not correct.
    ERROR_INVALID_EVENT_COUNT = WindowsError::ErrorCode.new("ERROR_INVALID_EVENT_COUNT",0x00000097,"The number of specified semaphore events for DosMuxSemWait is not correct.")

    # (0x00000098) DosMuxSemWait did not execute; too many semaphores are already set.
    ERROR_TOO_MANY_MUXWAITERS = WindowsError::ErrorCode.new("ERROR_TOO_MANY_MUXWAITERS",0x00000098,"DosMuxSemWait did not execute; too many semaphores are already set.")

    # (0x00000099) The DosMuxSemWait list is not correct.
    ERROR_INVALID_LIST_FORMAT = WindowsError::ErrorCode.new("ERROR_INVALID_LIST_FORMAT",0x00000099,"The DosMuxSemWait list is not correct.")

    # (0x0000009A) The volume label you entered exceeds the label character limit of the destination file system.
    ERROR_LABEL_TOO_LONG = WindowsError::ErrorCode.new("ERROR_LABEL_TOO_LONG",0x0000009A,"The volume label you entered exceeds the label character limit of the destination file system.")

    # (0x0000009B) Cannot create another thread.
    ERROR_TOO_MANY_TCBS = WindowsError::ErrorCode.new("ERROR_TOO_MANY_TCBS",0x0000009B,"Cannot create another thread.")

    # (0x0000009C) The recipient process has refused the signal.
    ERROR_SIGNAL_REFUSED = WindowsError::ErrorCode.new("ERROR_SIGNAL_REFUSED",0x0000009C,"The recipient process has refused the signal.")

    # (0x0000009D) The segment is already discarded and cannot be locked.
    ERROR_DISCARDED = WindowsError::ErrorCode.new("ERROR_DISCARDED",0x0000009D,"The segment is already discarded and cannot be locked.")

    # (0x0000009E) The segment is already unlocked.
    ERROR_NOT_LOCKED = WindowsError::ErrorCode.new("ERROR_NOT_LOCKED",0x0000009E,"The segment is already unlocked.")

    # (0x0000009F) The address for the thread ID is not correct.
    ERROR_BAD_THREADID_ADDR = WindowsError::ErrorCode.new("ERROR_BAD_THREADID_ADDR",0x0000009F,"The address for the thread ID is not correct.")

    # (0x000000A0) One or more arguments are not correct.
    ERROR_BAD_ARGUMENTS = WindowsError::ErrorCode.new("ERROR_BAD_ARGUMENTS",0x000000A0,"One or more arguments are not correct.")

    # (0x000000A1) The specified path is invalid.
    ERROR_BAD_PATHNAME = WindowsError::ErrorCode.new("ERROR_BAD_PATHNAME",0x000000A1,"The specified path is invalid.")

    # (0x000000A2) A signal is already pending.
    ERROR_SIGNAL_PENDING = WindowsError::ErrorCode.new("ERROR_SIGNAL_PENDING",0x000000A2,"A signal is already pending.")

    # (0x000000A4) No more threads can be created in the system.
    ERROR_MAX_THRDS_REACHED = WindowsError::ErrorCode.new("ERROR_MAX_THRDS_REACHED",0x000000A4,"No more threads can be created in the system.")

    # (0x000000A7) Unable to lock a region of a file.
    ERROR_LOCK_FAILED = WindowsError::ErrorCode.new("ERROR_LOCK_FAILED",0x000000A7,"Unable to lock a region of a file.")

    # (0x000000AA) The requested resource is in use.
    ERROR_BUSY = WindowsError::ErrorCode.new("ERROR_BUSY",0x000000AA,"The requested resource is in use.")

    # (0x000000AD) A lock request was not outstanding for the supplied cancel region.
    ERROR_CANCEL_VIOLATION = WindowsError::ErrorCode.new("ERROR_CANCEL_VIOLATION",0x000000AD,"A lock request was not outstanding for the supplied cancel region.")

    # (0x000000AE) The file system does not support atomic changes to the lock type.
    ERROR_ATOMIC_LOCKS_NOT_SUPPORTED = WindowsError::ErrorCode.new("ERROR_ATOMIC_LOCKS_NOT_SUPPORTED",0x000000AE,"The file system does not support atomic changes to the lock type.")

    # (0x000000B4) The system detected a segment number that was not correct.
    ERROR_INVALID_SEGMENT_NUMBER = WindowsError::ErrorCode.new("ERROR_INVALID_SEGMENT_NUMBER",0x000000B4,"The system detected a segment number that was not correct.")

    # (0x000000B6) The operating system cannot run %1.
    ERROR_INVALID_ORDINAL = WindowsError::ErrorCode.new("ERROR_INVALID_ORDINAL",0x000000B6,"The operating system cannot run %1.")

    # (0x000000B7) Cannot create a file when that file already exists.
    ERROR_ALREADY_EXISTS = WindowsError::ErrorCode.new("ERROR_ALREADY_EXISTS",0x000000B7,"Cannot create a file when that file already exists.")

    # (0x000000BA) The flag passed is not correct.
    ERROR_INVALID_FLAG_NUMBER = WindowsError::ErrorCode.new("ERROR_INVALID_FLAG_NUMBER",0x000000BA,"The flag passed is not correct.")

    # (0x000000BB) The specified system semaphore name was not found.
    ERROR_SEM_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_SEM_NOT_FOUND",0x000000BB,"The specified system semaphore name was not found.")

    # (0x000000BC) The operating system cannot run %1.
    ERROR_INVALID_STARTING_CODESEG = WindowsError::ErrorCode.new("ERROR_INVALID_STARTING_CODESEG",0x000000BC,"The operating system cannot run %1.")

    # (0x000000BD) The operating system cannot run %1.
    ERROR_INVALID_STACKSEG = WindowsError::ErrorCode.new("ERROR_INVALID_STACKSEG",0x000000BD,"The operating system cannot run %1.")

    # (0x000000BE) The operating system cannot run %1.
    ERROR_INVALID_MODULETYPE = WindowsError::ErrorCode.new("ERROR_INVALID_MODULETYPE",0x000000BE,"The operating system cannot run %1.")

    # (0x000000BF) Cannot run %1 in Win32 mode.
    ERROR_INVALID_EXE_SIGNATURE = WindowsError::ErrorCode.new("ERROR_INVALID_EXE_SIGNATURE",0x000000BF,"Cannot run %1 in Win32 mode.")

    # (0x000000C0) The operating system cannot run %1.
    ERROR_EXE_MARKED_INVALID = WindowsError::ErrorCode.new("ERROR_EXE_MARKED_INVALID",0x000000C0,"The operating system cannot run %1.")

    # (0x000000C1) %1 is not a valid Win32 application.
    ERROR_BAD_EXE_FORMAT = WindowsError::ErrorCode.new("ERROR_BAD_EXE_FORMAT",0x000000C1,"%1 is not a valid Win32 application.")

    # (0x000000C2) The operating system cannot run %1.
    ERROR_ITERATED_DATA_EXCEEDS_64k = WindowsError::ErrorCode.new("ERROR_ITERATED_DATA_EXCEEDS_64k",0x000000C2,"The operating system cannot run %1.")

    # (0x000000C3) The operating system cannot run %1.
    ERROR_INVALID_MINALLOCSIZE = WindowsError::ErrorCode.new("ERROR_INVALID_MINALLOCSIZE",0x000000C3,"The operating system cannot run %1.")

    # (0x000000C4) The operating system cannot run this application program.
    ERROR_DYNLINK_FROM_INVALID_RING = WindowsError::ErrorCode.new("ERROR_DYNLINK_FROM_INVALID_RING",0x000000C4,"The operating system cannot run this application program.")

    # (0x000000C5) The operating system is not presently configured to run this application.
    ERROR_IOPL_NOT_ENABLED = WindowsError::ErrorCode.new("ERROR_IOPL_NOT_ENABLED",0x000000C5,"The operating system is not presently configured to run this application.")

    # (0x000000C6) The operating system cannot run %1.
    ERROR_INVALID_SEGDPL = WindowsError::ErrorCode.new("ERROR_INVALID_SEGDPL",0x000000C6,"The operating system cannot run %1.")

    # (0x000000C7) The operating system cannot run this application program.
    ERROR_AUTODATASEG_EXCEEDS_64k = WindowsError::ErrorCode.new("ERROR_AUTODATASEG_EXCEEDS_64k",0x000000C7,"The operating system cannot run this application program.")

    # (0x000000C8) The code segment cannot be greater than or equal to 64 KB.
    ERROR_RING2SEG_MUST_BE_MOVABLE = WindowsError::ErrorCode.new("ERROR_RING2SEG_MUST_BE_MOVABLE",0x000000C8,"The code segment cannot be greater than or equal to 64 KB.")

    # (0x000000C9) The operating system cannot run %1.
    ERROR_RELOC_CHAIN_XEEDS_SEGLIM = WindowsError::ErrorCode.new("ERROR_RELOC_CHAIN_XEEDS_SEGLIM",0x000000C9,"The operating system cannot run %1.")

    # (0x000000CA) The operating system cannot run %1.
    ERROR_INFLOOP_IN_RELOC_CHAIN = WindowsError::ErrorCode.new("ERROR_INFLOOP_IN_RELOC_CHAIN",0x000000CA,"The operating system cannot run %1.")

    # (0x000000CB) The system could not find the environment option that was entered.
    ERROR_ENVVAR_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_ENVVAR_NOT_FOUND",0x000000CB,"The system could not find the environment option that was entered.")

    # (0x000000CD) No process in the command subtree has a signal handler.
    ERROR_NO_SIGNAL_SENT = WindowsError::ErrorCode.new("ERROR_NO_SIGNAL_SENT",0x000000CD,"No process in the command subtree has a signal handler.")

    # (0x000000CE) The file name or extension is too long.
    ERROR_FILENAME_EXCED_RANGE = WindowsError::ErrorCode.new("ERROR_FILENAME_EXCED_RANGE",0x000000CE,"The file name or extension is too long.")

    # (0x000000CF) The ring 2 stack is in use.
    ERROR_RING2_STACK_IN_USE = WindowsError::ErrorCode.new("ERROR_RING2_STACK_IN_USE",0x000000CF,"The ring 2 stack is in use.")

    # (0x000000D0) The asterisk (*) or question mark (?) global file name characters are entered incorrectly, or too many global file name characters are specified.
    ERROR_META_EXPANSION_TOO_LONG = WindowsError::ErrorCode.new("ERROR_META_EXPANSION_TOO_LONG",0x000000D0,"The asterisk (*) or question mark (?) global file name characters are entered incorrectly, or too many global file name characters are specified.")

    # (0x000000D1) The signal being posted is not correct.
    ERROR_INVALID_SIGNAL_NUMBER = WindowsError::ErrorCode.new("ERROR_INVALID_SIGNAL_NUMBER",0x000000D1,"The signal being posted is not correct.")

    # (0x000000D2) The signal handler cannot be set.
    ERROR_THREAD_1_INACTIVE = WindowsError::ErrorCode.new("ERROR_THREAD_1_INACTIVE",0x000000D2,"The signal handler cannot be set.")

    # (0x000000D4) The segment is locked and cannot be reallocated.
    ERROR_LOCKED = WindowsError::ErrorCode.new("ERROR_LOCKED",0x000000D4,"The segment is locked and cannot be reallocated.")

    # (0x000000D6) Too many dynamic-link modules are attached to this program or dynamic-link module.
    ERROR_TOO_MANY_MODULES = WindowsError::ErrorCode.new("ERROR_TOO_MANY_MODULES",0x000000D6,"Too many dynamic-link modules are attached to this program or dynamic-link module.")

    # (0x000000D7) Cannot nest calls to LoadModule.
    ERROR_NESTING_NOT_ALLOWED = WindowsError::ErrorCode.new("ERROR_NESTING_NOT_ALLOWED",0x000000D7,"Cannot nest calls to LoadModule.")

    # (0x000000D8) This version of %1 is not compatible with the version of Windows you're running. Check your computer's system information to see whether you need an x86 (32-bit) or x64 (64-bit) version of the program, and then contact the software publisher.
    ERROR_EXE_MACHINE_TYPE_MISMATCH = WindowsError::ErrorCode.new("ERROR_EXE_MACHINE_TYPE_MISMATCH",0x000000D8,"This version of %1 is not compatible with the version of Windows you're running. Check your computer's system information to see whether you need an x86 (32-bit) or x64 (64-bit) version of the program, and then contact the software publisher.")

    # (0x000000D9) The image file %1 is signed, unable to modify.
    ERROR_EXE_CANNOT_MODIFY_SIGNED_BINARY = WindowsError::ErrorCode.new("ERROR_EXE_CANNOT_MODIFY_SIGNED_BINARY",0x000000D9,"The image file %1 is signed, unable to modify.")

    # (0x000000DA) The image file %1 is strong signed, unable to modify.
    ERROR_EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY = WindowsError::ErrorCode.new("ERROR_EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY",0x000000DA,"The image file %1 is strong signed, unable to modify.")

    # (0x000000DC) This file is checked out or locked for editing by another user.
    ERROR_FILE_CHECKED_OUT = WindowsError::ErrorCode.new("ERROR_FILE_CHECKED_OUT",0x000000DC,"This file is checked out or locked for editing by another user.")

    # (0x000000DD) The file must be checked out before saving changes.
    ERROR_CHECKOUT_REQUIRED = WindowsError::ErrorCode.new("ERROR_CHECKOUT_REQUIRED",0x000000DD,"The file must be checked out before saving changes.")

    # (0x000000DE) The file type being saved or retrieved has been blocked.
    ERROR_BAD_FILE_TYPE = WindowsError::ErrorCode.new("ERROR_BAD_FILE_TYPE",0x000000DE,"The file type being saved or retrieved has been blocked.")

    # (0x000000DF) The file size exceeds the limit allowed and cannot be saved.
    ERROR_FILE_TOO_LARGE = WindowsError::ErrorCode.new("ERROR_FILE_TOO_LARGE",0x000000DF,"The file size exceeds the limit allowed and cannot be saved.")

    # (0x000000E0) Access denied. Before opening files in this location, you must first browse to the website and select the option to sign in automatically.
    ERROR_FORMS_AUTH_REQUIRED = WindowsError::ErrorCode.new("ERROR_FORMS_AUTH_REQUIRED",0x000000E0,"Access denied. Before opening files in this location, you must first browse to the website and select the option to sign in automatically.")

    # (0x000000E1) Operation did not complete successfully because the file contains a virus.
    ERROR_VIRUS_INFECTED = WindowsError::ErrorCode.new("ERROR_VIRUS_INFECTED",0x000000E1,"Operation did not complete successfully because the file contains a virus.")

    # (0x000000E2) This file contains a virus and cannot be opened. Due to the nature of this virus, the file has been removed from this location.
    ERROR_VIRUS_DELETED = WindowsError::ErrorCode.new("ERROR_VIRUS_DELETED",0x000000E2,"This file contains a virus and cannot be opened. Due to the nature of this virus, the file has been removed from this location.")

    # (0x000000E5) The pipe is local.
    ERROR_PIPE_LOCAL = WindowsError::ErrorCode.new("ERROR_PIPE_LOCAL",0x000000E5,"The pipe is local.")

    # (0x000000E6) The pipe state is invalid.
    ERROR_BAD_PIPE = WindowsError::ErrorCode.new("ERROR_BAD_PIPE",0x000000E6,"The pipe state is invalid.")

    # (0x000000E7) All pipe instances are busy.
    ERROR_PIPE_BUSY = WindowsError::ErrorCode.new("ERROR_PIPE_BUSY",0x000000E7,"All pipe instances are busy.")

    # (0x000000E8) The pipe is being closed.
    ERROR_NO_DATA = WindowsError::ErrorCode.new("ERROR_NO_DATA",0x000000E8,"The pipe is being closed.")

    # (0x000000E9) No process is on the other end of the pipe.
    ERROR_PIPE_NOT_CONNECTED = WindowsError::ErrorCode.new("ERROR_PIPE_NOT_CONNECTED",0x000000E9,"No process is on the other end of the pipe.")

    # (0x000000EA) More data is available.
    ERROR_MORE_DATA = WindowsError::ErrorCode.new("ERROR_MORE_DATA",0x000000EA,"More data is available.")

    # (0x000000F0) The session was canceled.
    ERROR_VC_DISCONNECTED = WindowsError::ErrorCode.new("ERROR_VC_DISCONNECTED",0x000000F0,"The session was canceled.")

    # (0x000000FE) The specified extended attribute name was invalid.
    ERROR_INVALID_EA_NAME = WindowsError::ErrorCode.new("ERROR_INVALID_EA_NAME",0x000000FE,"The specified extended attribute name was invalid.")

    # (0x000000FF) The extended attributes are inconsistent.
    ERROR_EA_LIST_INCONSISTENT = WindowsError::ErrorCode.new("ERROR_EA_LIST_INCONSISTENT",0x000000FF,"The extended attributes are inconsistent.")

    # (0x00000102) The wait operation timed out.
    WAIT_TIMEOUT = WindowsError::ErrorCode.new("WAIT_TIMEOUT",0x00000102,"The wait operation timed out.")

    # (0x00000103) No more data is available.
    ERROR_NO_MORE_ITEMS = WindowsError::ErrorCode.new("ERROR_NO_MORE_ITEMS",0x00000103,"No more data is available.")

    # (0x0000010A) The copy functions cannot be used.
    ERROR_CANNOT_COPY = WindowsError::ErrorCode.new("ERROR_CANNOT_COPY",0x0000010A,"The copy functions cannot be used.")

    # (0x0000010B) The directory name is invalid.
    ERROR_DIRECTORY = WindowsError::ErrorCode.new("ERROR_DIRECTORY",0x0000010B,"The directory name is invalid.")

    # (0x00000113) The extended attributes did not fit in the buffer.
    ERROR_EAS_DIDNT_FIT = WindowsError::ErrorCode.new("ERROR_EAS_DIDNT_FIT",0x00000113,"The extended attributes did not fit in the buffer.")

    # (0x00000114) The extended attribute file on the mounted file system is corrupt.
    ERROR_EA_FILE_CORRUPT = WindowsError::ErrorCode.new("ERROR_EA_FILE_CORRUPT",0x00000114,"The extended attribute file on the mounted file system is corrupt.")

    # (0x00000115) The extended attribute table file is full.
    ERROR_EA_TABLE_FULL = WindowsError::ErrorCode.new("ERROR_EA_TABLE_FULL",0x00000115,"The extended attribute table file is full.")

    # (0x00000116) The specified extended attribute handle is invalid.
    ERROR_INVALID_EA_HANDLE = WindowsError::ErrorCode.new("ERROR_INVALID_EA_HANDLE",0x00000116,"The specified extended attribute handle is invalid.")

    # (0x0000011A) The mounted file system does not support extended attributes.
    ERROR_EAS_NOT_SUPPORTED = WindowsError::ErrorCode.new("ERROR_EAS_NOT_SUPPORTED",0x0000011A,"The mounted file system does not support extended attributes.")

    # (0x00000120) Attempt to release mutex not owned by caller.
    ERROR_NOT_OWNER = WindowsError::ErrorCode.new("ERROR_NOT_OWNER",0x00000120,"Attempt to release mutex not owned by caller.")

    # (0x0000012A) Too many posts were made to a semaphore.
    ERROR_TOO_MANY_POSTS = WindowsError::ErrorCode.new("ERROR_TOO_MANY_POSTS",0x0000012A,"Too many posts were made to a semaphore.")

    # (0x0000012B) Only part of a ReadProcessMemory or WriteProcessMemory request was completed.
    ERROR_PARTIAL_COPY = WindowsError::ErrorCode.new("ERROR_PARTIAL_COPY",0x0000012B,"Only part of a ReadProcessMemory or WriteProcessMemory request was completed.")

    # (0x0000012C) The oplock request is denied.
    ERROR_OPLOCK_NOT_GRANTED = WindowsError::ErrorCode.new("ERROR_OPLOCK_NOT_GRANTED",0x0000012C,"The oplock request is denied.")

    # (0x0000012D) An invalid oplock acknowledgment was received by the system.
    ERROR_INVALID_OPLOCK_PROTOCOL = WindowsError::ErrorCode.new("ERROR_INVALID_OPLOCK_PROTOCOL",0x0000012D,"An invalid oplock acknowledgment was received by the system.")

    # (0x0000012E) The volume is too fragmented to complete this operation.
    ERROR_DISK_TOO_FRAGMENTED = WindowsError::ErrorCode.new("ERROR_DISK_TOO_FRAGMENTED",0x0000012E,"The volume is too fragmented to complete this operation.")

    # (0x0000012F) The file cannot be opened because it is in the process of being deleted.
    ERROR_DELETE_PENDING = WindowsError::ErrorCode.new("ERROR_DELETE_PENDING",0x0000012F,"The file cannot be opened because it is in the process of being deleted.")

    # (0x0000013D) The system cannot find message text for message number 0x%1 in the message file for %2.
    ERROR_MR_MID_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_MR_MID_NOT_FOUND",0x0000013D,"The system cannot find message text for message number 0x%1 in the message file for %2.")

    # (0x0000013E) The scope specified was not found.
    ERROR_SCOPE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_SCOPE_NOT_FOUND",0x0000013E,"The scope specified was not found.")

    # (0x0000015E) No action was taken because a system reboot is required.
    ERROR_FAIL_NOACTION_REBOOT = WindowsError::ErrorCode.new("ERROR_FAIL_NOACTION_REBOOT",0x0000015E,"No action was taken because a system reboot is required.")

    # (0x0000015F) The shutdown operation failed.
    ERROR_FAIL_SHUTDOWN = WindowsError::ErrorCode.new("ERROR_FAIL_SHUTDOWN",0x0000015F,"The shutdown operation failed.")

    # (0x00000160) The restart operation failed.
    ERROR_FAIL_RESTART = WindowsError::ErrorCode.new("ERROR_FAIL_RESTART",0x00000160,"The restart operation failed.")

    # (0x00000161) The maximum number of sessions has been reached.
    ERROR_MAX_SESSIONS_REACHED = WindowsError::ErrorCode.new("ERROR_MAX_SESSIONS_REACHED",0x00000161,"The maximum number of sessions has been reached.")

    # (0x00000190) The thread is already in background processing mode.
    ERROR_THREAD_MODE_ALREADY_BACKGROUND = WindowsError::ErrorCode.new("ERROR_THREAD_MODE_ALREADY_BACKGROUND",0x00000190,"The thread is already in background processing mode.")

    # (0x00000191) The thread is not in background processing mode.
    ERROR_THREAD_MODE_NOT_BACKGROUND = WindowsError::ErrorCode.new("ERROR_THREAD_MODE_NOT_BACKGROUND",0x00000191,"The thread is not in background processing mode.")

    # (0x00000192) The process is already in background processing mode.
    ERROR_PROCESS_MODE_ALREADY_BACKGROUND = WindowsError::ErrorCode.new("ERROR_PROCESS_MODE_ALREADY_BACKGROUND",0x00000192,"The process is already in background processing mode.")

    # (0x00000193) The process is not in background processing mode.
    ERROR_PROCESS_MODE_NOT_BACKGROUND = WindowsError::ErrorCode.new("ERROR_PROCESS_MODE_NOT_BACKGROUND",0x00000193,"The process is not in background processing mode.")

    # (0x000001E7) Attempt to access invalid address.
    ERROR_INVALID_ADDRESS = WindowsError::ErrorCode.new("ERROR_INVALID_ADDRESS",0x000001E7,"Attempt to access invalid address.")

    # (0x000001F4) User profile cannot be loaded.
    ERROR_USER_PROFILE_LOAD = WindowsError::ErrorCode.new("ERROR_USER_PROFILE_LOAD",0x000001F4,"User profile cannot be loaded.")

    # (0x00000216) Arithmetic result exceeded 32 bits.
    ERROR_ARITHMETIC_OVERFLOW = WindowsError::ErrorCode.new("ERROR_ARITHMETIC_OVERFLOW",0x00000216,"Arithmetic result exceeded 32 bits.")

    # (0x00000217) There is a process on the other end of the pipe.
    ERROR_PIPE_CONNECTED = WindowsError::ErrorCode.new("ERROR_PIPE_CONNECTED",0x00000217,"There is a process on the other end of the pipe.")

    # (0x00000218) Waiting for a process to open the other end of the pipe.
    ERROR_PIPE_LISTENING = WindowsError::ErrorCode.new("ERROR_PIPE_LISTENING",0x00000218,"Waiting for a process to open the other end of the pipe.")

    # (0x00000219) Application verifier has found an error in the current process.
    ERROR_VERIFIER_STOP = WindowsError::ErrorCode.new("ERROR_VERIFIER_STOP",0x00000219,"Application verifier has found an error in the current process.")

    # (0x0000021A) An error occurred in the ABIOS subsystem.
    ERROR_ABIOS_ERROR = WindowsError::ErrorCode.new("ERROR_ABIOS_ERROR",0x0000021A,"An error occurred in the ABIOS subsystem.")

    # (0x0000021B) A warning occurred in the WX86 subsystem.
    ERROR_WX86_WARNING = WindowsError::ErrorCode.new("ERROR_WX86_WARNING",0x0000021B,"A warning occurred in the WX86 subsystem.")

    # (0x0000021C) An error occurred in the WX86 subsystem.
    ERROR_WX86_ERROR = WindowsError::ErrorCode.new("ERROR_WX86_ERROR",0x0000021C,"An error occurred in the WX86 subsystem.")

    # (0x0000021D) An attempt was made to cancel or set a timer that has an associated asynchronous procedure call (APC) and the subject thread is not the thread that originally set the timer with an associated APC routine.
    ERROR_TIMER_NOT_CANCELED = WindowsError::ErrorCode.new("ERROR_TIMER_NOT_CANCELED",0x0000021D,"An attempt was made to cancel or set a timer that has an associated asynchronous procedure call (APC) and the subject thread is not the thread that originally set the timer with an associated APC routine.")

    # (0x0000021E) Unwind exception code.
    ERROR_UNWIND = WindowsError::ErrorCode.new("ERROR_UNWIND",0x0000021E,"Unwind exception code.")

    # (0x0000021F) An invalid or unaligned stack was encountered during an unwind operation.
    ERROR_BAD_STACK = WindowsError::ErrorCode.new("ERROR_BAD_STACK",0x0000021F,"An invalid or unaligned stack was encountered during an unwind operation.")

    # (0x00000220) An invalid unwind target was encountered during an unwind operation.
    ERROR_INVALID_UNWIND_TARGET = WindowsError::ErrorCode.new("ERROR_INVALID_UNWIND_TARGET",0x00000220,"An invalid unwind target was encountered during an unwind operation.")

    # (0x00000221) Invalid object attributes specified to NtCreatePort or invalid port attributes specified to NtConnectPort.
    ERROR_INVALID_PORT_ATTRIBUTES = WindowsError::ErrorCode.new("ERROR_INVALID_PORT_ATTRIBUTES",0x00000221,"Invalid object attributes specified to NtCreatePort or invalid port attributes specified to NtConnectPort.")

    # (0x00000222) Length of message passed to NtRequestPort or NtRequestWaitReplyPort was longer than the maximum message allowed by the port.
    ERROR_PORT_MESSAGE_TOO_LONG = WindowsError::ErrorCode.new("ERROR_PORT_MESSAGE_TOO_LONG",0x00000222,"Length of message passed to NtRequestPort or NtRequestWaitReplyPort was longer than the maximum message allowed by the port.")

    # (0x00000223) An attempt was made to lower a quota limit below the current usage.
    ERROR_INVALID_QUOTA_LOWER = WindowsError::ErrorCode.new("ERROR_INVALID_QUOTA_LOWER",0x00000223,"An attempt was made to lower a quota limit below the current usage.")

    # (0x00000224) An attempt was made to attach to a device that was already attached to another device.
    ERROR_DEVICE_ALREADY_ATTACHED = WindowsError::ErrorCode.new("ERROR_DEVICE_ALREADY_ATTACHED",0x00000224,"An attempt was made to attach to a device that was already attached to another device.")

    # (0x00000225) An attempt was made to execute an instruction at an unaligned address, and the host system does not support unaligned instruction references.
    ERROR_INSTRUCTION_MISALIGNMENT = WindowsError::ErrorCode.new("ERROR_INSTRUCTION_MISALIGNMENT",0x00000225,"An attempt was made to execute an instruction at an unaligned address, and the host system does not support unaligned instruction references.")

    # (0x00000226) Profiling not started.
    ERROR_PROFILING_NOT_STARTED = WindowsError::ErrorCode.new("ERROR_PROFILING_NOT_STARTED",0x00000226,"Profiling not started.")

    # (0x00000227) Profiling not stopped.
    ERROR_PROFILING_NOT_STOPPED = WindowsError::ErrorCode.new("ERROR_PROFILING_NOT_STOPPED",0x00000227,"Profiling not stopped.")

    # (0x00000228) The passed ACL did not contain the minimum required information.
    ERROR_COULD_NOT_INTERPRET = WindowsError::ErrorCode.new("ERROR_COULD_NOT_INTERPRET",0x00000228,"The passed ACL did not contain the minimum required information.")

    # (0x00000229) The number of active profiling objects is at the maximum and no more may be started.
    ERROR_PROFILING_AT_LIMIT = WindowsError::ErrorCode.new("ERROR_PROFILING_AT_LIMIT",0x00000229,"The number of active profiling objects is at the maximum and no more may be started.")

    # (0x0000022A) Used to indicate that an operation cannot continue without blocking for I/O.
    ERROR_CANT_WAIT = WindowsError::ErrorCode.new("ERROR_CANT_WAIT",0x0000022A,"Used to indicate that an operation cannot continue without blocking for I/O.")

    # (0x0000022B) Indicates that a thread attempted to terminate itself by default (called NtTerminateThread with NULL) and it was the last thread in the current process.
    ERROR_CANT_TERMINATE_SELF = WindowsError::ErrorCode.new("ERROR_CANT_TERMINATE_SELF",0x0000022B,"Indicates that a thread attempted to terminate itself by default (called NtTerminateThread with NULL) and it was the last thread in the current process.")

    # (0x0000022C) If an MM error is returned that is not defined in the standard FsRtl filter, it is converted to one of the following errors that is guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.
    ERROR_UNEXPECTED_MM_CREATE_ERR = WindowsError::ErrorCode.new("ERROR_UNEXPECTED_MM_CREATE_ERR",0x0000022C,"If an MM error is returned that is not defined in the standard FsRtl filter, it is converted to one of the following errors that is guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.")

    # (0x0000022D) If an MM error is returned that is not defined in the standard FsRtl filter, it is converted to one of the following errors that is guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.
    ERROR_UNEXPECTED_MM_MAP_ERROR = WindowsError::ErrorCode.new("ERROR_UNEXPECTED_MM_MAP_ERROR",0x0000022D,"If an MM error is returned that is not defined in the standard FsRtl filter, it is converted to one of the following errors that is guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.")

    # (0x0000022E) If an MM error is returned that is not defined in the standard FsRtl filter, it is converted to one of the following errors that is guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.
    ERROR_UNEXPECTED_MM_EXTEND_ERR = WindowsError::ErrorCode.new("ERROR_UNEXPECTED_MM_EXTEND_ERR",0x0000022E,"If an MM error is returned that is not defined in the standard FsRtl filter, it is converted to one of the following errors that is guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.")

    # (0x0000022F) A malformed function table was encountered during an unwind operation.
    ERROR_BAD_FUNCTION_TABLE = WindowsError::ErrorCode.new("ERROR_BAD_FUNCTION_TABLE",0x0000022F,"A malformed function table was encountered during an unwind operation.")

    # (0x00000230) Indicates that an attempt was made to assign protection to a file system file or directory and one of the SIDs in the security descriptor could not be translated into a GUID that could be stored by the file system. This causes the protection attempt to fail, which may cause a file creation attempt to fail.
    ERROR_NO_GUID_TRANSLATION = WindowsError::ErrorCode.new("ERROR_NO_GUID_TRANSLATION",0x00000230,"Indicates that an attempt was made to assign protection to a file system file or directory and one of the SIDs in the security descriptor could not be translated into a GUID that could be stored by the file system. This causes the protection attempt to fail, which may cause a file creation attempt to fail.")

    # (0x00000231) Indicates that an attempt was made to grow a local domain table (LDT) by setting its size, or that the size was not an even number of selectors.
    ERROR_INVALID_LDT_SIZE = WindowsError::ErrorCode.new("ERROR_INVALID_LDT_SIZE",0x00000231,"Indicates that an attempt was made to grow a local domain table (LDT) by setting its size, or that the size was not an even number of selectors.")

    # (0x00000233) Indicates that the starting value for the LDT information was not an integral multiple of the selector size.
    ERROR_INVALID_LDT_OFFSET = WindowsError::ErrorCode.new("ERROR_INVALID_LDT_OFFSET",0x00000233,"Indicates that the starting value for the LDT information was not an integral multiple of the selector size.")

    # (0x00000234) Indicates that the user supplied an invalid descriptor when trying to set up LDT descriptors.
    ERROR_INVALID_LDT_DESCRIPTOR = WindowsError::ErrorCode.new("ERROR_INVALID_LDT_DESCRIPTOR",0x00000234,"Indicates that the user supplied an invalid descriptor when trying to set up LDT descriptors.")

    # (0x00000235) Indicates a process has too many threads to perform the requested action. For example, assignment of a primary token may only be performed when a process has zero or one threads.
    ERROR_TOO_MANY_THREADS = WindowsError::ErrorCode.new("ERROR_TOO_MANY_THREADS",0x00000235,"Indicates a process has too many threads to perform the requested action. For example, assignment of a primary token may only be performed when a process has zero or one threads.")

    # (0x00000236) An attempt was made to operate on a thread within a specific process, but the thread specified is not in the process specified.
    ERROR_THREAD_NOT_IN_PROCESS = WindowsError::ErrorCode.new("ERROR_THREAD_NOT_IN_PROCESS",0x00000236,"An attempt was made to operate on a thread within a specific process, but the thread specified is not in the process specified.")

    # (0x00000237) Page file quota was exceeded.
    ERROR_PAGEFILE_QUOTA_EXCEEDED = WindowsError::ErrorCode.new("ERROR_PAGEFILE_QUOTA_EXCEEDED",0x00000237,"Page file quota was exceeded.")

    # (0x00000238) The Netlogon service cannot start because another Netlogon service running in the domain conflicts with the specified role.
    ERROR_LOGON_SERVER_CONFLICT = WindowsError::ErrorCode.new("ERROR_LOGON_SERVER_CONFLICT",0x00000238,"The Netlogon service cannot start because another Netlogon service running in the domain conflicts with the specified role.")

    # (0x00000239) The Security Accounts Manager (SAM) database on a Windows Server is significantly out of synchronization with the copy on the domain controller. A complete synchronization is required.
    ERROR_SYNCHRONIZATION_REQUIRED = WindowsError::ErrorCode.new("ERROR_SYNCHRONIZATION_REQUIRED",0x00000239,"The Security Accounts Manager (SAM) database on a Windows Server is significantly out of synchronization with the copy on the domain controller. A complete synchronization is required.")

    # (0x0000023A) The NtCreateFile API failed. This error should never be returned to an application, it is a place holder for the Windows LAN Manager Redirector to use in its internal error mapping routines.
    ERROR_NET_OPEN_FAILED = WindowsError::ErrorCode.new("ERROR_NET_OPEN_FAILED",0x0000023A,"The NtCreateFile API failed. This error should never be returned to an application, it is a place holder for the Windows LAN Manager Redirector to use in its internal error mapping routines.")

    # (0x0000023B) {Privilege Failed} The I/O permissions for the process could not be changed.
    ERROR_IO_PRIVILEGE_FAILED = WindowsError::ErrorCode.new("ERROR_IO_PRIVILEGE_FAILED",0x0000023B,"{Privilege Failed} The I/O permissions for the process could not be changed.")

    # (0x0000023C) {Application Exit by CTRL+C} The application terminated as a result of a CTRL+C.
    ERROR_CONTROL_C_EXIT = WindowsError::ErrorCode.new("ERROR_CONTROL_C_EXIT",0x0000023C,"{Application Exit by CTRL+C} The application terminated as a result of a CTRL+C.")

    # (0x0000023D) {Missing System File} The required system file %hs is bad or missing.
    ERROR_MISSING_SYSTEMFILE = WindowsError::ErrorCode.new("ERROR_MISSING_SYSTEMFILE",0x0000023D,"{Missing System File} The required system file %hs is bad or missing.")

    # (0x0000023E) {Application Error} The exception %s (0x%08lx) occurred in the application at location 0x%08lx.
    ERROR_UNHANDLED_EXCEPTION = WindowsError::ErrorCode.new("ERROR_UNHANDLED_EXCEPTION",0x0000023E,"{Application Error} The exception %s (0x%08lx) occurred in the application at location 0x%08lx.")

    # (0x0000023F) {Application Error} The application failed to initialize properly (0x%lx). Click OK to terminate the application.
    ERROR_APP_INIT_FAILURE = WindowsError::ErrorCode.new("ERROR_APP_INIT_FAILURE",0x0000023F,"{Application Error} The application failed to initialize properly (0x%lx). Click OK to terminate the application.")

    # (0x00000240) {Unable to Create Paging File} The creation of the paging file %hs failed (%lx). The requested size was %ld.
    ERROR_PAGEFILE_CREATE_FAILED = WindowsError::ErrorCode.new("ERROR_PAGEFILE_CREATE_FAILED",0x00000240,"{Unable to Create Paging File} The creation of the paging file %hs failed (%lx). The requested size was %ld.")

    # (0x00000241) The hash for the image cannot be found in the system catalogs. The image is likely corrupt or the victim of tampering.
    ERROR_INVALID_IMAGE_HASH = WindowsError::ErrorCode.new("ERROR_INVALID_IMAGE_HASH",0x00000241,"The hash for the image cannot be found in the system catalogs. The image is likely corrupt or the victim of tampering.")

    # (0x00000242) {No Paging File Specified} No paging file was specified in the system configuration.
    ERROR_NO_PAGEFILE = WindowsError::ErrorCode.new("ERROR_NO_PAGEFILE",0x00000242,"{No Paging File Specified} No paging file was specified in the system configuration.")

    # (0x00000243) {EXCEPTION} A real-mode application issued a floating-point instruction, and floating-point hardware is not present.
    ERROR_ILLEGAL_FLOAT_CONTEXT = WindowsError::ErrorCode.new("ERROR_ILLEGAL_FLOAT_CONTEXT",0x00000243,"{EXCEPTION} A real-mode application issued a floating-point instruction, and floating-point hardware is not present.")

    # (0x00000244) An event pair synchronization operation was performed using the thread-specific client/server event pair object, but no event pair object was associated with the thread.
    ERROR_NO_EVENT_PAIR = WindowsError::ErrorCode.new("ERROR_NO_EVENT_PAIR",0x00000244,"An event pair synchronization operation was performed using the thread-specific client/server event pair object, but no event pair object was associated with the thread.")

    # (0x00000245) A Windows Server has an incorrect configuration.
    ERROR_DOMAIN_CTRLR_CONFIG_ERROR = WindowsError::ErrorCode.new("ERROR_DOMAIN_CTRLR_CONFIG_ERROR",0x00000245,"A Windows Server has an incorrect configuration.")

    # (0x00000246) An illegal character was encountered. For a multibyte character set, this includes a lead byte without a succeeding trail byte. For the Unicode character set, this includes the characters 0xFFFF and 0xFFFE.
    ERROR_ILLEGAL_CHARACTER = WindowsError::ErrorCode.new("ERROR_ILLEGAL_CHARACTER",0x00000246,"An illegal character was encountered. For a multibyte character set, this includes a lead byte without a succeeding trail byte. For the Unicode character set, this includes the characters 0xFFFF and 0xFFFE.")

    # (0x00000247) The Unicode character is not defined in the Unicode character set installed on the system.
    ERROR_UNDEFINED_CHARACTER = WindowsError::ErrorCode.new("ERROR_UNDEFINED_CHARACTER",0x00000247,"The Unicode character is not defined in the Unicode character set installed on the system.")

    # (0x00000248) The paging file cannot be created on a floppy disk.
    ERROR_FLOPPY_VOLUME = WindowsError::ErrorCode.new("ERROR_FLOPPY_VOLUME",0x00000248,"The paging file cannot be created on a floppy disk.")

    # (0x00000249) The system bios failed to connect a system interrupt to the device or bus for which the device is connected.
    ERROR_BIOS_FAILED_TO_CONNECT_INTERRUPT = WindowsError::ErrorCode.new("ERROR_BIOS_FAILED_TO_CONNECT_INTERRUPT",0x00000249,"The system bios failed to connect a system interrupt to the device or bus for which the device is connected.")

    # (0x0000024A) This operation is only allowed for the primary domain controller (PDC) of the domain.
    ERROR_BACKUP_CONTROLLER = WindowsError::ErrorCode.new("ERROR_BACKUP_CONTROLLER",0x0000024A,"This operation is only allowed for the primary domain controller (PDC) of the domain.")

    # (0x0000024B) An attempt was made to acquire a mutant such that its maximum count would have been exceeded.
    ERROR_MUTANT_LIMIT_EXCEEDED = WindowsError::ErrorCode.new("ERROR_MUTANT_LIMIT_EXCEEDED",0x0000024B,"An attempt was made to acquire a mutant such that its maximum count would have been exceeded.")

    # (0x0000024C) A volume has been accessed for which a file system driver is required that has not yet been loaded.
    ERROR_FS_DRIVER_REQUIRED = WindowsError::ErrorCode.new("ERROR_FS_DRIVER_REQUIRED",0x0000024C,"A volume has been accessed for which a file system driver is required that has not yet been loaded.")

    # (0x0000024D) {Registry File Failure} The registry cannot load the hive (file): %hs or its log or alternate. It is corrupt, absent, or not writable.
    ERROR_CANNOT_LOAD_REGISTRY_FILE = WindowsError::ErrorCode.new("ERROR_CANNOT_LOAD_REGISTRY_FILE",0x0000024D,"{Registry File Failure} The registry cannot load the hive (file): %hs or its log or alternate. It is corrupt, absent, or not writable.")

    # (0x0000024E) {Unexpected Failure in DebugActiveProcess} An unexpected failure occurred while processing a DebugActiveProcess API request. You may choose OK to terminate the process, or Cancel to ignore the error.
    ERROR_DEBUG_ATTACH_FAILED = WindowsError::ErrorCode.new("ERROR_DEBUG_ATTACH_FAILED",0x0000024E,"{Unexpected Failure in DebugActiveProcess} An unexpected failure occurred while processing a DebugActiveProcess API request. You may choose OK to terminate the process, or Cancel to ignore the error.")

    # (0x0000024F) {Fatal System Error} The %hs system process terminated unexpectedly with a status of 0x%08x (0x%08x 0x%08x). The system has been shut down.
    ERROR_SYSTEM_PROCESS_TERMINATED = WindowsError::ErrorCode.new("ERROR_SYSTEM_PROCESS_TERMINATED",0x0000024F,"{Fatal System Error} The %hs system process terminated unexpectedly with a status of 0x%08x (0x%08x 0x%08x). The system has been shut down.")

    # (0x00000250) {Data Not Accepted} The transport driver interface (TDI) client could not handle the data received during an indication.
    ERROR_DATA_NOT_ACCEPTED = WindowsError::ErrorCode.new("ERROR_DATA_NOT_ACCEPTED",0x00000250,"{Data Not Accepted} The transport driver interface (TDI) client could not handle the data received during an indication.")

    # (0x00000251) The NT Virtual DOS Machine (NTVDM) encountered a hard error.
    ERROR_VDM_HARD_ERROR = WindowsError::ErrorCode.new("ERROR_VDM_HARD_ERROR",0x00000251,"The NT Virtual DOS Machine (NTVDM) encountered a hard error.")

    # (0x00000252) {Cancel Timeout} The driver %hs failed to complete a canceled I/O request in the allotted time.
    ERROR_DRIVER_CANCEL_TIMEOUT = WindowsError::ErrorCode.new("ERROR_DRIVER_CANCEL_TIMEOUT",0x00000252,"{Cancel Timeout} The driver %hs failed to complete a canceled I/O request in the allotted time.")

    # (0x00000253) {Reply Message Mismatch} An attempt was made to reply to a local procedure call (LPC) message, but the thread specified by the client ID in the message was not waiting on that message.
    ERROR_REPLY_MESSAGE_MISMATCH = WindowsError::ErrorCode.new("ERROR_REPLY_MESSAGE_MISMATCH",0x00000253,"{Reply Message Mismatch} An attempt was made to reply to a local procedure call (LPC) message, but the thread specified by the client ID in the message was not waiting on that message.")

    # (0x00000254) {Delayed Write Failed} Windows was unable to save all the data for the file %hs. The data has been lost. This error may be caused by a failure of your computer hardware or network connection. Try to save this file elsewhere.
    ERROR_LOST_WRITEBEHIND_DATA = WindowsError::ErrorCode.new("ERROR_LOST_WRITEBEHIND_DATA",0x00000254,"{Delayed Write Failed} Windows was unable to save all the data for the file %hs. The data has been lost. This error may be caused by a failure of your computer hardware or network connection. Try to save this file elsewhere.")

    # (0x00000255) The parameters passed to the server in the client/server shared memory window were invalid. Too much data may have been put in the shared memory window.
    ERROR_CLIENT_SERVER_PARAMETERS_INVALID = WindowsError::ErrorCode.new("ERROR_CLIENT_SERVER_PARAMETERS_INVALID",0x00000255,"The parameters passed to the server in the client/server shared memory window were invalid. Too much data may have been put in the shared memory window.")

    # (0x00000256) The stream is not a tiny stream.
    ERROR_NOT_TINY_STREAM = WindowsError::ErrorCode.new("ERROR_NOT_TINY_STREAM",0x00000256,"The stream is not a tiny stream.")

    # (0x00000257) The request must be handled by the stack overflow code.
    ERROR_STACK_OVERFLOW_READ = WindowsError::ErrorCode.new("ERROR_STACK_OVERFLOW_READ",0x00000257,"The request must be handled by the stack overflow code.")

    # (0x00000258) Internal OFS status codes indicating how an allocation operation is handled. Either it is retried after the containing onode is moved or the extent stream is converted to a large stream.
    ERROR_CONVERT_TO_LARGE = WindowsError::ErrorCode.new("ERROR_CONVERT_TO_LARGE",0x00000258,"Internal OFS status codes indicating how an allocation operation is handled. Either it is retried after the containing onode is moved or the extent stream is converted to a large stream.")

    # (0x00000259) The attempt to find the object found an object matching by ID on the volume but it is out of the scope of the handle used for the operation.
    ERROR_FOUND_OUT_OF_SCOPE = WindowsError::ErrorCode.new("ERROR_FOUND_OUT_OF_SCOPE",0x00000259,"The attempt to find the object found an object matching by ID on the volume but it is out of the scope of the handle used for the operation.")

    # (0x0000025A) The bucket array must be grown. Retry transaction after doing so.
    ERROR_ALLOCATE_BUCKET = WindowsError::ErrorCode.new("ERROR_ALLOCATE_BUCKET",0x0000025A,"The bucket array must be grown. Retry transaction after doing so.")

    # (0x0000025B) The user/kernel marshaling buffer has overflowed.
    ERROR_MARSHALL_OVERFLOW = WindowsError::ErrorCode.new("ERROR_MARSHALL_OVERFLOW",0x0000025B,"The user/kernel marshaling buffer has overflowed.")

    # (0x0000025C) The supplied variant structure contains invalid data.
    ERROR_INVALID_VARIANT = WindowsError::ErrorCode.new("ERROR_INVALID_VARIANT",0x0000025C,"The supplied variant structure contains invalid data.")

    # (0x0000025D) The specified buffer contains ill-formed data.
    ERROR_BAD_COMPRESSION_BUFFER = WindowsError::ErrorCode.new("ERROR_BAD_COMPRESSION_BUFFER",0x0000025D,"The specified buffer contains ill-formed data.")

    # (0x0000025E) {Audit Failed} An attempt to generate a security audit failed.
    ERROR_AUDIT_FAILED = WindowsError::ErrorCode.new("ERROR_AUDIT_FAILED",0x0000025E,"{Audit Failed} An attempt to generate a security audit failed.")

    # (0x0000025F) The timer resolution was not previously set by the current process.
    ERROR_TIMER_RESOLUTION_NOT_SET = WindowsError::ErrorCode.new("ERROR_TIMER_RESOLUTION_NOT_SET",0x0000025F,"The timer resolution was not previously set by the current process.")

    # (0x00000260) There is insufficient account information to log you on.
    ERROR_INSUFFICIENT_LOGON_INFO = WindowsError::ErrorCode.new("ERROR_INSUFFICIENT_LOGON_INFO",0x00000260,"There is insufficient account information to log you on.")

    # (0x00000261) {Invalid DLL Entrypoint} The dynamic link library %hs is not written correctly. The stack pointer has been left in an inconsistent state. The entry point should be declared as WINAPI or STDCALL. Select YES to fail the DLL load. Select NO to continue execution. Selecting NO may cause the application to operate incorrectly.
    ERROR_BAD_DLL_ENTRYPOINT = WindowsError::ErrorCode.new("ERROR_BAD_DLL_ENTRYPOINT",0x00000261,"{Invalid DLL Entrypoint} The dynamic link library %hs is not written correctly. The stack pointer has been left in an inconsistent state. The entry point should be declared as WINAPI or STDCALL. Select YES to fail the DLL load. Select NO to continue execution. Selecting NO may cause the application to operate incorrectly.")

    # (0x00000262) {Invalid Service Callback Entrypoint} The %hs service is not written correctly. The stack pointer has been left in an inconsistent state. The callback entry point should be declared as WINAPI or STDCALL. Selecting OK will cause the service to continue operation. However, the service process may operate incorrectly.
    ERROR_BAD_SERVICE_ENTRYPOINT = WindowsError::ErrorCode.new("ERROR_BAD_SERVICE_ENTRYPOINT",0x00000262,"{Invalid Service Callback Entrypoint} The %hs service is not written correctly. The stack pointer has been left in an inconsistent state. The callback entry point should be declared as WINAPI or STDCALL. Selecting OK will cause the service to continue operation. However, the service process may operate incorrectly.")

    # (0x00000263) There is an IP address conflict with another system on the network.
    ERROR_IP_ADDRESS_CONFLICT1 = WindowsError::ErrorCode.new("ERROR_IP_ADDRESS_CONFLICT1",0x00000263,"There is an IP address conflict with another system on the network.")

    # (0x00000264) There is an IP address conflict with another system on the network.
    ERROR_IP_ADDRESS_CONFLICT2 = WindowsError::ErrorCode.new("ERROR_IP_ADDRESS_CONFLICT2",0x00000264,"There is an IP address conflict with another system on the network.")

    # (0x00000265) {Low On Registry Space} The system has reached the maximum size allowed for the system part of the registry. Additional storage requests will be ignored.
    ERROR_REGISTRY_QUOTA_LIMIT = WindowsError::ErrorCode.new("ERROR_REGISTRY_QUOTA_LIMIT",0x00000265,"{Low On Registry Space} The system has reached the maximum size allowed for the system part of the registry. Additional storage requests will be ignored.")

    # (0x00000266) A callback return system service cannot be executed when no callback is active.
    ERROR_NO_CALLBACK_ACTIVE = WindowsError::ErrorCode.new("ERROR_NO_CALLBACK_ACTIVE",0x00000266,"A callback return system service cannot be executed when no callback is active.")

    # (0x00000267) The password provided is too short to meet the policy of your user account. Choose a longer password.
    ERROR_PWD_TOO_SHORT = WindowsError::ErrorCode.new("ERROR_PWD_TOO_SHORT",0x00000267,"The password provided is too short to meet the policy of your user account. Choose a longer password.")

    # (0x00000268) The policy of your user account does not allow you to change passwords too frequently. This is done to prevent users from changing back to a familiar, but potentially discovered, password. If you feel your password has been compromised, contact your administrator immediately to have a new one assigned.
    ERROR_PWD_TOO_RECENT = WindowsError::ErrorCode.new("ERROR_PWD_TOO_RECENT",0x00000268,"The policy of your user account does not allow you to change passwords too frequently. This is done to prevent users from changing back to a familiar, but potentially discovered, password. If you feel your password has been compromised, contact your administrator immediately to have a new one assigned.")

    # (0x00000269) You have attempted to change your password to one that you have used in the past. The policy of your user account does not allow this. Select a password that you have not previously used.
    ERROR_PWD_HISTORY_CONFLICT = WindowsError::ErrorCode.new("ERROR_PWD_HISTORY_CONFLICT",0x00000269,"You have attempted to change your password to one that you have used in the past. The policy of your user account does not allow this. Select a password that you have not previously used.")

    # (0x0000026A) The specified compression format is unsupported.
    ERROR_UNSUPPORTED_COMPRESSION = WindowsError::ErrorCode.new("ERROR_UNSUPPORTED_COMPRESSION",0x0000026A,"The specified compression format is unsupported.")

    # (0x0000026B) The specified hardware profile configuration is invalid.
    ERROR_INVALID_HW_PROFILE = WindowsError::ErrorCode.new("ERROR_INVALID_HW_PROFILE",0x0000026B,"The specified hardware profile configuration is invalid.")

    # (0x0000026C) The specified Plug and Play registry device path is invalid.
    ERROR_INVALID_PLUGPLAY_DEVICE_PATH = WindowsError::ErrorCode.new("ERROR_INVALID_PLUGPLAY_DEVICE_PATH",0x0000026C,"The specified Plug and Play registry device path is invalid.")

    # (0x0000026D) The specified quota list is internally inconsistent with its descriptor.
    ERROR_QUOTA_LIST_INCONSISTENT = WindowsError::ErrorCode.new("ERROR_QUOTA_LIST_INCONSISTENT",0x0000026D,"The specified quota list is internally inconsistent with its descriptor.")

    # (0x0000026E) {Windows Evaluation Notification} The evaluation period for this installation of Windows has expired. This system will shut down in 1 hour. To restore access to this installation of Windows, upgrade this installation using a licensed distribution of this product.
    ERROR_EVALUATION_EXPIRATION = WindowsError::ErrorCode.new("ERROR_EVALUATION_EXPIRATION",0x0000026E,"{Windows Evaluation Notification} The evaluation period for this installation of Windows has expired. This system will shut down in 1 hour. To restore access to this installation of Windows, upgrade this installation using a licensed distribution of this product.")

    # (0x0000026F) {Illegal System DLL Relocation} The system DLL %hs was relocated in memory. The application will not run properly. The relocation occurred because the DLL %hs occupied an address range reserved for Windows system DLLs. The vendor supplying the DLL should be contacted for a new DLL.
    ERROR_ILLEGAL_DLL_RELOCATION = WindowsError::ErrorCode.new("ERROR_ILLEGAL_DLL_RELOCATION",0x0000026F,"{Illegal System DLL Relocation} The system DLL %hs was relocated in memory. The application will not run properly. The relocation occurred because the DLL %hs occupied an address range reserved for Windows system DLLs. The vendor supplying the DLL should be contacted for a new DLL.")

    # (0x00000270) {DLL Initialization Failed} The application failed to initialize because the window station is shutting down.
    ERROR_DLL_INIT_FAILED_LOGOFF = WindowsError::ErrorCode.new("ERROR_DLL_INIT_FAILED_LOGOFF",0x00000270,"{DLL Initialization Failed} The application failed to initialize because the window station is shutting down.")

    # (0x00000271) The validation process needs to continue on to the next step.
    ERROR_VALIDATE_CONTINUE = WindowsError::ErrorCode.new("ERROR_VALIDATE_CONTINUE",0x00000271,"The validation process needs to continue on to the next step.")

    # (0x00000272) There are no more matches for the current index enumeration.
    ERROR_NO_MORE_MATCHES = WindowsError::ErrorCode.new("ERROR_NO_MORE_MATCHES",0x00000272,"There are no more matches for the current index enumeration.")

    # (0x00000273) The range could not be added to the range list because of a conflict.
    ERROR_RANGE_LIST_CONFLICT = WindowsError::ErrorCode.new("ERROR_RANGE_LIST_CONFLICT",0x00000273,"The range could not be added to the range list because of a conflict.")

    # (0x00000274) The server process is running under a SID different than that required by the client.
    ERROR_SERVER_SID_MISMATCH = WindowsError::ErrorCode.new("ERROR_SERVER_SID_MISMATCH",0x00000274,"The server process is running under a SID different than that required by the client.")

    # (0x00000275) A group marked use for deny only cannot be enabled.
    ERROR_CANT_ENABLE_DENY_ONLY = WindowsError::ErrorCode.new("ERROR_CANT_ENABLE_DENY_ONLY",0x00000275,"A group marked use for deny only cannot be enabled.")

    # (0x00000276) {EXCEPTION} Multiple floating point faults.
    ERROR_FLOAT_MULTIPLE_FAULTS = WindowsError::ErrorCode.new("ERROR_FLOAT_MULTIPLE_FAULTS",0x00000276,"{EXCEPTION} Multiple floating point faults.")

    # (0x00000277) {EXCEPTION} Multiple floating point traps.
    ERROR_FLOAT_MULTIPLE_TRAPS = WindowsError::ErrorCode.new("ERROR_FLOAT_MULTIPLE_TRAPS",0x00000277,"{EXCEPTION} Multiple floating point traps.")

    # (0x00000278) The requested interface is not supported.
    ERROR_NOINTERFACE = WindowsError::ErrorCode.new("ERROR_NOINTERFACE",0x00000278,"The requested interface is not supported.")

    # (0x00000279) {System Standby Failed} The driver %hs does not support standby mode. Updating this driver may allow the system to go to standby mode.
    ERROR_DRIVER_FAILED_SLEEP = WindowsError::ErrorCode.new("ERROR_DRIVER_FAILED_SLEEP",0x00000279,"{System Standby Failed} The driver %hs does not support standby mode. Updating this driver may allow the system to go to standby mode.")

    # (0x0000027A) The system file %1 has become corrupt and has been replaced.
    ERROR_CORRUPT_SYSTEM_FILE = WindowsError::ErrorCode.new("ERROR_CORRUPT_SYSTEM_FILE",0x0000027A,"The system file %1 has become corrupt and has been replaced.")

    # (0x0000027B) {Virtual Memory Minimum Too Low} Your system is low on virtual memory. Windows is increasing the size of your virtual memory paging file. During this process, memory requests for some applications may be denied. For more information, see Help.
    ERROR_COMMITMENT_MINIMUM = WindowsError::ErrorCode.new("ERROR_COMMITMENT_MINIMUM",0x0000027B,"{Virtual Memory Minimum Too Low} Your system is low on virtual memory. Windows is increasing the size of your virtual memory paging file. During this process, memory requests for some applications may be denied. For more information, see Help.")

    # (0x0000027C) A device was removed so enumeration must be restarted.
    ERROR_PNP_RESTART_ENUMERATION = WindowsError::ErrorCode.new("ERROR_PNP_RESTART_ENUMERATION",0x0000027C,"A device was removed so enumeration must be restarted.")

    # (0x0000027D) {Fatal System Error} The system image %s is not properly signed. The file has been replaced with the signed file. The system has been shut down.
    ERROR_SYSTEM_IMAGE_BAD_SIGNATURE = WindowsError::ErrorCode.new("ERROR_SYSTEM_IMAGE_BAD_SIGNATURE",0x0000027D,"{Fatal System Error} The system image %s is not properly signed. The file has been replaced with the signed file. The system has been shut down.")

    # (0x0000027E) Device will not start without a reboot.
    ERROR_PNP_REBOOT_REQUIRED = WindowsError::ErrorCode.new("ERROR_PNP_REBOOT_REQUIRED",0x0000027E,"Device will not start without a reboot.")

    # (0x0000027F) There is not enough power to complete the requested operation.
    ERROR_INSUFFICIENT_POWER = WindowsError::ErrorCode.new("ERROR_INSUFFICIENT_POWER",0x0000027F,"There is not enough power to complete the requested operation.")

    # (0x00000281) The system is in the process of shutting down.
    ERROR_SYSTEM_SHUTDOWN = WindowsError::ErrorCode.new("ERROR_SYSTEM_SHUTDOWN",0x00000281,"The system is in the process of shutting down.")

    # (0x00000282) An attempt to remove a process DebugPort was made, but a port was not already associated with the process.
    ERROR_PORT_NOT_SET = WindowsError::ErrorCode.new("ERROR_PORT_NOT_SET",0x00000282,"An attempt to remove a process DebugPort was made, but a port was not already associated with the process.")

    # (0x00000283) This version of Windows is not compatible with the behavior version of directory forest, domain, or domain controller.
    ERROR_DS_VERSION_CHECK_FAILURE = WindowsError::ErrorCode.new("ERROR_DS_VERSION_CHECK_FAILURE",0x00000283,"This version of Windows is not compatible with the behavior version of directory forest, domain, or domain controller.")

    # (0x00000284) The specified range could not be found in the range list.
    ERROR_RANGE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_RANGE_NOT_FOUND",0x00000284,"The specified range could not be found in the range list.")

    # (0x00000286) The driver was not loaded because the system is booting into safe mode.
    ERROR_NOT_SAFE_MODE_DRIVER = WindowsError::ErrorCode.new("ERROR_NOT_SAFE_MODE_DRIVER",0x00000286,"The driver was not loaded because the system is booting into safe mode.")

    # (0x00000287) The driver was not loaded because it failed its initialization call.
    ERROR_FAILED_DRIVER_ENTRY = WindowsError::ErrorCode.new("ERROR_FAILED_DRIVER_ENTRY",0x00000287,"The driver was not loaded because it failed its initialization call.")

    # (0x00000288) The device encountered an error while applying power or reading the device configuration. This may be caused by a failure of your hardware or by a poor connection.
    ERROR_DEVICE_ENUMERATION_ERROR = WindowsError::ErrorCode.new("ERROR_DEVICE_ENUMERATION_ERROR",0x00000288,"The device encountered an error while applying power or reading the device configuration. This may be caused by a failure of your hardware or by a poor connection.")

    # (0x00000289) The create operation failed because the name contained at least one mount point that resolves to a volume to which the specified device object is not attached.
    ERROR_MOUNT_POINT_NOT_RESOLVED = WindowsError::ErrorCode.new("ERROR_MOUNT_POINT_NOT_RESOLVED",0x00000289,"The create operation failed because the name contained at least one mount point that resolves to a volume to which the specified device object is not attached.")

    # (0x0000028A) The device object parameter is either not a valid device object or is not attached to the volume specified by the file name.
    ERROR_INVALID_DEVICE_OBJECT_PARAMETER = WindowsError::ErrorCode.new("ERROR_INVALID_DEVICE_OBJECT_PARAMETER",0x0000028A,"The device object parameter is either not a valid device object or is not attached to the volume specified by the file name.")

    # (0x0000028B) A machine check error has occurred. Check the system event log for additional information.
    ERROR_MCA_OCCURED = WindowsError::ErrorCode.new("ERROR_MCA_OCCURED",0x0000028B,"A machine check error has occurred. Check the system event log for additional information.")

    # (0x0000028C) There was an error [%2] processing the driver database.
    ERROR_DRIVER_DATABASE_ERROR = WindowsError::ErrorCode.new("ERROR_DRIVER_DATABASE_ERROR",0x0000028C,"There was an error [%2] processing the driver database.")

    # (0x0000028D) The system hive size has exceeded its limit.
    ERROR_SYSTEM_HIVE_TOO_LARGE = WindowsError::ErrorCode.new("ERROR_SYSTEM_HIVE_TOO_LARGE",0x0000028D,"The system hive size has exceeded its limit.")

    # (0x0000028E) The driver could not be loaded because a previous version of the driver is still in memory.
    ERROR_DRIVER_FAILED_PRIOR_UNLOAD = WindowsError::ErrorCode.new("ERROR_DRIVER_FAILED_PRIOR_UNLOAD",0x0000028E,"The driver could not be loaded because a previous version of the driver is still in memory.")

    # (0x0000028F) {Volume Shadow Copy Service} Wait while the Volume Shadow Copy Service prepares volume %hs for hibernation.
    ERROR_VOLSNAP_PREPARE_HIBERNATE = WindowsError::ErrorCode.new("ERROR_VOLSNAP_PREPARE_HIBERNATE",0x0000028F,"{Volume Shadow Copy Service} Wait while the Volume Shadow Copy Service prepares volume %hs for hibernation.")

    # (0x00000290) The system has failed to hibernate (the error code is %hs). Hibernation will be disabled until the system is restarted.
    ERROR_HIBERNATION_FAILURE = WindowsError::ErrorCode.new("ERROR_HIBERNATION_FAILURE",0x00000290,"The system has failed to hibernate (the error code is %hs). Hibernation will be disabled until the system is restarted.")

    # (0x00000299) The requested operation could not be completed due to a file system limitation.
    ERROR_FILE_SYSTEM_LIMITATION = WindowsError::ErrorCode.new("ERROR_FILE_SYSTEM_LIMITATION",0x00000299,"The requested operation could not be completed due to a file system limitation.")

    # (0x0000029C) An assertion failure has occurred.
    ERROR_ASSERTION_FAILURE = WindowsError::ErrorCode.new("ERROR_ASSERTION_FAILURE",0x0000029C,"An assertion failure has occurred.")

    # (0x0000029D) An error occurred in the Advanced Configuration and Power Interface (ACPI) subsystem.
    ERROR_ACPI_ERROR = WindowsError::ErrorCode.new("ERROR_ACPI_ERROR",0x0000029D,"An error occurred in the Advanced Configuration and Power Interface (ACPI) subsystem.")

    # (0x0000029E) WOW assertion error.
    ERROR_WOW_ASSERTION = WindowsError::ErrorCode.new("ERROR_WOW_ASSERTION",0x0000029E,"WOW assertion error.")

    # (0x0000029F) A device is missing in the system BIOS MultiProcessor Specification (MPS) table. This device will not be used. Contact your system vendor for system BIOS update.
    ERROR_PNP_BAD_MPS_TABLE = WindowsError::ErrorCode.new("ERROR_PNP_BAD_MPS_TABLE",0x0000029F,"A device is missing in the system BIOS MultiProcessor Specification (MPS) table. This device will not be used. Contact your system vendor for system BIOS update.")

    # (0x000002A0) A translator failed to translate resources.
    ERROR_PNP_TRANSLATION_FAILED = WindowsError::ErrorCode.new("ERROR_PNP_TRANSLATION_FAILED",0x000002A0,"A translator failed to translate resources.")

    # (0x000002A1) An interrupt request (IRQ) translator failed to translate resources.
    ERROR_PNP_IRQ_TRANSLATION_FAILED = WindowsError::ErrorCode.new("ERROR_PNP_IRQ_TRANSLATION_FAILED",0x000002A1,"An interrupt request (IRQ) translator failed to translate resources.")

    # (0x000002A2) Driver %2 returned invalid ID for a child device (%3).
    ERROR_PNP_INVALID_ID = WindowsError::ErrorCode.new("ERROR_PNP_INVALID_ID",0x000002A2,"Driver %2 returned invalid ID for a child device (%3).")

    # (0x000002A3) {Kernel Debugger Awakened} the system debugger was awakened by an interrupt.
    ERROR_WAKE_SYSTEM_DEBUGGER = WindowsError::ErrorCode.new("ERROR_WAKE_SYSTEM_DEBUGGER",0x000002A3,"{Kernel Debugger Awakened} the system debugger was awakened by an interrupt.")

    # (0x000002A4) {Handles Closed} Handles to objects have been automatically closed because of the requested operation.
    ERROR_HANDLES_CLOSED = WindowsError::ErrorCode.new("ERROR_HANDLES_CLOSED",0x000002A4,"{Handles Closed} Handles to objects have been automatically closed because of the requested operation.")

    # (0x000002A5) {Too Much Information} The specified ACL contained more information than was expected.
    ERROR_EXTRANEOUS_INFORMATION = WindowsError::ErrorCode.new("ERROR_EXTRANEOUS_INFORMATION",0x000002A5,"{Too Much Information} The specified ACL contained more information than was expected.")

    # (0x000002A6) This warning level status indicates that the transaction state already exists for the registry subtree, but that a transaction commit was previously aborted. The commit has NOT been completed, but it has not been rolled back either (so it may still be committed if desired).
    ERROR_RXACT_COMMIT_NECESSARY = WindowsError::ErrorCode.new("ERROR_RXACT_COMMIT_NECESSARY",0x000002A6,"This warning level status indicates that the transaction state already exists for the registry subtree, but that a transaction commit was previously aborted. The commit has NOT been completed, but it has not been rolled back either (so it may still be committed if desired).")

    # (0x000002A7) {Media Changed} The media may have changed.
    ERROR_MEDIA_CHECK = WindowsError::ErrorCode.new("ERROR_MEDIA_CHECK",0x000002A7,"{Media Changed} The media may have changed.")

    # (0x000002A8) {GUID Substitution} During the translation of a GUID to a Windows SID, no administratively defined GUID prefix was found. A substitute prefix was used, which will not compromise system security. However, this may provide more restrictive access than intended.
    ERROR_GUID_SUBSTITUTION_MADE = WindowsError::ErrorCode.new("ERROR_GUID_SUBSTITUTION_MADE",0x000002A8,"{GUID Substitution} During the translation of a GUID to a Windows SID, no administratively defined GUID prefix was found. A substitute prefix was used, which will not compromise system security. However, this may provide more restrictive access than intended.")

    # (0x000002A9) The create operation stopped after reaching a symbolic link.
    ERROR_STOPPED_ON_SYMLINK = WindowsError::ErrorCode.new("ERROR_STOPPED_ON_SYMLINK",0x000002A9,"The create operation stopped after reaching a symbolic link.")

    # (0x000002AA) A long jump has been executed.
    ERROR_LONGJUMP = WindowsError::ErrorCode.new("ERROR_LONGJUMP",0x000002AA,"A long jump has been executed.")

    # (0x000002AB) The Plug and Play query operation was not successful.
    ERROR_PLUGPLAY_QUERY_VETOED = WindowsError::ErrorCode.new("ERROR_PLUGPLAY_QUERY_VETOED",0x000002AB,"The Plug and Play query operation was not successful.")

    # (0x000002AC) A frame consolidation has been executed.
    ERROR_UNWIND_CONSOLIDATE = WindowsError::ErrorCode.new("ERROR_UNWIND_CONSOLIDATE",0x000002AC,"A frame consolidation has been executed.")

    # (0x000002AD) {Registry Hive Recovered} Registry hive (file): %hs was corrupted and it has been recovered. Some data might have been lost.
    ERROR_REGISTRY_HIVE_RECOVERED = WindowsError::ErrorCode.new("ERROR_REGISTRY_HIVE_RECOVERED",0x000002AD,"{Registry Hive Recovered} Registry hive (file): %hs was corrupted and it has been recovered. Some data might have been lost.")

    # (0x000002AE) The application is attempting to run executable code from the module %hs. This may be insecure. An alternative, %hs, is available. Should the application use the secure module %hs?
    ERROR_DLL_MIGHT_BE_INSECURE = WindowsError::ErrorCode.new("ERROR_DLL_MIGHT_BE_INSECURE",0x000002AE,"The application is attempting to run executable code from the module %hs. This may be insecure. An alternative, %hs, is available. Should the application use the secure module %hs?")

    # (0x000002AF) The application is loading executable code from the module %hs. This is secure, but may be incompatible with previous releases of the operating system. An alternative, %hs, is available. Should the application use the secure module %hs?
    ERROR_DLL_MIGHT_BE_INCOMPATIBLE = WindowsError::ErrorCode.new("ERROR_DLL_MIGHT_BE_INCOMPATIBLE",0x000002AF,"The application is loading executable code from the module %hs. This is secure, but may be incompatible with previous releases of the operating system. An alternative, %hs, is available. Should the application use the secure module %hs?")

    # (0x000002B0) Debugger did not handle the exception.
    ERROR_DBG_EXCEPTION_NOT_HANDLED = WindowsError::ErrorCode.new("ERROR_DBG_EXCEPTION_NOT_HANDLED",0x000002B0,"Debugger did not handle the exception.")

    # (0x000002B1) Debugger will reply later.
    ERROR_DBG_REPLY_LATER = WindowsError::ErrorCode.new("ERROR_DBG_REPLY_LATER",0x000002B1,"Debugger will reply later.")

    # (0x000002B2) Debugger cannot provide handle.
    ERROR_DBG_UNABLE_TO_PROVIDE_HANDLE = WindowsError::ErrorCode.new("ERROR_DBG_UNABLE_TO_PROVIDE_HANDLE",0x000002B2,"Debugger cannot provide handle.")

    # (0x000002B3) Debugger terminated thread.
    ERROR_DBG_TERMINATE_THREAD = WindowsError::ErrorCode.new("ERROR_DBG_TERMINATE_THREAD",0x000002B3,"Debugger terminated thread.")

    # (0x000002B4) Debugger terminated process.
    ERROR_DBG_TERMINATE_PROCESS = WindowsError::ErrorCode.new("ERROR_DBG_TERMINATE_PROCESS",0x000002B4,"Debugger terminated process.")

    # (0x000002B5) Debugger got control C.
    ERROR_DBG_CONTROL_C = WindowsError::ErrorCode.new("ERROR_DBG_CONTROL_C",0x000002B5,"Debugger got control C.")

    # (0x000002B6) Debugger printed exception on control C.
    ERROR_DBG_PRINTEXCEPTION_C = WindowsError::ErrorCode.new("ERROR_DBG_PRINTEXCEPTION_C",0x000002B6,"Debugger printed exception on control C.")

    # (0x000002B7) Debugger received Routing Information Protocol (RIP) exception.
    ERROR_DBG_RIPEXCEPTION = WindowsError::ErrorCode.new("ERROR_DBG_RIPEXCEPTION",0x000002B7,"Debugger received Routing Information Protocol (RIP) exception.")

    # (0x000002B8) Debugger received control break.
    ERROR_DBG_CONTROL_BREAK = WindowsError::ErrorCode.new("ERROR_DBG_CONTROL_BREAK",0x000002B8,"Debugger received control break.")

    # (0x000002B9) Debugger command communication exception.
    ERROR_DBG_COMMAND_EXCEPTION = WindowsError::ErrorCode.new("ERROR_DBG_COMMAND_EXCEPTION",0x000002B9,"Debugger command communication exception.")

    # (0x000002BA) {Object Exists} An attempt was made to create an object and the object name already existed.
    ERROR_OBJECT_NAME_EXISTS = WindowsError::ErrorCode.new("ERROR_OBJECT_NAME_EXISTS",0x000002BA,"{Object Exists} An attempt was made to create an object and the object name already existed.")

    # (0x000002BB) {Thread Suspended} A thread termination occurred while the thread was suspended. The thread was resumed and termination proceeded.
    ERROR_THREAD_WAS_SUSPENDED = WindowsError::ErrorCode.new("ERROR_THREAD_WAS_SUSPENDED",0x000002BB,"{Thread Suspended} A thread termination occurred while the thread was suspended. The thread was resumed and termination proceeded.")

    # (0x000002BC) {Image Relocated} An image file could not be mapped at the address specified in the image file. Local fixes must be performed on this image.
    ERROR_IMAGE_NOT_AT_BASE = WindowsError::ErrorCode.new("ERROR_IMAGE_NOT_AT_BASE",0x000002BC,"{Image Relocated} An image file could not be mapped at the address specified in the image file. Local fixes must be performed on this image.")

    # (0x000002BD) This informational level status indicates that a specified registry subtree transaction state did not yet exist and had to be created.
    ERROR_RXACT_STATE_CREATED = WindowsError::ErrorCode.new("ERROR_RXACT_STATE_CREATED",0x000002BD,"This informational level status indicates that a specified registry subtree transaction state did not yet exist and had to be created.")

    # (0x000002BE) {Segment Load} A virtual DOS machine (VDM) is loading, unloading, or moving an MS-DOS or Win16 program segment image. An exception is raised so a debugger can load, unload, or track symbols and breakpoints within these 16-bit segments.
    ERROR_SEGMENT_NOTIFICATION = WindowsError::ErrorCode.new("ERROR_SEGMENT_NOTIFICATION",0x000002BE,"{Segment Load} A virtual DOS machine (VDM) is loading, unloading, or moving an MS-DOS or Win16 program segment image. An exception is raised so a debugger can load, unload, or track symbols and breakpoints within these 16-bit segments.")

    # (0x000002BF) {Invalid Current Directory} The process cannot switch to the startup current directory %hs. Select OK to set current directory to %hs, or select CANCEL to exit.
    ERROR_BAD_CURRENT_DIRECTORY = WindowsError::ErrorCode.new("ERROR_BAD_CURRENT_DIRECTORY",0x000002BF,"{Invalid Current Directory} The process cannot switch to the startup current directory %hs. Select OK to set current directory to %hs, or select CANCEL to exit.")

    # (0x000002C0) {Redundant Read} To satisfy a read request, the NT fault-tolerant file system successfully read the requested data from a redundant copy. This was done because the file system encountered a failure on a member of the fault-tolerant volume, but it was unable to reassign the failing area of the device.
    ERROR_FT_READ_RECOVERY_FROM_BACKUP = WindowsError::ErrorCode.new("ERROR_FT_READ_RECOVERY_FROM_BACKUP",0x000002C0,"{Redundant Read} To satisfy a read request, the NT fault-tolerant file system successfully read the requested data from a redundant copy. This was done because the file system encountered a failure on a member of the fault-tolerant volume, but it was unable to reassign the failing area of the device.")

    # (0x000002C1) {Redundant Write} To satisfy a write request, the Windows NT fault-tolerant file system successfully wrote a redundant copy of the information. This was done because the file system encountered a failure on a member of the fault-tolerant volume, but it was not able to reassign the failing area of the device.
    ERROR_FT_WRITE_RECOVERY = WindowsError::ErrorCode.new("ERROR_FT_WRITE_RECOVERY",0x000002C1,"{Redundant Write} To satisfy a write request, the Windows NT fault-tolerant file system successfully wrote a redundant copy of the information. This was done because the file system encountered a failure on a member of the fault-tolerant volume, but it was not able to reassign the failing area of the device.")

    # (0x000002C2) {Machine Type Mismatch} The image file %hs is valid, but is for a machine type other than the current machine. Select OK to continue, or CANCEL to fail the DLL load.
    ERROR_IMAGE_MACHINE_TYPE_MISMATCH = WindowsError::ErrorCode.new("ERROR_IMAGE_MACHINE_TYPE_MISMATCH",0x000002C2,"{Machine Type Mismatch} The image file %hs is valid, but is for a machine type other than the current machine. Select OK to continue, or CANCEL to fail the DLL load.")

    # (0x000002C3) {Partial Data Received} The network transport returned partial data to its client. The remaining data will be sent later.
    ERROR_RECEIVE_PARTIAL = WindowsError::ErrorCode.new("ERROR_RECEIVE_PARTIAL",0x000002C3,"{Partial Data Received} The network transport returned partial data to its client. The remaining data will be sent later.")

    # (0x000002C4) {Expedited Data Received} The network transport returned data to its client that was marked as expedited by the remote system.
    ERROR_RECEIVE_EXPEDITED = WindowsError::ErrorCode.new("ERROR_RECEIVE_EXPEDITED",0x000002C4,"{Expedited Data Received} The network transport returned data to its client that was marked as expedited by the remote system.")

    # (0x000002C5) {Partial Expedited Data Received} The network transport returned partial data to its client and this data was marked as expedited by the remote system. The remaining data will be sent later.
    ERROR_RECEIVE_PARTIAL_EXPEDITED = WindowsError::ErrorCode.new("ERROR_RECEIVE_PARTIAL_EXPEDITED",0x000002C5,"{Partial Expedited Data Received} The network transport returned partial data to its client and this data was marked as expedited by the remote system. The remaining data will be sent later.")

    # (0x000002C6) {TDI Event Done} The TDI indication has completed successfully.
    ERROR_EVENT_DONE = WindowsError::ErrorCode.new("ERROR_EVENT_DONE",0x000002C6,"{TDI Event Done} The TDI indication has completed successfully.")

    # (0x000002C7) {TDI Event Pending} The TDI indication has entered the pending state.
    ERROR_EVENT_PENDING = WindowsError::ErrorCode.new("ERROR_EVENT_PENDING",0x000002C7,"{TDI Event Pending} The TDI indication has entered the pending state.")

    # (0x000002C8) Checking file system on %wZ.
    ERROR_CHECKING_FILE_SYSTEM = WindowsError::ErrorCode.new("ERROR_CHECKING_FILE_SYSTEM",0x000002C8,"Checking file system on %wZ.")

    # (0x000002C9) {Fatal Application Exit} %hs.
    ERROR_FATAL_APP_EXIT = WindowsError::ErrorCode.new("ERROR_FATAL_APP_EXIT",0x000002C9,"{Fatal Application Exit} %hs.")

    # (0x000002CA) The specified registry key is referenced by a predefined handle.
    ERROR_PREDEFINED_HANDLE = WindowsError::ErrorCode.new("ERROR_PREDEFINED_HANDLE",0x000002CA,"The specified registry key is referenced by a predefined handle.")

    # (0x000002CB) {Page Unlocked} The page protection of a locked page was changed to 'No Access' and the page was unlocked from memory and from the process.
    ERROR_WAS_UNLOCKED = WindowsError::ErrorCode.new("ERROR_WAS_UNLOCKED",0x000002CB,"{Page Unlocked} The page protection of a locked page was changed to 'No Access' and the page was unlocked from memory and from the process.")

    # (0x000002CD) {Page Locked} One of the pages to lock was already locked.
    ERROR_WAS_LOCKED = WindowsError::ErrorCode.new("ERROR_WAS_LOCKED",0x000002CD,"{Page Locked} One of the pages to lock was already locked.")

    # (0x000002CF) The value already corresponds with a Win 32 error code.
    ERROR_ALREADY_WIN32 = WindowsError::ErrorCode.new("ERROR_ALREADY_WIN32",0x000002CF,"The value already corresponds with a Win 32 error code.")

    # (0x000002D0) {Machine Type Mismatch} The image file %hs is valid, but is for a machine type other than the current machine.
    ERROR_IMAGE_MACHINE_TYPE_MISMATCH_EXE = WindowsError::ErrorCode.new("ERROR_IMAGE_MACHINE_TYPE_MISMATCH_EXE",0x000002D0,"{Machine Type Mismatch} The image file %hs is valid, but is for a machine type other than the current machine.")

    # (0x000002D1) A yield execution was performed and no thread was available to run.
    ERROR_NO_YIELD_PERFORMED = WindowsError::ErrorCode.new("ERROR_NO_YIELD_PERFORMED",0x000002D1,"A yield execution was performed and no thread was available to run.")

    # (0x000002D2) The resume flag to a timer API was ignored.
    ERROR_TIMER_RESUME_IGNORED = WindowsError::ErrorCode.new("ERROR_TIMER_RESUME_IGNORED",0x000002D2,"The resume flag to a timer API was ignored.")

    # (0x000002D3) The arbiter has deferred arbitration of these resources to its parent.
    ERROR_ARBITRATION_UNHANDLED = WindowsError::ErrorCode.new("ERROR_ARBITRATION_UNHANDLED",0x000002D3,"The arbiter has deferred arbitration of these resources to its parent.")

    # (0x000002D4) The inserted CardBus device cannot be started because of a configuration error on %hs"."
    ERROR_CARDBUS_NOT_SUPPORTED = WindowsError::ErrorCode.new("ERROR_CARDBUS_NOT_SUPPORTED",0x000002D4,"The inserted CardBus device cannot be started because of a configuration error on %hs\".\"")

    # (0x000002D5) The CPUs in this multiprocessor system are not all the same revision level. To use all processors the operating system restricts itself to the features of the least capable processor in the system. If problems occur with this system, contact the CPU manufacturer to see if this mix of processors is supported.
    ERROR_MP_PROCESSOR_MISMATCH = WindowsError::ErrorCode.new("ERROR_MP_PROCESSOR_MISMATCH",0x000002D5,"The CPUs in this multiprocessor system are not all the same revision level. To use all processors the operating system restricts itself to the features of the least capable processor in the system. If problems occur with this system, contact the CPU manufacturer to see if this mix of processors is supported.")

    # (0x000002D6) The system was put into hibernation.
    ERROR_HIBERNATED = WindowsError::ErrorCode.new("ERROR_HIBERNATED",0x000002D6,"The system was put into hibernation.")

    # (0x000002D7) The system was resumed from hibernation.
    ERROR_RESUME_HIBERNATION = WindowsError::ErrorCode.new("ERROR_RESUME_HIBERNATION",0x000002D7,"The system was resumed from hibernation.")

    # (0x000002D8) Windows has detected that the system firmware (BIOS) was updated (previous firmware date = %2, current firmware date %3).
    ERROR_FIRMWARE_UPDATED = WindowsError::ErrorCode.new("ERROR_FIRMWARE_UPDATED",0x000002D8,"Windows has detected that the system firmware (BIOS) was updated (previous firmware date = %2, current firmware date %3).")

    # (0x000002D9) A device driver is leaking locked I/O pages, causing system degradation. The system has automatically enabled a tracking code to try and catch the culprit.
    ERROR_DRIVERS_LEAKING_LOCKED_PAGES = WindowsError::ErrorCode.new("ERROR_DRIVERS_LEAKING_LOCKED_PAGES",0x000002D9,"A device driver is leaking locked I/O pages, causing system degradation. The system has automatically enabled a tracking code to try and catch the culprit.")

    # (0x000002DA) The system has awoken.
    ERROR_WAKE_SYSTEM = WindowsError::ErrorCode.new("ERROR_WAKE_SYSTEM",0x000002DA,"The system has awoken.")

    # (0x000002DF) The call failed because the handle associated with it was closed.
    ERROR_ABANDONED_WAIT_0 = WindowsError::ErrorCode.new("ERROR_ABANDONED_WAIT_0",0x000002DF,"The call failed because the handle associated with it was closed.")

    # (0x000002E4) The requested operation requires elevation.
    ERROR_ELEVATION_REQUIRED = WindowsError::ErrorCode.new("ERROR_ELEVATION_REQUIRED",0x000002E4,"The requested operation requires elevation.")

    # (0x000002E5) A reparse should be performed by the object manager because the name of the file resulted in a symbolic link.
    ERROR_REPARSE = WindowsError::ErrorCode.new("ERROR_REPARSE",0x000002E5,"A reparse should be performed by the object manager because the name of the file resulted in a symbolic link.")

    # (0x000002E6) An open/create operation completed while an oplock break is underway.
    ERROR_OPLOCK_BREAK_IN_PROGRESS = WindowsError::ErrorCode.new("ERROR_OPLOCK_BREAK_IN_PROGRESS",0x000002E6,"An open/create operation completed while an oplock break is underway.")

    # (0x000002E7) A new volume has been mounted by a file system.
    ERROR_VOLUME_MOUNTED = WindowsError::ErrorCode.new("ERROR_VOLUME_MOUNTED",0x000002E7,"A new volume has been mounted by a file system.")

    # (0x000002E8) This success level status indicates that the transaction state already exists for the registry subtree, but that a transaction commit was previously aborted. The commit has now been completed.
    ERROR_RXACT_COMMITTED = WindowsError::ErrorCode.new("ERROR_RXACT_COMMITTED",0x000002E8,"This success level status indicates that the transaction state already exists for the registry subtree, but that a transaction commit was previously aborted. The commit has now been completed.")

    # (0x000002E9) This indicates that a notify change request has been completed due to closing the handle which made the notify change request.
    ERROR_NOTIFY_CLEANUP = WindowsError::ErrorCode.new("ERROR_NOTIFY_CLEANUP",0x000002E9,"This indicates that a notify change request has been completed due to closing the handle which made the notify change request.")

    # (0x000002EA) {Connect Failure on Primary Transport} An attempt was made to connect to the remote server %hs on the primary transport, but the connection failed. The computer was able to connect on a secondary transport.
    ERROR_PRIMARY_TRANSPORT_CONNECT_FAILED = WindowsError::ErrorCode.new("ERROR_PRIMARY_TRANSPORT_CONNECT_FAILED",0x000002EA,"{Connect Failure on Primary Transport} An attempt was made to connect to the remote server %hs on the primary transport, but the connection failed. The computer was able to connect on a secondary transport.")

    # (0x000002EB) Page fault was a transition fault.
    ERROR_PAGE_FAULT_TRANSITION = WindowsError::ErrorCode.new("ERROR_PAGE_FAULT_TRANSITION",0x000002EB,"Page fault was a transition fault.")

    # (0x000002EC) Page fault was a demand zero fault.
    ERROR_PAGE_FAULT_DEMAND_ZERO = WindowsError::ErrorCode.new("ERROR_PAGE_FAULT_DEMAND_ZERO",0x000002EC,"Page fault was a demand zero fault.")

    # (0x000002ED) Page fault was a demand zero fault.
    ERROR_PAGE_FAULT_COPY_ON_WRITE = WindowsError::ErrorCode.new("ERROR_PAGE_FAULT_COPY_ON_WRITE",0x000002ED,"Page fault was a demand zero fault.")

    # (0x000002EE) Page fault was a demand zero fault.
    ERROR_PAGE_FAULT_GUARD_PAGE = WindowsError::ErrorCode.new("ERROR_PAGE_FAULT_GUARD_PAGE",0x000002EE,"Page fault was a demand zero fault.")

    # (0x000002EF) Page fault was satisfied by reading from a secondary storage device.
    ERROR_PAGE_FAULT_PAGING_FILE = WindowsError::ErrorCode.new("ERROR_PAGE_FAULT_PAGING_FILE",0x000002EF,"Page fault was satisfied by reading from a secondary storage device.")

    # (0x000002F0) Cached page was locked during operation.
    ERROR_CACHE_PAGE_LOCKED = WindowsError::ErrorCode.new("ERROR_CACHE_PAGE_LOCKED",0x000002F0,"Cached page was locked during operation.")

    # (0x000002F1) Crash dump exists in paging file.
    ERROR_CRASH_DUMP = WindowsError::ErrorCode.new("ERROR_CRASH_DUMP",0x000002F1,"Crash dump exists in paging file.")

    # (0x000002F2) Specified buffer contains all zeros.
    ERROR_BUFFER_ALL_ZEROS = WindowsError::ErrorCode.new("ERROR_BUFFER_ALL_ZEROS",0x000002F2,"Specified buffer contains all zeros.")

    # (0x000002F3) A reparse should be performed by the object manager because the name of the file resulted in a symbolic link.
    ERROR_REPARSE_OBJECT = WindowsError::ErrorCode.new("ERROR_REPARSE_OBJECT",0x000002F3,"A reparse should be performed by the object manager because the name of the file resulted in a symbolic link.")

    # (0x000002F4) The device has succeeded a query-stop and its resource requirements have changed.
    ERROR_RESOURCE_REQUIREMENTS_CHANGED = WindowsError::ErrorCode.new("ERROR_RESOURCE_REQUIREMENTS_CHANGED",0x000002F4,"The device has succeeded a query-stop and its resource requirements have changed.")

    # (0x000002F5) The translator has translated these resources into the global space and no further translations should be performed.
    ERROR_TRANSLATION_COMPLETE = WindowsError::ErrorCode.new("ERROR_TRANSLATION_COMPLETE",0x000002F5,"The translator has translated these resources into the global space and no further translations should be performed.")

    # (0x000002F6) A process being terminated has no threads to terminate.
    ERROR_NOTHING_TO_TERMINATE = WindowsError::ErrorCode.new("ERROR_NOTHING_TO_TERMINATE",0x000002F6,"A process being terminated has no threads to terminate.")

    # (0x000002F7) The specified process is not part of a job.
    ERROR_PROCESS_NOT_IN_JOB = WindowsError::ErrorCode.new("ERROR_PROCESS_NOT_IN_JOB",0x000002F7,"The specified process is not part of a job.")

    # (0x000002F8) The specified process is part of a job.
    ERROR_PROCESS_IN_JOB = WindowsError::ErrorCode.new("ERROR_PROCESS_IN_JOB",0x000002F8,"The specified process is part of a job.")

    # (0x000002F9) {Volume Shadow Copy Service} The system is now ready for hibernation.
    ERROR_VOLSNAP_HIBERNATE_READY = WindowsError::ErrorCode.new("ERROR_VOLSNAP_HIBERNATE_READY",0x000002F9,"{Volume Shadow Copy Service} The system is now ready for hibernation.")

    # (0x000002FA) A file system or file system filter driver has successfully completed an FsFilter operation.
    ERROR_FSFILTER_OP_COMPLETED_SUCCESSFULLY = WindowsError::ErrorCode.new("ERROR_FSFILTER_OP_COMPLETED_SUCCESSFULLY",0x000002FA,"A file system or file system filter driver has successfully completed an FsFilter operation.")

    # (0x000002FB) The specified interrupt vector was already connected.
    ERROR_INTERRUPT_VECTOR_ALREADY_CONNECTED = WindowsError::ErrorCode.new("ERROR_INTERRUPT_VECTOR_ALREADY_CONNECTED",0x000002FB,"The specified interrupt vector was already connected.")

    # (0x000002FC) The specified interrupt vector is still connected.
    ERROR_INTERRUPT_STILL_CONNECTED = WindowsError::ErrorCode.new("ERROR_INTERRUPT_STILL_CONNECTED",0x000002FC,"The specified interrupt vector is still connected.")

    # (0x000002FD) An operation is blocked waiting for an oplock.
    ERROR_WAIT_FOR_OPLOCK = WindowsError::ErrorCode.new("ERROR_WAIT_FOR_OPLOCK",0x000002FD,"An operation is blocked waiting for an oplock.")

    # (0x000002FE) Debugger handled exception.
    ERROR_DBG_EXCEPTION_HANDLED = WindowsError::ErrorCode.new("ERROR_DBG_EXCEPTION_HANDLED",0x000002FE,"Debugger handled exception.")

    # (0x000002FF) Debugger continued.
    ERROR_DBG_CONTINUE = WindowsError::ErrorCode.new("ERROR_DBG_CONTINUE",0x000002FF,"Debugger continued.")

    # (0x00000300) An exception occurred in a user mode callback and the kernel callback frame should be removed.
    ERROR_CALLBACK_POP_STACK = WindowsError::ErrorCode.new("ERROR_CALLBACK_POP_STACK",0x00000300,"An exception occurred in a user mode callback and the kernel callback frame should be removed.")

    # (0x00000301) Compression is disabled for this volume.
    ERROR_COMPRESSION_DISABLED = WindowsError::ErrorCode.new("ERROR_COMPRESSION_DISABLED",0x00000301,"Compression is disabled for this volume.")

    # (0x00000302) The data provider cannot fetch backward through a result set.
    ERROR_CANTFETCHBACKWARDS = WindowsError::ErrorCode.new("ERROR_CANTFETCHBACKWARDS",0x00000302,"The data provider cannot fetch backward through a result set.")

    # (0x00000303) The data provider cannot scroll backward through a result set.
    ERROR_CANTSCROLLBACKWARDS = WindowsError::ErrorCode.new("ERROR_CANTSCROLLBACKWARDS",0x00000303,"The data provider cannot scroll backward through a result set.")

    # (0x00000304) The data provider requires that previously fetched data is released before asking for more data.
    ERROR_ROWSNOTRELEASED = WindowsError::ErrorCode.new("ERROR_ROWSNOTRELEASED",0x00000304,"The data provider requires that previously fetched data is released before asking for more data.")

    # (0x00000305) The data provider was not able to interpret the flags set for a column binding in an accessor.
    ERROR_BAD_ACCESSOR_FLAGS = WindowsError::ErrorCode.new("ERROR_BAD_ACCESSOR_FLAGS",0x00000305,"The data provider was not able to interpret the flags set for a column binding in an accessor.")

    # (0x00000306) One or more errors occurred while processing the request.
    ERROR_ERRORS_ENCOUNTERED = WindowsError::ErrorCode.new("ERROR_ERRORS_ENCOUNTERED",0x00000306,"One or more errors occurred while processing the request.")

    # (0x00000307) The implementation is not capable of performing the request.
    ERROR_NOT_CAPABLE = WindowsError::ErrorCode.new("ERROR_NOT_CAPABLE",0x00000307,"The implementation is not capable of performing the request.")

    # (0x00000308) The client of a component requested an operation that is not valid given the state of the component instance.
    ERROR_REQUEST_OUT_OF_SEQUENCE = WindowsError::ErrorCode.new("ERROR_REQUEST_OUT_OF_SEQUENCE",0x00000308,"The client of a component requested an operation that is not valid given the state of the component instance.")

    # (0x00000309) A version number could not be parsed.
    ERROR_VERSION_PARSE_ERROR = WindowsError::ErrorCode.new("ERROR_VERSION_PARSE_ERROR",0x00000309,"A version number could not be parsed.")

    # (0x0000030A) The iterator's start position is invalid.
    ERROR_BADSTARTPOSITION = WindowsError::ErrorCode.new("ERROR_BADSTARTPOSITION",0x0000030A,"The iterator's start position is invalid.")

    # (0x0000030B) The hardware has reported an uncorrectable memory error.
    ERROR_MEMORY_HARDWARE = WindowsError::ErrorCode.new("ERROR_MEMORY_HARDWARE",0x0000030B,"The hardware has reported an uncorrectable memory error.")

    # (0x0000030C) The attempted operation required self-healing to be enabled.
    ERROR_DISK_REPAIR_DISABLED = WindowsError::ErrorCode.new("ERROR_DISK_REPAIR_DISABLED",0x0000030C,"The attempted operation required self-healing to be enabled.")

    # (0x0000030D) The Desktop heap encountered an error while allocating session memory. There is more information in the system event log.
    ERROR_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE = WindowsError::ErrorCode.new("ERROR_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE",0x0000030D,"The Desktop heap encountered an error while allocating session memory. There is more information in the system event log.")

    # (0x0000030E) The system power state is transitioning from %2 to %3.
    ERROR_SYSTEM_POWERSTATE_TRANSITION = WindowsError::ErrorCode.new("ERROR_SYSTEM_POWERSTATE_TRANSITION",0x0000030E,"The system power state is transitioning from %2 to %3.")

    # (0x0000030F) The system power state is transitioning from %2 to %3 but could enter %4.
    ERROR_SYSTEM_POWERSTATE_COMPLEX_TRANSITION = WindowsError::ErrorCode.new("ERROR_SYSTEM_POWERSTATE_COMPLEX_TRANSITION",0x0000030F,"The system power state is transitioning from %2 to %3 but could enter %4.")

    # (0x00000310) A thread is getting dispatched with MCA EXCEPTION because of MCA.
    ERROR_MCA_EXCEPTION = WindowsError::ErrorCode.new("ERROR_MCA_EXCEPTION",0x00000310,"A thread is getting dispatched with MCA EXCEPTION because of MCA.")

    # (0x00000311) Access to %1 is monitored by policy rule %2.
    ERROR_ACCESS_AUDIT_BY_POLICY = WindowsError::ErrorCode.new("ERROR_ACCESS_AUDIT_BY_POLICY",0x00000311,"Access to %1 is monitored by policy rule %2.")

    # (0x00000312) Access to %1 has been restricted by your administrator by policy rule %2.
    ERROR_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY = WindowsError::ErrorCode.new("ERROR_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY",0x00000312,"Access to %1 has been restricted by your administrator by policy rule %2.")

    # (0x00000313) A valid hibernation file has been invalidated and should be abandoned.
    ERROR_ABANDON_HIBERFILE = WindowsError::ErrorCode.new("ERROR_ABANDON_HIBERFILE",0x00000313,"A valid hibernation file has been invalidated and should be abandoned.")

    # (0x00000314) {Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error may be caused by network connectivity issues. Try to save this file elsewhere.
    ERROR_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED = WindowsError::ErrorCode.new("ERROR_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED",0x00000314,"{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error may be caused by network connectivity issues. Try to save this file elsewhere.")

    # (0x00000315) {Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error was returned by the server on which the file exists. Try to save this file elsewhere.
    ERROR_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR = WindowsError::ErrorCode.new("ERROR_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR",0x00000315,"{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error was returned by the server on which the file exists. Try to save this file elsewhere.")

    # (0x00000316) {Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error may be caused if the device has been removed or the media is write-protected.
    ERROR_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR = WindowsError::ErrorCode.new("ERROR_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR",0x00000316,"{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error may be caused if the device has been removed or the media is write-protected.")

    # (0x000003E2) Access to the extended attribute was denied.
    ERROR_EA_ACCESS_DENIED = WindowsError::ErrorCode.new("ERROR_EA_ACCESS_DENIED",0x000003E2,"Access to the extended attribute was denied.")

    # (0x000003E3) The I/O operation has been aborted because of either a thread exit or an application request.
    ERROR_OPERATION_ABORTED = WindowsError::ErrorCode.new("ERROR_OPERATION_ABORTED",0x000003E3,"The I/O operation has been aborted because of either a thread exit or an application request.")

    # (0x000003E4) Overlapped I/O event is not in a signaled state.
    ERROR_IO_INCOMPLETE = WindowsError::ErrorCode.new("ERROR_IO_INCOMPLETE",0x000003E4,"Overlapped I/O event is not in a signaled state.")

    # (0x000003E5) Overlapped I/O operation is in progress.
    ERROR_IO_PENDING = WindowsError::ErrorCode.new("ERROR_IO_PENDING",0x000003E5,"Overlapped I/O operation is in progress.")

    # (0x000003E6) Invalid access to memory location.
    ERROR_NOACCESS = WindowsError::ErrorCode.new("ERROR_NOACCESS",0x000003E6,"Invalid access to memory location.")

    # (0x000003E7) Error performing in-page operation.
    ERROR_SWAPERROR = WindowsError::ErrorCode.new("ERROR_SWAPERROR",0x000003E7,"Error performing in-page operation.")

    # (0x000003E9) Recursion too deep; the stack overflowed.
    ERROR_STACK_OVERFLOW = WindowsError::ErrorCode.new("ERROR_STACK_OVERFLOW",0x000003E9,"Recursion too deep; the stack overflowed.")

    # (0x000003EA) The window cannot act on the sent message.
    ERROR_INVALID_MESSAGE = WindowsError::ErrorCode.new("ERROR_INVALID_MESSAGE",0x000003EA,"The window cannot act on the sent message.")

    # (0x000003EB) Cannot complete this function.
    ERROR_CAN_NOT_COMPLETE = WindowsError::ErrorCode.new("ERROR_CAN_NOT_COMPLETE",0x000003EB,"Cannot complete this function.")

    # (0x000003EC) Invalid flags.
    ERROR_INVALID_FLAGS = WindowsError::ErrorCode.new("ERROR_INVALID_FLAGS",0x000003EC,"Invalid flags.")

    # (0x000003ED) The volume does not contain a recognized file system. Be sure that all required file system drivers are loaded and that the volume is not corrupted.
    ERROR_UNRECOGNIZED_VOLUME = WindowsError::ErrorCode.new("ERROR_UNRECOGNIZED_VOLUME",0x000003ED,"The volume does not contain a recognized file system. Be sure that all required file system drivers are loaded and that the volume is not corrupted.")

    # (0x000003EE) The volume for a file has been externally altered so that the opened file is no longer valid.
    ERROR_FILE_INVALID = WindowsError::ErrorCode.new("ERROR_FILE_INVALID",0x000003EE,"The volume for a file has been externally altered so that the opened file is no longer valid.")

    # (0x000003EF) The requested operation cannot be performed in full-screen mode.
    ERROR_FULLSCREEN_MODE = WindowsError::ErrorCode.new("ERROR_FULLSCREEN_MODE",0x000003EF,"The requested operation cannot be performed in full-screen mode.")

    # (0x000003F0) An attempt was made to reference a token that does not exist.
    ERROR_NO_TOKEN = WindowsError::ErrorCode.new("ERROR_NO_TOKEN",0x000003F0,"An attempt was made to reference a token that does not exist.")

    # (0x000003F1) The configuration registry database is corrupt.
    ERROR_BADDB = WindowsError::ErrorCode.new("ERROR_BADDB",0x000003F1,"The configuration registry database is corrupt.")

    # (0x000003F2) The configuration registry key is invalid.
    ERROR_BADKEY = WindowsError::ErrorCode.new("ERROR_BADKEY",0x000003F2,"The configuration registry key is invalid.")

    # (0x000003F3) The configuration registry key could not be opened.
    ERROR_CANTOPEN = WindowsError::ErrorCode.new("ERROR_CANTOPEN",0x000003F3,"The configuration registry key could not be opened.")

    # (0x000003F4) The configuration registry key could not be read.
    ERROR_CANTREAD = WindowsError::ErrorCode.new("ERROR_CANTREAD",0x000003F4,"The configuration registry key could not be read.")

    # (0x000003F5) The configuration registry key could not be written.
    ERROR_CANTWRITE = WindowsError::ErrorCode.new("ERROR_CANTWRITE",0x000003F5,"The configuration registry key could not be written.")

    # (0x000003F6) One of the files in the registry database had to be recovered by use of a log or alternate copy. The recovery was successful.
    ERROR_REGISTRY_RECOVERED = WindowsError::ErrorCode.new("ERROR_REGISTRY_RECOVERED",0x000003F6,"One of the files in the registry database had to be recovered by use of a log or alternate copy. The recovery was successful.")

    # (0x000003F7) The registry is corrupted. The structure of one of the files containing registry data is corrupted, or the system's memory image of the file is corrupted, or the file could not be recovered because the alternate copy or log was absent or corrupted.
    ERROR_REGISTRY_CORRUPT = WindowsError::ErrorCode.new("ERROR_REGISTRY_CORRUPT",0x000003F7,"The registry is corrupted. The structure of one of the files containing registry data is corrupted, or the system's memory image of the file is corrupted, or the file could not be recovered because the alternate copy or log was absent or corrupted.")

    # (0x000003F8) An I/O operation initiated by the registry failed and cannot be recovered. The registry could not read in, write out, or flush one of the files that contain the system's image of the registry.
    ERROR_REGISTRY_IO_FAILED = WindowsError::ErrorCode.new("ERROR_REGISTRY_IO_FAILED",0x000003F8,"An I/O operation initiated by the registry failed and cannot be recovered. The registry could not read in, write out, or flush one of the files that contain the system's image of the registry.")

    # (0x000003F9) The system attempted to load or restore a file into the registry, but the specified file is not in a registry file format.
    ERROR_NOT_REGISTRY_FILE = WindowsError::ErrorCode.new("ERROR_NOT_REGISTRY_FILE",0x000003F9,"The system attempted to load or restore a file into the registry, but the specified file is not in a registry file format.")

    # (0x000003FA) Illegal operation attempted on a registry key that has been marked for deletion.
    ERROR_KEY_DELETED = WindowsError::ErrorCode.new("ERROR_KEY_DELETED",0x000003FA,"Illegal operation attempted on a registry key that has been marked for deletion.")

    # (0x000003FB) System could not allocate the required space in a registry log.
    ERROR_NO_LOG_SPACE = WindowsError::ErrorCode.new("ERROR_NO_LOG_SPACE",0x000003FB,"System could not allocate the required space in a registry log.")

    # (0x000003FC) Cannot create a symbolic link in a registry key that already has subkeys or values.
    ERROR_KEY_HAS_CHILDREN = WindowsError::ErrorCode.new("ERROR_KEY_HAS_CHILDREN",0x000003FC,"Cannot create a symbolic link in a registry key that already has subkeys or values.")

    # (0x000003FD) Cannot create a stable subkey under a volatile parent key.
    ERROR_CHILD_MUST_BE_VOLATILE = WindowsError::ErrorCode.new("ERROR_CHILD_MUST_BE_VOLATILE",0x000003FD,"Cannot create a stable subkey under a volatile parent key.")

    # (0x000003FE) A notify change request is being completed and the information is not being returned in the caller's buffer. The caller now needs to enumerate the files to find the changes.
    ERROR_NOTIFY_ENUM_DIR = WindowsError::ErrorCode.new("ERROR_NOTIFY_ENUM_DIR",0x000003FE,"A notify change request is being completed and the information is not being returned in the caller's buffer. The caller now needs to enumerate the files to find the changes.")

    # (0x0000041B) A stop control has been sent to a service that other running services are dependent on.
    ERROR_DEPENDENT_SERVICES_RUNNING = WindowsError::ErrorCode.new("ERROR_DEPENDENT_SERVICES_RUNNING",0x0000041B,"A stop control has been sent to a service that other running services are dependent on.")

    # (0x0000041C) The requested control is not valid for this service.
    ERROR_INVALID_SERVICE_CONTROL = WindowsError::ErrorCode.new("ERROR_INVALID_SERVICE_CONTROL",0x0000041C,"The requested control is not valid for this service.")

    # (0x0000041D) The service did not respond to the start or control request in a timely fashion.
    ERROR_SERVICE_REQUEST_TIMEOUT = WindowsError::ErrorCode.new("ERROR_SERVICE_REQUEST_TIMEOUT",0x0000041D,"The service did not respond to the start or control request in a timely fashion.")

    # (0x0000041E) A thread could not be created for the service.
    ERROR_SERVICE_NO_THREAD = WindowsError::ErrorCode.new("ERROR_SERVICE_NO_THREAD",0x0000041E,"A thread could not be created for the service.")

    # (0x0000041F) The service database is locked.
    ERROR_SERVICE_DATABASE_LOCKED = WindowsError::ErrorCode.new("ERROR_SERVICE_DATABASE_LOCKED",0x0000041F,"The service database is locked.")

    # (0x00000420) An instance of the service is already running.
    ERROR_SERVICE_ALREADY_RUNNING = WindowsError::ErrorCode.new("ERROR_SERVICE_ALREADY_RUNNING",0x00000420,"An instance of the service is already running.")

    # (0x00000421) The account name is invalid or does not exist, or the password is invalid for the account name specified.
    ERROR_INVALID_SERVICE_ACCOUNT = WindowsError::ErrorCode.new("ERROR_INVALID_SERVICE_ACCOUNT",0x00000421,"The account name is invalid or does not exist, or the password is invalid for the account name specified.")

    # (0x00000422) The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.
    ERROR_SERVICE_DISABLED = WindowsError::ErrorCode.new("ERROR_SERVICE_DISABLED",0x00000422,"The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.")

    # (0x00000423) Circular service dependency was specified.
    ERROR_CIRCULAR_DEPENDENCY = WindowsError::ErrorCode.new("ERROR_CIRCULAR_DEPENDENCY",0x00000423,"Circular service dependency was specified.")

    # (0x00000424) The specified service does not exist as an installed service.
    ERROR_SERVICE_DOES_NOT_EXIST = WindowsError::ErrorCode.new("ERROR_SERVICE_DOES_NOT_EXIST",0x00000424,"The specified service does not exist as an installed service.")

    # (0x00000425) The service cannot accept control messages at this time.
    ERROR_SERVICE_CANNOT_ACCEPT_CTRL = WindowsError::ErrorCode.new("ERROR_SERVICE_CANNOT_ACCEPT_CTRL",0x00000425,"The service cannot accept control messages at this time.")

    # (0x00000426) The service has not been started.
    ERROR_SERVICE_NOT_ACTIVE = WindowsError::ErrorCode.new("ERROR_SERVICE_NOT_ACTIVE",0x00000426,"The service has not been started.")

    # (0x00000427) The service process could not connect to the service controller.
    ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = WindowsError::ErrorCode.new("ERROR_FAILED_SERVICE_CONTROLLER_CONNECT",0x00000427,"The service process could not connect to the service controller.")

    # (0x00000428) An exception occurred in the service when handling the control request.
    ERROR_EXCEPTION_IN_SERVICE = WindowsError::ErrorCode.new("ERROR_EXCEPTION_IN_SERVICE",0x00000428,"An exception occurred in the service when handling the control request.")

    # (0x00000429) The database specified does not exist.
    ERROR_DATABASE_DOES_NOT_EXIST = WindowsError::ErrorCode.new("ERROR_DATABASE_DOES_NOT_EXIST",0x00000429,"The database specified does not exist.")

    # (0x0000042A) The service has returned a service-specific error code.
    ERROR_SERVICE_SPECIFIC_ERROR = WindowsError::ErrorCode.new("ERROR_SERVICE_SPECIFIC_ERROR",0x0000042A,"The service has returned a service-specific error code.")

    # (0x0000042B) The process terminated unexpectedly.
    ERROR_PROCESS_ABORTED = WindowsError::ErrorCode.new("ERROR_PROCESS_ABORTED",0x0000042B,"The process terminated unexpectedly.")

    # (0x0000042C) The dependency service or group failed to start.
    ERROR_SERVICE_DEPENDENCY_FAIL = WindowsError::ErrorCode.new("ERROR_SERVICE_DEPENDENCY_FAIL",0x0000042C,"The dependency service or group failed to start.")

    # (0x0000042D) The service did not start due to a logon failure.
    ERROR_SERVICE_LOGON_FAILED = WindowsError::ErrorCode.new("ERROR_SERVICE_LOGON_FAILED",0x0000042D,"The service did not start due to a logon failure.")

    # (0x0000042E) After starting, the service hung in a start-pending state.
    ERROR_SERVICE_START_HANG = WindowsError::ErrorCode.new("ERROR_SERVICE_START_HANG",0x0000042E,"After starting, the service hung in a start-pending state.")

    # (0x0000042F) The specified service database lock is invalid.
    ERROR_INVALID_SERVICE_LOCK = WindowsError::ErrorCode.new("ERROR_INVALID_SERVICE_LOCK",0x0000042F,"The specified service database lock is invalid.")

    # (0x00000430) The specified service has been marked for deletion.
    ERROR_SERVICE_MARKED_FOR_DELETE = WindowsError::ErrorCode.new("ERROR_SERVICE_MARKED_FOR_DELETE",0x00000430,"The specified service has been marked for deletion.")

    # (0x00000431) The specified service already exists.
    ERROR_SERVICE_EXISTS = WindowsError::ErrorCode.new("ERROR_SERVICE_EXISTS",0x00000431,"The specified service already exists.")

    # (0x00000432) The system is currently running with the last-known-good configuration.
    ERROR_ALREADY_RUNNING_LKG = WindowsError::ErrorCode.new("ERROR_ALREADY_RUNNING_LKG",0x00000432,"The system is currently running with the last-known-good configuration.")

    # (0x00000433) The dependency service does not exist or has been marked for deletion.
    ERROR_SERVICE_DEPENDENCY_DELETED = WindowsError::ErrorCode.new("ERROR_SERVICE_DEPENDENCY_DELETED",0x00000433,"The dependency service does not exist or has been marked for deletion.")

    # (0x00000434) The current boot has already been accepted for use as the last-known-good control set.
    ERROR_BOOT_ALREADY_ACCEPTED = WindowsError::ErrorCode.new("ERROR_BOOT_ALREADY_ACCEPTED",0x00000434,"The current boot has already been accepted for use as the last-known-good control set.")

    # (0x00000435) No attempts to start the service have been made since the last boot.
    ERROR_SERVICE_NEVER_STARTED = WindowsError::ErrorCode.new("ERROR_SERVICE_NEVER_STARTED",0x00000435,"No attempts to start the service have been made since the last boot.")

    # (0x00000436) The name is already in use as either a service name or a service display name.
    ERROR_DUPLICATE_SERVICE_NAME = WindowsError::ErrorCode.new("ERROR_DUPLICATE_SERVICE_NAME",0x00000436,"The name is already in use as either a service name or a service display name.")

    # (0x00000437) The account specified for this service is different from the account specified for other services running in the same process.
    ERROR_DIFFERENT_SERVICE_ACCOUNT = WindowsError::ErrorCode.new("ERROR_DIFFERENT_SERVICE_ACCOUNT",0x00000437,"The account specified for this service is different from the account specified for other services running in the same process.")

    # (0x00000438) Failure actions can only be set for Win32 services, not for drivers.
    ERROR_CANNOT_DETECT_DRIVER_FAILURE = WindowsError::ErrorCode.new("ERROR_CANNOT_DETECT_DRIVER_FAILURE",0x00000438,"Failure actions can only be set for Win32 services, not for drivers.")

    # (0x00000439) This service runs in the same process as the service control manager. Therefore, the service control manager cannot take action if this service's process terminates unexpectedly.
    ERROR_CANNOT_DETECT_PROCESS_ABORT = WindowsError::ErrorCode.new("ERROR_CANNOT_DETECT_PROCESS_ABORT",0x00000439,"This service runs in the same process as the service control manager. Therefore, the service control manager cannot take action if this service's process terminates unexpectedly.")

    # (0x0000043A) No recovery program has been configured for this service.
    ERROR_NO_RECOVERY_PROGRAM = WindowsError::ErrorCode.new("ERROR_NO_RECOVERY_PROGRAM",0x0000043A,"No recovery program has been configured for this service.")

    # (0x0000043B) The executable program that this service is configured to run in does not implement the service.
    ERROR_SERVICE_NOT_IN_EXE = WindowsError::ErrorCode.new("ERROR_SERVICE_NOT_IN_EXE",0x0000043B,"The executable program that this service is configured to run in does not implement the service.")

    # (0x0000043C) This service cannot be started in Safe Mode.
    ERROR_NOT_SAFEBOOT_SERVICE = WindowsError::ErrorCode.new("ERROR_NOT_SAFEBOOT_SERVICE",0x0000043C,"This service cannot be started in Safe Mode.")

    # (0x0000044C) The physical end of the tape has been reached.
    ERROR_END_OF_MEDIA = WindowsError::ErrorCode.new("ERROR_END_OF_MEDIA",0x0000044C,"The physical end of the tape has been reached.")

    # (0x0000044D) A tape access reached a filemark.
    ERROR_FILEMARK_DETECTED = WindowsError::ErrorCode.new("ERROR_FILEMARK_DETECTED",0x0000044D,"A tape access reached a filemark.")

    # (0x0000044E) The beginning of the tape or a partition was encountered.
    ERROR_BEGINNING_OF_MEDIA = WindowsError::ErrorCode.new("ERROR_BEGINNING_OF_MEDIA",0x0000044E,"The beginning of the tape or a partition was encountered.")

    # (0x0000044F) A tape access reached the end of a set of files.
    ERROR_SETMARK_DETECTED = WindowsError::ErrorCode.new("ERROR_SETMARK_DETECTED",0x0000044F,"A tape access reached the end of a set of files.")

    # (0x00000450) No more data is on the tape.
    ERROR_NO_DATA_DETECTED = WindowsError::ErrorCode.new("ERROR_NO_DATA_DETECTED",0x00000450,"No more data is on the tape.")

    # (0x00000451) Tape could not be partitioned.
    ERROR_PARTITION_FAILURE = WindowsError::ErrorCode.new("ERROR_PARTITION_FAILURE",0x00000451,"Tape could not be partitioned.")

    # (0x00000452) When accessing a new tape of a multivolume partition, the current block size is incorrect.
    ERROR_INVALID_BLOCK_LENGTH = WindowsError::ErrorCode.new("ERROR_INVALID_BLOCK_LENGTH",0x00000452,"When accessing a new tape of a multivolume partition, the current block size is incorrect.")

    # (0x00000453) Tape partition information could not be found when loading a tape.
    ERROR_DEVICE_NOT_PARTITIONED = WindowsError::ErrorCode.new("ERROR_DEVICE_NOT_PARTITIONED",0x00000453,"Tape partition information could not be found when loading a tape.")

    # (0x00000454) Unable to lock the media eject mechanism.
    ERROR_UNABLE_TO_LOCK_MEDIA = WindowsError::ErrorCode.new("ERROR_UNABLE_TO_LOCK_MEDIA",0x00000454,"Unable to lock the media eject mechanism.")

    # (0x00000455) Unable to unload the media.
    ERROR_UNABLE_TO_UNLOAD_MEDIA = WindowsError::ErrorCode.new("ERROR_UNABLE_TO_UNLOAD_MEDIA",0x00000455,"Unable to unload the media.")

    # (0x00000456) The media in the drive may have changed.
    ERROR_MEDIA_CHANGED = WindowsError::ErrorCode.new("ERROR_MEDIA_CHANGED",0x00000456,"The media in the drive may have changed.")

    # (0x00000457) The I/O bus was reset.
    ERROR_BUS_RESET = WindowsError::ErrorCode.new("ERROR_BUS_RESET",0x00000457,"The I/O bus was reset.")

    # (0x00000458) No media in drive.
    ERROR_NO_MEDIA_IN_DRIVE = WindowsError::ErrorCode.new("ERROR_NO_MEDIA_IN_DRIVE",0x00000458,"No media in drive.")

    # (0x00000459) No mapping for the Unicode character exists in the target multibyte code page.
    ERROR_NO_UNICODE_TRANSLATION = WindowsError::ErrorCode.new("ERROR_NO_UNICODE_TRANSLATION",0x00000459,"No mapping for the Unicode character exists in the target multibyte code page.")

    # (0x0000045A) A DLL initialization routine failed.
    ERROR_DLL_INIT_FAILED = WindowsError::ErrorCode.new("ERROR_DLL_INIT_FAILED",0x0000045A,"A DLL initialization routine failed.")

    # (0x0000045B) A system shutdown is in progress.
    ERROR_SHUTDOWN_IN_PROGRESS = WindowsError::ErrorCode.new("ERROR_SHUTDOWN_IN_PROGRESS",0x0000045B,"A system shutdown is in progress.")

    # (0x0000045C) Unable to abort the system shutdown because no shutdown was in progress.
    ERROR_NO_SHUTDOWN_IN_PROGRESS = WindowsError::ErrorCode.new("ERROR_NO_SHUTDOWN_IN_PROGRESS",0x0000045C,"Unable to abort the system shutdown because no shutdown was in progress.")

    # (0x0000045D) The request could not be performed because of an I/O device error.
    ERROR_IO_DEVICE = WindowsError::ErrorCode.new("ERROR_IO_DEVICE",0x0000045D,"The request could not be performed because of an I/O device error.")

    # (0x0000045E) No serial device was successfully initialized. The serial driver will unload.
    ERROR_SERIAL_NO_DEVICE = WindowsError::ErrorCode.new("ERROR_SERIAL_NO_DEVICE",0x0000045E,"No serial device was successfully initialized. The serial driver will unload.")

    # (0x0000045F) Unable to open a device that was sharing an IRQ with other devices. At least one other device that uses that IRQ was already opened.
    ERROR_IRQ_BUSY = WindowsError::ErrorCode.new("ERROR_IRQ_BUSY",0x0000045F,"Unable to open a device that was sharing an IRQ with other devices. At least one other device that uses that IRQ was already opened.")

    # (0x00000460) A serial I/O operation was completed by another write to the serial port. (The IOCTL_SERIAL_XOFF_COUNTER reached zero.)
    ERROR_MORE_WRITES = WindowsError::ErrorCode.new("ERROR_MORE_WRITES",0x00000460,"A serial I/O operation was completed by another write to the serial port. (The IOCTL_SERIAL_XOFF_COUNTER reached zero.)")

    # (0x00000461) A serial I/O operation completed because the time-out period expired. (The IOCTL_SERIAL_XOFF_COUNTER did not reach zero.)
    ERROR_COUNTER_TIMEOUT = WindowsError::ErrorCode.new("ERROR_COUNTER_TIMEOUT",0x00000461,"A serial I/O operation completed because the time-out period expired. (The IOCTL_SERIAL_XOFF_COUNTER did not reach zero.)")

    # (0x00000462) No ID address mark was found on the floppy disk.
    ERROR_FLOPPY_ID_MARK_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_FLOPPY_ID_MARK_NOT_FOUND",0x00000462,"No ID address mark was found on the floppy disk.")

    # (0x00000463) Mismatch between the floppy disk sector ID field and the floppy disk controller track address.
    ERROR_FLOPPY_WRONG_CYLINDER = WindowsError::ErrorCode.new("ERROR_FLOPPY_WRONG_CYLINDER",0x00000463,"Mismatch between the floppy disk sector ID field and the floppy disk controller track address.")

    # (0x00000464) The floppy disk controller reported an error that is not recognized by the floppy disk driver.
    ERROR_FLOPPY_UNKNOWN_ERROR = WindowsError::ErrorCode.new("ERROR_FLOPPY_UNKNOWN_ERROR",0x00000464,"The floppy disk controller reported an error that is not recognized by the floppy disk driver.")

    # (0x00000465) The floppy disk controller returned inconsistent results in its registers.
    ERROR_FLOPPY_BAD_REGISTERS = WindowsError::ErrorCode.new("ERROR_FLOPPY_BAD_REGISTERS",0x00000465,"The floppy disk controller returned inconsistent results in its registers.")

    # (0x00000466) While accessing the hard disk, a recalibrate operation failed, even after retries.
    ERROR_DISK_RECALIBRATE_FAILED = WindowsError::ErrorCode.new("ERROR_DISK_RECALIBRATE_FAILED",0x00000466,"While accessing the hard disk, a recalibrate operation failed, even after retries.")

    # (0x00000467) While accessing the hard disk, a disk operation failed even after retries.
    ERROR_DISK_OPERATION_FAILED = WindowsError::ErrorCode.new("ERROR_DISK_OPERATION_FAILED",0x00000467,"While accessing the hard disk, a disk operation failed even after retries.")

    # (0x00000468) While accessing the hard disk, a disk controller reset was needed, but that also failed.
    ERROR_DISK_RESET_FAILED = WindowsError::ErrorCode.new("ERROR_DISK_RESET_FAILED",0x00000468,"While accessing the hard disk, a disk controller reset was needed, but that also failed.")

    # (0x00000469) Physical end of tape encountered.
    ERROR_EOM_OVERFLOW = WindowsError::ErrorCode.new("ERROR_EOM_OVERFLOW",0x00000469,"Physical end of tape encountered.")

    # (0x0000046A) Not enough server storage is available to process this command.
    ERROR_NOT_ENOUGH_SERVER_MEMORY = WindowsError::ErrorCode.new("ERROR_NOT_ENOUGH_SERVER_MEMORY",0x0000046A,"Not enough server storage is available to process this command.")

    # (0x0000046B) A potential deadlock condition has been detected.
    ERROR_POSSIBLE_DEADLOCK = WindowsError::ErrorCode.new("ERROR_POSSIBLE_DEADLOCK",0x0000046B,"A potential deadlock condition has been detected.")

    # (0x0000046C) The base address or the file offset specified does not have the proper alignment.
    ERROR_MAPPED_ALIGNMENT = WindowsError::ErrorCode.new("ERROR_MAPPED_ALIGNMENT",0x0000046C,"The base address or the file offset specified does not have the proper alignment.")

    # (0x00000474) An attempt to change the system power state was vetoed by another application or driver.
    ERROR_SET_POWER_STATE_VETOED = WindowsError::ErrorCode.new("ERROR_SET_POWER_STATE_VETOED",0x00000474,"An attempt to change the system power state was vetoed by another application or driver.")

    # (0x00000475) The system BIOS failed an attempt to change the system power state.
    ERROR_SET_POWER_STATE_FAILED = WindowsError::ErrorCode.new("ERROR_SET_POWER_STATE_FAILED",0x00000475,"The system BIOS failed an attempt to change the system power state.")

    # (0x00000476) An attempt was made to create more links on a file than the file system supports.
    ERROR_TOO_MANY_LINKS = WindowsError::ErrorCode.new("ERROR_TOO_MANY_LINKS",0x00000476,"An attempt was made to create more links on a file than the file system supports.")

    # (0x0000047E) The specified program requires a newer version of Windows.
    ERROR_OLD_WIN_VERSION = WindowsError::ErrorCode.new("ERROR_OLD_WIN_VERSION",0x0000047E,"The specified program requires a newer version of Windows.")

    # (0x0000047F) The specified program is not a Windows or MS-DOS program.
    ERROR_APP_WRONG_OS = WindowsError::ErrorCode.new("ERROR_APP_WRONG_OS",0x0000047F,"The specified program is not a Windows or MS-DOS program.")

    # (0x00000480) Cannot start more than one instance of the specified program.
    ERROR_SINGLE_INSTANCE_APP = WindowsError::ErrorCode.new("ERROR_SINGLE_INSTANCE_APP",0x00000480,"Cannot start more than one instance of the specified program.")

    # (0x00000481) The specified program was written for an earlier version of Windows.
    ERROR_RMODE_APP = WindowsError::ErrorCode.new("ERROR_RMODE_APP",0x00000481,"The specified program was written for an earlier version of Windows.")

    # (0x00000482) One of the library files needed to run this application is damaged.
    ERROR_INVALID_DLL = WindowsError::ErrorCode.new("ERROR_INVALID_DLL",0x00000482,"One of the library files needed to run this application is damaged.")

    # (0x00000483) No application is associated with the specified file for this operation.
    ERROR_NO_ASSOCIATION = WindowsError::ErrorCode.new("ERROR_NO_ASSOCIATION",0x00000483,"No application is associated with the specified file for this operation.")

    # (0x00000484) An error occurred in sending the command to the application.
    ERROR_DDE_FAIL = WindowsError::ErrorCode.new("ERROR_DDE_FAIL",0x00000484,"An error occurred in sending the command to the application.")

    # (0x00000485) One of the library files needed to run this application cannot be found.
    ERROR_DLL_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_DLL_NOT_FOUND",0x00000485,"One of the library files needed to run this application cannot be found.")

    # (0x00000486) The current process has used all of its system allowance of handles for Windows manager objects.
    ERROR_NO_MORE_USER_HANDLES = WindowsError::ErrorCode.new("ERROR_NO_MORE_USER_HANDLES",0x00000486,"The current process has used all of its system allowance of handles for Windows manager objects.")

    # (0x00000487) The message can be used only with synchronous operations.
    ERROR_MESSAGE_SYNC_ONLY = WindowsError::ErrorCode.new("ERROR_MESSAGE_SYNC_ONLY",0x00000487,"The message can be used only with synchronous operations.")

    # (0x00000488) The indicated source element has no media.
    ERROR_SOURCE_ELEMENT_EMPTY = WindowsError::ErrorCode.new("ERROR_SOURCE_ELEMENT_EMPTY",0x00000488,"The indicated source element has no media.")

    # (0x00000489) The indicated destination element already contains media.
    ERROR_DESTINATION_ELEMENT_FULL = WindowsError::ErrorCode.new("ERROR_DESTINATION_ELEMENT_FULL",0x00000489,"The indicated destination element already contains media.")

    # (0x0000048A) The indicated element does not exist.
    ERROR_ILLEGAL_ELEMENT_ADDRESS = WindowsError::ErrorCode.new("ERROR_ILLEGAL_ELEMENT_ADDRESS",0x0000048A,"The indicated element does not exist.")

    # (0x0000048B) The indicated element is part of a magazine that is not present.
    ERROR_MAGAZINE_NOT_PRESENT = WindowsError::ErrorCode.new("ERROR_MAGAZINE_NOT_PRESENT",0x0000048B,"The indicated element is part of a magazine that is not present.")

    # (0x0000048C) The indicated device requires re-initialization due to hardware errors.
    ERROR_DEVICE_REINITIALIZATION_NEEDED = WindowsError::ErrorCode.new("ERROR_DEVICE_REINITIALIZATION_NEEDED",0x0000048C,"The indicated device requires re-initialization due to hardware errors.")

    # (0x0000048D) The device has indicated that cleaning is required before further operations are attempted.
    ERROR_DEVICE_REQUIRES_CLEANING = WindowsError::ErrorCode.new("ERROR_DEVICE_REQUIRES_CLEANING",0x0000048D,"The device has indicated that cleaning is required before further operations are attempted.")

    # (0x0000048E) The device has indicated that its door is open.
    ERROR_DEVICE_DOOR_OPEN = WindowsError::ErrorCode.new("ERROR_DEVICE_DOOR_OPEN",0x0000048E,"The device has indicated that its door is open.")

    # (0x0000048F) The device is not connected.
    ERROR_DEVICE_NOT_CONNECTED = WindowsError::ErrorCode.new("ERROR_DEVICE_NOT_CONNECTED",0x0000048F,"The device is not connected.")

    # (0x00000490) Element not found.
    ERROR_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_NOT_FOUND",0x00000490,"Element not found.")

    # (0x00000491) There was no match for the specified key in the index.
    ERROR_NO_MATCH = WindowsError::ErrorCode.new("ERROR_NO_MATCH",0x00000491,"There was no match for the specified key in the index.")

    # (0x00000492) The property set specified does not exist on the object.
    ERROR_SET_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_SET_NOT_FOUND",0x00000492,"The property set specified does not exist on the object.")

    # (0x00000493) The point passed to GetMouseMovePoints is not in the buffer.
    ERROR_POINT_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_POINT_NOT_FOUND",0x00000493,"The point passed to GetMouseMovePoints is not in the buffer.")

    # (0x00000494) The tracking (workstation) service is not running.
    ERROR_NO_TRACKING_SERVICE = WindowsError::ErrorCode.new("ERROR_NO_TRACKING_SERVICE",0x00000494,"The tracking (workstation) service is not running.")

    # (0x00000495) The volume ID could not be found.
    ERROR_NO_VOLUME_ID = WindowsError::ErrorCode.new("ERROR_NO_VOLUME_ID",0x00000495,"The volume ID could not be found.")

    # (0x00000497) Unable to remove the file to be replaced.
    ERROR_UNABLE_TO_REMOVE_REPLACED = WindowsError::ErrorCode.new("ERROR_UNABLE_TO_REMOVE_REPLACED",0x00000497,"Unable to remove the file to be replaced.")

    # (0x00000498) Unable to move the replacement file to the file to be replaced. The file to be replaced has retained its original name.
    ERROR_UNABLE_TO_MOVE_REPLACEMENT = WindowsError::ErrorCode.new("ERROR_UNABLE_TO_MOVE_REPLACEMENT",0x00000498,"Unable to move the replacement file to the file to be replaced. The file to be replaced has retained its original name.")

    # (0x00000499) Unable to move the replacement file to the file to be replaced. The file to be replaced has been renamed using the backup name.
    ERROR_UNABLE_TO_MOVE_REPLACEMENT_2 = WindowsError::ErrorCode.new("ERROR_UNABLE_TO_MOVE_REPLACEMENT_2",0x00000499,"Unable to move the replacement file to the file to be replaced. The file to be replaced has been renamed using the backup name.")

    # (0x0000049A) The volume change journal is being deleted.
    ERROR_JOURNAL_DELETE_IN_PROGRESS = WindowsError::ErrorCode.new("ERROR_JOURNAL_DELETE_IN_PROGRESS",0x0000049A,"The volume change journal is being deleted.")

    # (0x0000049B) The volume change journal is not active.
    ERROR_JOURNAL_NOT_ACTIVE = WindowsError::ErrorCode.new("ERROR_JOURNAL_NOT_ACTIVE",0x0000049B,"The volume change journal is not active.")

    # (0x0000049C) A file was found, but it may not be the correct file.
    ERROR_POTENTIAL_FILE_FOUND = WindowsError::ErrorCode.new("ERROR_POTENTIAL_FILE_FOUND",0x0000049C,"A file was found, but it may not be the correct file.")

    # (0x0000049D) The journal entry has been deleted from the journal.
    ERROR_JOURNAL_ENTRY_DELETED = WindowsError::ErrorCode.new("ERROR_JOURNAL_ENTRY_DELETED",0x0000049D,"The journal entry has been deleted from the journal.")

    # (0x000004A6) A system shutdown has already been scheduled.
    ERROR_SHUTDOWN_IS_SCHEDULED = WindowsError::ErrorCode.new("ERROR_SHUTDOWN_IS_SCHEDULED",0x000004A6,"A system shutdown has already been scheduled.")

    # (0x000004A7) The system shutdown cannot be initiated because there are other users logged on to the computer.
    ERROR_SHUTDOWN_USERS_LOGGED_ON = WindowsError::ErrorCode.new("ERROR_SHUTDOWN_USERS_LOGGED_ON",0x000004A7,"The system shutdown cannot be initiated because there are other users logged on to the computer.")

    # (0x000004B0) The specified device name is invalid.
    ERROR_BAD_DEVICE = WindowsError::ErrorCode.new("ERROR_BAD_DEVICE",0x000004B0,"The specified device name is invalid.")

    # (0x000004B1) The device is not currently connected but it is a remembered connection.
    ERROR_CONNECTION_UNAVAIL = WindowsError::ErrorCode.new("ERROR_CONNECTION_UNAVAIL",0x000004B1,"The device is not currently connected but it is a remembered connection.")

    # (0x000004B2) The local device name has a remembered connection to another network resource.
    ERROR_DEVICE_ALREADY_REMEMBERED = WindowsError::ErrorCode.new("ERROR_DEVICE_ALREADY_REMEMBERED",0x000004B2,"The local device name has a remembered connection to another network resource.")

    # (0x000004B3) The network path was either typed incorrectly, does not exist, or the network provider is not currently available. Try retyping the path or contact your network administrator.
    ERROR_NO_NET_OR_BAD_PATH = WindowsError::ErrorCode.new("ERROR_NO_NET_OR_BAD_PATH",0x000004B3,"The network path was either typed incorrectly, does not exist, or the network provider is not currently available. Try retyping the path or contact your network administrator.")

    # (0x000004B4) The specified network provider name is invalid.
    ERROR_BAD_PROVIDER = WindowsError::ErrorCode.new("ERROR_BAD_PROVIDER",0x000004B4,"The specified network provider name is invalid.")

    # (0x000004B5) Unable to open the network connection profile.
    ERROR_CANNOT_OPEN_PROFILE = WindowsError::ErrorCode.new("ERROR_CANNOT_OPEN_PROFILE",0x000004B5,"Unable to open the network connection profile.")

    # (0x000004B6) The network connection profile is corrupted.
    ERROR_BAD_PROFILE = WindowsError::ErrorCode.new("ERROR_BAD_PROFILE",0x000004B6,"The network connection profile is corrupted.")

    # (0x000004B7) Cannot enumerate a noncontainer.
    ERROR_NOT_CONTAINER = WindowsError::ErrorCode.new("ERROR_NOT_CONTAINER",0x000004B7,"Cannot enumerate a noncontainer.")

    # (0x000004B8) An extended error has occurred.
    ERROR_EXTENDED_ERROR = WindowsError::ErrorCode.new("ERROR_EXTENDED_ERROR",0x000004B8,"An extended error has occurred.")

    # (0x000004B9) The format of the specified group name is invalid.
    ERROR_INVALID_GROUPNAME = WindowsError::ErrorCode.new("ERROR_INVALID_GROUPNAME",0x000004B9,"The format of the specified group name is invalid.")

    # (0x000004BA) The format of the specified computer name is invalid.
    ERROR_INVALID_COMPUTERNAME = WindowsError::ErrorCode.new("ERROR_INVALID_COMPUTERNAME",0x000004BA,"The format of the specified computer name is invalid.")

    # (0x000004BB) The format of the specified event name is invalid.
    ERROR_INVALID_EVENTNAME = WindowsError::ErrorCode.new("ERROR_INVALID_EVENTNAME",0x000004BB,"The format of the specified event name is invalid.")

    # (0x000004BC) The format of the specified domain name is invalid.
    ERROR_INVALID_DOMAINNAME = WindowsError::ErrorCode.new("ERROR_INVALID_DOMAINNAME",0x000004BC,"The format of the specified domain name is invalid.")

    # (0x000004BD) The format of the specified service name is invalid.
    ERROR_INVALID_SERVICENAME = WindowsError::ErrorCode.new("ERROR_INVALID_SERVICENAME",0x000004BD,"The format of the specified service name is invalid.")

    # (0x000004BE) The format of the specified network name is invalid.
    ERROR_INVALID_NETNAME = WindowsError::ErrorCode.new("ERROR_INVALID_NETNAME",0x000004BE,"The format of the specified network name is invalid.")

    # (0x000004BF) The format of the specified share name is invalid.
    ERROR_INVALID_SHARENAME = WindowsError::ErrorCode.new("ERROR_INVALID_SHARENAME",0x000004BF,"The format of the specified share name is invalid.")

    # (0x000004C0) The format of the specified password is invalid.
    ERROR_INVALID_PASSWORDNAME = WindowsError::ErrorCode.new("ERROR_INVALID_PASSWORDNAME",0x000004C0,"The format of the specified password is invalid.")

    # (0x000004C1) The format of the specified message name is invalid.
    ERROR_INVALID_MESSAGENAME = WindowsError::ErrorCode.new("ERROR_INVALID_MESSAGENAME",0x000004C1,"The format of the specified message name is invalid.")

    # (0x000004C2) The format of the specified message destination is invalid.
    ERROR_INVALID_MESSAGEDEST = WindowsError::ErrorCode.new("ERROR_INVALID_MESSAGEDEST",0x000004C2,"The format of the specified message destination is invalid.")

    # (0x000004C3) Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed. Disconnect all previous connections to the server or shared resource and try again.
    ERROR_SESSION_CREDENTIAL_CONFLICT = WindowsError::ErrorCode.new("ERROR_SESSION_CREDENTIAL_CONFLICT",0x000004C3,"Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed. Disconnect all previous connections to the server or shared resource and try again.")

    # (0x000004C4) An attempt was made to establish a session to a network server, but there are already too many sessions established to that server.
    ERROR_REMOTE_SESSION_LIMIT_EXCEEDED = WindowsError::ErrorCode.new("ERROR_REMOTE_SESSION_LIMIT_EXCEEDED",0x000004C4,"An attempt was made to establish a session to a network server, but there are already too many sessions established to that server.")

    # (0x000004C5) The workgroup or domain name is already in use by another computer on the network.
    ERROR_DUP_DOMAINNAME = WindowsError::ErrorCode.new("ERROR_DUP_DOMAINNAME",0x000004C5,"The workgroup or domain name is already in use by another computer on the network.")

    # (0x000004C6) The network is not present or not started.
    ERROR_NO_NETWORK = WindowsError::ErrorCode.new("ERROR_NO_NETWORK",0x000004C6,"The network is not present or not started.")

    # (0x000004C7) The operation was canceled by the user.
    ERROR_CANCELLED = WindowsError::ErrorCode.new("ERROR_CANCELLED",0x000004C7,"The operation was canceled by the user.")

    # (0x000004C8) The requested operation cannot be performed on a file with a user-mapped section open.
    ERROR_USER_MAPPED_FILE = WindowsError::ErrorCode.new("ERROR_USER_MAPPED_FILE",0x000004C8,"The requested operation cannot be performed on a file with a user-mapped section open.")

    # (0x000004C9) The remote system refused the network connection.
    ERROR_CONNECTION_REFUSED = WindowsError::ErrorCode.new("ERROR_CONNECTION_REFUSED",0x000004C9,"The remote system refused the network connection.")

    # (0x000004CA) The network connection was gracefully closed.
    ERROR_GRACEFUL_DISCONNECT = WindowsError::ErrorCode.new("ERROR_GRACEFUL_DISCONNECT",0x000004CA,"The network connection was gracefully closed.")

    # (0x000004CB) The network transport endpoint already has an address associated with it.
    ERROR_ADDRESS_ALREADY_ASSOCIATED = WindowsError::ErrorCode.new("ERROR_ADDRESS_ALREADY_ASSOCIATED",0x000004CB,"The network transport endpoint already has an address associated with it.")

    # (0x000004CC) An address has not yet been associated with the network endpoint.
    ERROR_ADDRESS_NOT_ASSOCIATED = WindowsError::ErrorCode.new("ERROR_ADDRESS_NOT_ASSOCIATED",0x000004CC,"An address has not yet been associated with the network endpoint.")

    # (0x000004CD) An operation was attempted on a nonexistent network connection.
    ERROR_CONNECTION_INVALID = WindowsError::ErrorCode.new("ERROR_CONNECTION_INVALID",0x000004CD,"An operation was attempted on a nonexistent network connection.")

    # (0x000004CE) An invalid operation was attempted on an active network connection.
    ERROR_CONNECTION_ACTIVE = WindowsError::ErrorCode.new("ERROR_CONNECTION_ACTIVE",0x000004CE,"An invalid operation was attempted on an active network connection.")

    # (0x000004CF) The network location cannot be reached. For information about network troubleshooting, see Windows Help.
    ERROR_NETWORK_UNREACHABLE = WindowsError::ErrorCode.new("ERROR_NETWORK_UNREACHABLE",0x000004CF,"The network location cannot be reached. For information about network troubleshooting, see Windows Help.")

    # (0x000004D0) The network location cannot be reached. For information about network troubleshooting, see Windows Help.
    ERROR_HOST_UNREACHABLE = WindowsError::ErrorCode.new("ERROR_HOST_UNREACHABLE",0x000004D0,"The network location cannot be reached. For information about network troubleshooting, see Windows Help.")

    # (0x000004D1) The network location cannot be reached. For information about network troubleshooting, see Windows Help.
    ERROR_PROTOCOL_UNREACHABLE = WindowsError::ErrorCode.new("ERROR_PROTOCOL_UNREACHABLE",0x000004D1,"The network location cannot be reached. For information about network troubleshooting, see Windows Help.")

    # (0x000004D2) No service is operating at the destination network endpoint on the remote system.
    ERROR_PORT_UNREACHABLE = WindowsError::ErrorCode.new("ERROR_PORT_UNREACHABLE",0x000004D2,"No service is operating at the destination network endpoint on the remote system.")

    # (0x000004D3) The request was aborted.
    ERROR_REQUEST_ABORTED = WindowsError::ErrorCode.new("ERROR_REQUEST_ABORTED",0x000004D3,"The request was aborted.")

    # (0x000004D4) The network connection was aborted by the local system.
    ERROR_CONNECTION_ABORTED = WindowsError::ErrorCode.new("ERROR_CONNECTION_ABORTED",0x000004D4,"The network connection was aborted by the local system.")

    # (0x000004D5) The operation could not be completed. A retry should be performed.
    ERROR_RETRY = WindowsError::ErrorCode.new("ERROR_RETRY",0x000004D5,"The operation could not be completed. A retry should be performed.")

    # (0x000004D6) A connection to the server could not be made because the limit on the number of concurrent connections for this account has been reached.
    ERROR_CONNECTION_COUNT_LIMIT = WindowsError::ErrorCode.new("ERROR_CONNECTION_COUNT_LIMIT",0x000004D6,"A connection to the server could not be made because the limit on the number of concurrent connections for this account has been reached.")

    # (0x000004D7) Attempting to log on during an unauthorized time of day for this account.
    ERROR_LOGIN_TIME_RESTRICTION = WindowsError::ErrorCode.new("ERROR_LOGIN_TIME_RESTRICTION",0x000004D7,"Attempting to log on during an unauthorized time of day for this account.")

    # (0x000004D8) The account is not authorized to log on from this station.
    ERROR_LOGIN_WKSTA_RESTRICTION = WindowsError::ErrorCode.new("ERROR_LOGIN_WKSTA_RESTRICTION",0x000004D8,"The account is not authorized to log on from this station.")

    # (0x000004D9) The network address could not be used for the operation requested.
    ERROR_INCORRECT_ADDRESS = WindowsError::ErrorCode.new("ERROR_INCORRECT_ADDRESS",0x000004D9,"The network address could not be used for the operation requested.")

    # (0x000004DA) The service is already registered.
    ERROR_ALREADY_REGISTERED = WindowsError::ErrorCode.new("ERROR_ALREADY_REGISTERED",0x000004DA,"The service is already registered.")

    # (0x000004DB) The specified service does not exist.
    ERROR_SERVICE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_SERVICE_NOT_FOUND",0x000004DB,"The specified service does not exist.")

    # (0x000004DC) The operation being requested was not performed because the user has not been authenticated.
    ERROR_NOT_AUTHENTICATED = WindowsError::ErrorCode.new("ERROR_NOT_AUTHENTICATED",0x000004DC,"The operation being requested was not performed because the user has not been authenticated.")

    # (0x000004DD) The operation being requested was not performed because the user has not logged on to the network. The specified service does not exist.
    ERROR_NOT_LOGGED_ON = WindowsError::ErrorCode.new("ERROR_NOT_LOGGED_ON",0x000004DD,"The operation being requested was not performed because the user has not logged on to the network. The specified service does not exist.")

    # (0x000004DE) Continue with work in progress.
    ERROR_CONTINUE = WindowsError::ErrorCode.new("ERROR_CONTINUE",0x000004DE,"Continue with work in progress.")

    # (0x000004DF) An attempt was made to perform an initialization operation when initialization has already been completed.
    ERROR_ALREADY_INITIALIZED = WindowsError::ErrorCode.new("ERROR_ALREADY_INITIALIZED",0x000004DF,"An attempt was made to perform an initialization operation when initialization has already been completed.")

    # (0x000004E0) No more local devices.
    ERROR_NO_MORE_DEVICES = WindowsError::ErrorCode.new("ERROR_NO_MORE_DEVICES",0x000004E0,"No more local devices.")

    # (0x000004E1) The specified site does not exist.
    ERROR_NO_SUCH_SITE = WindowsError::ErrorCode.new("ERROR_NO_SUCH_SITE",0x000004E1,"The specified site does not exist.")

    # (0x000004E2) A domain controller with the specified name already exists.
    ERROR_DOMAIN_CONTROLLER_EXISTS = WindowsError::ErrorCode.new("ERROR_DOMAIN_CONTROLLER_EXISTS",0x000004E2,"A domain controller with the specified name already exists.")

    # (0x000004E3) This operation is supported only when you are connected to the server.
    ERROR_ONLY_IF_CONNECTED = WindowsError::ErrorCode.new("ERROR_ONLY_IF_CONNECTED",0x000004E3,"This operation is supported only when you are connected to the server.")

    # (0x000004E4) The group policy framework should call the extension even if there are no changes.
    ERROR_OVERRIDE_NOCHANGES = WindowsError::ErrorCode.new("ERROR_OVERRIDE_NOCHANGES",0x000004E4,"The group policy framework should call the extension even if there are no changes.")

    # (0x000004E5) The specified user does not have a valid profile.
    ERROR_BAD_USER_PROFILE = WindowsError::ErrorCode.new("ERROR_BAD_USER_PROFILE",0x000004E5,"The specified user does not have a valid profile.")

    # (0x000004E6) This operation is not supported on a computer running Windows Server 2003 for Small Business Server.
    ERROR_NOT_SUPPORTED_ON_SBS = WindowsError::ErrorCode.new("ERROR_NOT_SUPPORTED_ON_SBS",0x000004E6,"This operation is not supported on a computer running Windows Server 2003 for Small Business Server.")

    # (0x000004E7) The server machine is shutting down.
    ERROR_SERVER_SHUTDOWN_IN_PROGRESS = WindowsError::ErrorCode.new("ERROR_SERVER_SHUTDOWN_IN_PROGRESS",0x000004E7,"The server machine is shutting down.")

    # (0x000004E8) The remote system is not available. For information about network troubleshooting, see Windows Help.
    ERROR_HOST_DOWN = WindowsError::ErrorCode.new("ERROR_HOST_DOWN",0x000004E8,"The remote system is not available. For information about network troubleshooting, see Windows Help.")

    # (0x000004E9) The security identifier provided is not from an account domain.
    ERROR_NON_ACCOUNT_SID = WindowsError::ErrorCode.new("ERROR_NON_ACCOUNT_SID",0x000004E9,"The security identifier provided is not from an account domain.")

    # (0x000004EA) The security identifier provided does not have a domain component.
    ERROR_NON_DOMAIN_SID = WindowsError::ErrorCode.new("ERROR_NON_DOMAIN_SID",0x000004EA,"The security identifier provided does not have a domain component.")

    # (0x000004EB) AppHelp dialog canceled, thus preventing the application from starting.
    ERROR_APPHELP_BLOCK = WindowsError::ErrorCode.new("ERROR_APPHELP_BLOCK",0x000004EB,"AppHelp dialog canceled, thus preventing the application from starting.")

    # (0x000004EC) This program is blocked by Group Policy. For more information, contact your system administrator.
    ERROR_ACCESS_DISABLED_BY_POLICY = WindowsError::ErrorCode.new("ERROR_ACCESS_DISABLED_BY_POLICY",0x000004EC,"This program is blocked by Group Policy. For more information, contact your system administrator.")

    # (0x000004ED) A program attempt to use an invalid register value. Normally caused by an uninitialized register. This error is Itanium specific.
    ERROR_REG_NAT_CONSUMPTION = WindowsError::ErrorCode.new("ERROR_REG_NAT_CONSUMPTION",0x000004ED,"A program attempt to use an invalid register value. Normally caused by an uninitialized register. This error is Itanium specific.")

    # (0x000004EE) The share is currently offline or does not exist.
    ERROR_CSCSHARE_OFFLINE = WindowsError::ErrorCode.new("ERROR_CSCSHARE_OFFLINE",0x000004EE,"The share is currently offline or does not exist.")

    # (0x000004EF) The Kerberos protocol encountered an error while validating the KDC certificate during smartcard logon. There is more information in the system event log.
    ERROR_PKINIT_FAILURE = WindowsError::ErrorCode.new("ERROR_PKINIT_FAILURE",0x000004EF,"The Kerberos protocol encountered an error while validating the KDC certificate during smartcard logon. There is more information in the system event log.")

    # (0x000004F0) The Kerberos protocol encountered an error while attempting to utilize the smartcard subsystem.
    ERROR_SMARTCARD_SUBSYSTEM_FAILURE = WindowsError::ErrorCode.new("ERROR_SMARTCARD_SUBSYSTEM_FAILURE",0x000004F0,"The Kerberos protocol encountered an error while attempting to utilize the smartcard subsystem.")

    # (0x000004F1) The system detected a possible attempt to compromise security. Ensure that you can contact the server that authenticated you.
    ERROR_DOWNGRADE_DETECTED = WindowsError::ErrorCode.new("ERROR_DOWNGRADE_DETECTED",0x000004F1,"The system detected a possible attempt to compromise security. Ensure that you can contact the server that authenticated you.")

    # (0x000004F7) The machine is locked and cannot be shut down without the force option.
    ERROR_MACHINE_LOCKED = WindowsError::ErrorCode.new("ERROR_MACHINE_LOCKED",0x000004F7,"The machine is locked and cannot be shut down without the force option.")

    # (0x000004F9) An application-defined callback gave invalid data when called.
    ERROR_CALLBACK_SUPPLIED_INVALID_DATA = WindowsError::ErrorCode.new("ERROR_CALLBACK_SUPPLIED_INVALID_DATA",0x000004F9,"An application-defined callback gave invalid data when called.")

    # (0x000004FA) The Group Policy framework should call the extension in the synchronous foreground policy refresh.
    ERROR_SYNC_FOREGROUND_REFRESH_REQUIRED = WindowsError::ErrorCode.new("ERROR_SYNC_FOREGROUND_REFRESH_REQUIRED",0x000004FA,"The Group Policy framework should call the extension in the synchronous foreground policy refresh.")

    # (0x000004FB) This driver has been blocked from loading.
    ERROR_DRIVER_BLOCKED = WindowsError::ErrorCode.new("ERROR_DRIVER_BLOCKED",0x000004FB,"This driver has been blocked from loading.")

    # (0x000004FC) A DLL referenced a module that was neither a DLL nor the process's executable image.
    ERROR_INVALID_IMPORT_OF_NON_DLL = WindowsError::ErrorCode.new("ERROR_INVALID_IMPORT_OF_NON_DLL",0x000004FC,"A DLL referenced a module that was neither a DLL nor the process's executable image.")

    # (0x000004FD) Windows cannot open this program because it has been disabled.
    ERROR_ACCESS_DISABLED_WEBBLADE = WindowsError::ErrorCode.new("ERROR_ACCESS_DISABLED_WEBBLADE",0x000004FD,"Windows cannot open this program because it has been disabled.")

    # (0x000004FE) Windows cannot open this program because the license enforcement system has been tampered with or become corrupted.
    ERROR_ACCESS_DISABLED_WEBBLADE_TAMPER = WindowsError::ErrorCode.new("ERROR_ACCESS_DISABLED_WEBBLADE_TAMPER",0x000004FE,"Windows cannot open this program because the license enforcement system has been tampered with or become corrupted.")

    # (0x000004FF) A transaction recover failed.
    ERROR_RECOVERY_FAILURE = WindowsError::ErrorCode.new("ERROR_RECOVERY_FAILURE",0x000004FF,"A transaction recover failed.")

    # (0x00000500) The current thread has already been converted to a fiber.
    ERROR_ALREADY_FIBER = WindowsError::ErrorCode.new("ERROR_ALREADY_FIBER",0x00000500,"The current thread has already been converted to a fiber.")

    # (0x00000501) The current thread has already been converted from a fiber.
    ERROR_ALREADY_THREAD = WindowsError::ErrorCode.new("ERROR_ALREADY_THREAD",0x00000501,"The current thread has already been converted from a fiber.")

    # (0x00000502) The system detected an overrun of a stack-based buffer in this application. This overrun could potentially allow a malicious user to gain control of this application.
    ERROR_STACK_BUFFER_OVERRUN = WindowsError::ErrorCode.new("ERROR_STACK_BUFFER_OVERRUN",0x00000502,"The system detected an overrun of a stack-based buffer in this application. This overrun could potentially allow a malicious user to gain control of this application.")

    # (0x00000503) Data present in one of the parameters is more than the function can operate on.
    ERROR_PARAMETER_QUOTA_EXCEEDED = WindowsError::ErrorCode.new("ERROR_PARAMETER_QUOTA_EXCEEDED",0x00000503,"Data present in one of the parameters is more than the function can operate on.")

    # (0x00000504) An attempt to perform an operation on a debug object failed because the object is in the process of being deleted.
    ERROR_DEBUGGER_INACTIVE = WindowsError::ErrorCode.new("ERROR_DEBUGGER_INACTIVE",0x00000504,"An attempt to perform an operation on a debug object failed because the object is in the process of being deleted.")

    # (0x00000505) An attempt to delay-load a .dll or get a function address in a delay-loaded .dll failed.
    ERROR_DELAY_LOAD_FAILED = WindowsError::ErrorCode.new("ERROR_DELAY_LOAD_FAILED",0x00000505,"An attempt to delay-load a .dll or get a function address in a delay-loaded .dll failed.")

    # (0x00000506) %1 is a 16-bit application. You do not have permissions to execute 16-bit applications. Check your permissions with your system administrator.
    ERROR_VDM_DISALLOWED = WindowsError::ErrorCode.new("ERROR_VDM_DISALLOWED",0x00000506,"%1 is a 16-bit application. You do not have permissions to execute 16-bit applications. Check your permissions with your system administrator.")

    # (0x00000507) Insufficient information exists to identify the cause of failure.
    ERROR_UNIDENTIFIED_ERROR = WindowsError::ErrorCode.new("ERROR_UNIDENTIFIED_ERROR",0x00000507,"Insufficient information exists to identify the cause of failure.")

    # (0x00000508) The parameter passed to a C runtime function is incorrect.
    ERROR_INVALID_CRUNTIME_PARAMETER = WindowsError::ErrorCode.new("ERROR_INVALID_CRUNTIME_PARAMETER",0x00000508,"The parameter passed to a C runtime function is incorrect.")

    # (0x00000509) The operation occurred beyond the valid data length of the file.
    ERROR_BEYOND_VDL = WindowsError::ErrorCode.new("ERROR_BEYOND_VDL",0x00000509,"The operation occurred beyond the valid data length of the file.")

    # (0x0000050A) The service start failed because one or more services in the same process have an incompatible service SID type setting. A service with a restricted service SID type can only coexist in the same process with other services with a restricted SID type.
    ERROR_INCOMPATIBLE_SERVICE_SID_TYPE = WindowsError::ErrorCode.new("ERROR_INCOMPATIBLE_SERVICE_SID_TYPE",0x0000050A,"The service start failed because one or more services in the same process have an incompatible service SID type setting. A service with a restricted service SID type can only coexist in the same process with other services with a restricted SID type.")

    # (0x0000050B) The process hosting the driver for this device has been terminated.
    ERROR_DRIVER_PROCESS_TERMINATED = WindowsError::ErrorCode.new("ERROR_DRIVER_PROCESS_TERMINATED",0x0000050B,"The process hosting the driver for this device has been terminated.")

    # (0x0000050C) An operation attempted to exceed an implementation-defined limit.
    ERROR_IMPLEMENTATION_LIMIT = WindowsError::ErrorCode.new("ERROR_IMPLEMENTATION_LIMIT",0x0000050C,"An operation attempted to exceed an implementation-defined limit.")

    # (0x0000050D) Either the target process, or the target thread's containing process, is a protected process.
    ERROR_PROCESS_IS_PROTECTED = WindowsError::ErrorCode.new("ERROR_PROCESS_IS_PROTECTED",0x0000050D,"Either the target process, or the target thread's containing process, is a protected process.")

    # (0x0000050E) The service notification client is lagging too far behind the current state of services in the machine.
    ERROR_SERVICE_NOTIFY_CLIENT_LAGGING = WindowsError::ErrorCode.new("ERROR_SERVICE_NOTIFY_CLIENT_LAGGING",0x0000050E,"The service notification client is lagging too far behind the current state of services in the machine.")

    # (0x0000050F) An operation failed because the storage quota was exceeded.
    ERROR_DISK_QUOTA_EXCEEDED = WindowsError::ErrorCode.new("ERROR_DISK_QUOTA_EXCEEDED",0x0000050F,"An operation failed because the storage quota was exceeded.")

    # (0x00000510) An operation failed because the content was blocked.
    ERROR_CONTENT_BLOCKED = WindowsError::ErrorCode.new("ERROR_CONTENT_BLOCKED",0x00000510,"An operation failed because the content was blocked.")

    # (0x00000511) A privilege that the service requires to function properly does not exist in the service account configuration. You may use the Services Microsoft Management Console (MMC) snap-in (Services.msc) and the Local Security Settings MMC snap-in (Secpol.msc) to view the service configuration and the account configuration.
    ERROR_INCOMPATIBLE_SERVICE_PRIVILEGE = WindowsError::ErrorCode.new("ERROR_INCOMPATIBLE_SERVICE_PRIVILEGE",0x00000511,"A privilege that the service requires to function properly does not exist in the service account configuration. You may use the Services Microsoft Management Console (MMC) snap-in (Services.msc) and the Local Security Settings MMC snap-in (Secpol.msc) to view the service configuration and the account configuration.")

    # (0x00000513) Indicates a particular SID may not be assigned as the label of an object.
    ERROR_INVALID_LABEL = WindowsError::ErrorCode.new("ERROR_INVALID_LABEL",0x00000513,"Indicates a particular SID may not be assigned as the label of an object.")

    # (0x00000514) Not all privileges or groups referenced are assigned to the caller.
    ERROR_NOT_ALL_ASSIGNED = WindowsError::ErrorCode.new("ERROR_NOT_ALL_ASSIGNED",0x00000514,"Not all privileges or groups referenced are assigned to the caller.")

    # (0x00000515) Some mapping between account names and SIDs was not done.
    ERROR_SOME_NOT_MAPPED = WindowsError::ErrorCode.new("ERROR_SOME_NOT_MAPPED",0x00000515,"Some mapping between account names and SIDs was not done.")

    # (0x00000516) No system quota limits are specifically set for this account.
    ERROR_NO_QUOTAS_FOR_ACCOUNT = WindowsError::ErrorCode.new("ERROR_NO_QUOTAS_FOR_ACCOUNT",0x00000516,"No system quota limits are specifically set for this account.")

    # (0x00000517) No encryption key is available. A well-known encryption key was returned.
    ERROR_LOCAL_USER_SESSION_KEY = WindowsError::ErrorCode.new("ERROR_LOCAL_USER_SESSION_KEY",0x00000517,"No encryption key is available. A well-known encryption key was returned.")

    # (0x00000518) The password is too complex to be converted to a LAN Manager password. The LAN Manager password returned is a null string.
    ERROR_NULL_LM_PASSWORD = WindowsError::ErrorCode.new("ERROR_NULL_LM_PASSWORD",0x00000518,"The password is too complex to be converted to a LAN Manager password. The LAN Manager password returned is a null string.")

    # (0x00000519) The revision level is unknown.
    ERROR_UNKNOWN_REVISION = WindowsError::ErrorCode.new("ERROR_UNKNOWN_REVISION",0x00000519,"The revision level is unknown.")

    # (0x0000051A) Indicates two revision levels are incompatible.
    ERROR_REVISION_MISMATCH = WindowsError::ErrorCode.new("ERROR_REVISION_MISMATCH",0x0000051A,"Indicates two revision levels are incompatible.")

    # (0x0000051B) This SID may not be assigned as the owner of this object.
    ERROR_INVALID_OWNER = WindowsError::ErrorCode.new("ERROR_INVALID_OWNER",0x0000051B,"This SID may not be assigned as the owner of this object.")

    # (0x0000051C) This SID may not be assigned as the primary group of an object.
    ERROR_INVALID_PRIMARY_GROUP = WindowsError::ErrorCode.new("ERROR_INVALID_PRIMARY_GROUP",0x0000051C,"This SID may not be assigned as the primary group of an object.")

    # (0x0000051D) An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client.
    ERROR_NO_IMPERSONATION_TOKEN = WindowsError::ErrorCode.new("ERROR_NO_IMPERSONATION_TOKEN",0x0000051D,"An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client.")

    # (0x0000051E) The group may not be disabled.
    ERROR_CANT_DISABLE_MANDATORY = WindowsError::ErrorCode.new("ERROR_CANT_DISABLE_MANDATORY",0x0000051E,"The group may not be disabled.")

    # (0x0000051F) There are currently no logon servers available to service the logon request.
    ERROR_NO_LOGON_SERVERS = WindowsError::ErrorCode.new("ERROR_NO_LOGON_SERVERS",0x0000051F,"There are currently no logon servers available to service the logon request.")

    # (0x00000520) A specified logon session does not exist. It may already have been terminated.
    ERROR_NO_SUCH_LOGON_SESSION = WindowsError::ErrorCode.new("ERROR_NO_SUCH_LOGON_SESSION",0x00000520,"A specified logon session does not exist. It may already have been terminated.")

    # (0x00000521) A specified privilege does not exist.
    ERROR_NO_SUCH_PRIVILEGE = WindowsError::ErrorCode.new("ERROR_NO_SUCH_PRIVILEGE",0x00000521,"A specified privilege does not exist.")

    # (0x00000522) A required privilege is not held by the client.
    ERROR_PRIVILEGE_NOT_HELD = WindowsError::ErrorCode.new("ERROR_PRIVILEGE_NOT_HELD",0x00000522,"A required privilege is not held by the client.")

    # (0x00000523) The name provided is not a properly formed account name.
    ERROR_INVALID_ACCOUNT_NAME = WindowsError::ErrorCode.new("ERROR_INVALID_ACCOUNT_NAME",0x00000523,"The name provided is not a properly formed account name.")

    # (0x00000524) The specified account already exists.
    ERROR_USER_EXISTS = WindowsError::ErrorCode.new("ERROR_USER_EXISTS",0x00000524,"The specified account already exists.")

    # (0x00000525) The specified account does not exist.
    ERROR_NO_SUCH_USER = WindowsError::ErrorCode.new("ERROR_NO_SUCH_USER",0x00000525,"The specified account does not exist.")

    # (0x00000526) The specified group already exists.
    ERROR_GROUP_EXISTS = WindowsError::ErrorCode.new("ERROR_GROUP_EXISTS",0x00000526,"The specified group already exists.")

    # (0x00000527) The specified group does not exist.
    ERROR_NO_SUCH_GROUP = WindowsError::ErrorCode.new("ERROR_NO_SUCH_GROUP",0x00000527,"The specified group does not exist.")

    # (0x00000528) Either the specified user account is already a member of the specified group, or the specified group cannot be deleted because it contains a member.
    ERROR_MEMBER_IN_GROUP = WindowsError::ErrorCode.new("ERROR_MEMBER_IN_GROUP",0x00000528,"Either the specified user account is already a member of the specified group, or the specified group cannot be deleted because it contains a member.")

    # (0x00000529) The specified user account is not a member of the specified group account.
    ERROR_MEMBER_NOT_IN_GROUP = WindowsError::ErrorCode.new("ERROR_MEMBER_NOT_IN_GROUP",0x00000529,"The specified user account is not a member of the specified group account.")

    # (0x0000052A) The last remaining administration account cannot be disabled or deleted.
    ERROR_LAST_ADMIN = WindowsError::ErrorCode.new("ERROR_LAST_ADMIN",0x0000052A,"The last remaining administration account cannot be disabled or deleted.")

    # (0x0000052B) Unable to update the password. The value provided as the current password is incorrect.
    ERROR_WRONG_PASSWORD = WindowsError::ErrorCode.new("ERROR_WRONG_PASSWORD",0x0000052B,"Unable to update the password. The value provided as the current password is incorrect.")

    # (0x0000052C) Unable to update the password. The value provided for the new password contains values that are not allowed in passwords.
    ERROR_ILL_FORMED_PASSWORD = WindowsError::ErrorCode.new("ERROR_ILL_FORMED_PASSWORD",0x0000052C,"Unable to update the password. The value provided for the new password contains values that are not allowed in passwords.")

    # (0x0000052D) Unable to update the password. The value provided for the new password does not meet the length, complexity, or history requirements of the domain.
    ERROR_PASSWORD_RESTRICTION = WindowsError::ErrorCode.new("ERROR_PASSWORD_RESTRICTION",0x0000052D,"Unable to update the password. The value provided for the new password does not meet the length, complexity, or history requirements of the domain.")

    # (0x0000052E) Logon failure: Unknown user name or bad password.
    ERROR_LOGON_FAILURE = WindowsError::ErrorCode.new("ERROR_LOGON_FAILURE",0x0000052E,"Logon failure: Unknown user name or bad password.")

    # (0x0000052F) Logon failure: User account restriction. Possible reasons are blank passwords not allowed, logon hour restrictions, or a policy restriction has been enforced.
    ERROR_ACCOUNT_RESTRICTION = WindowsError::ErrorCode.new("ERROR_ACCOUNT_RESTRICTION",0x0000052F,"Logon failure: User account restriction. Possible reasons are blank passwords not allowed, logon hour restrictions, or a policy restriction has been enforced.")

    # (0x00000530) Logon failure: Account logon time restriction violation.
    ERROR_INVALID_LOGON_HOURS = WindowsError::ErrorCode.new("ERROR_INVALID_LOGON_HOURS",0x00000530,"Logon failure: Account logon time restriction violation.")

    # (0x00000531) Logon failure: User not allowed to log on to this computer.
    ERROR_INVALID_WORKSTATION = WindowsError::ErrorCode.new("ERROR_INVALID_WORKSTATION",0x00000531,"Logon failure: User not allowed to log on to this computer.")

    # (0x00000532) Logon failure: The specified account password has expired.
    ERROR_PASSWORD_EXPIRED = WindowsError::ErrorCode.new("ERROR_PASSWORD_EXPIRED",0x00000532,"Logon failure: The specified account password has expired.")

    # (0x00000533) Logon failure: Account currently disabled.
    ERROR_ACCOUNT_DISABLED = WindowsError::ErrorCode.new("ERROR_ACCOUNT_DISABLED",0x00000533,"Logon failure: Account currently disabled.")

    # (0x00000534) No mapping between account names and SIDs was done.
    ERROR_NONE_MAPPED = WindowsError::ErrorCode.new("ERROR_NONE_MAPPED",0x00000534,"No mapping between account names and SIDs was done.")

    # (0x00000535) Too many local user identifiers (LUIDs) were requested at one time.
    ERROR_TOO_MANY_LUIDS_REQUESTED = WindowsError::ErrorCode.new("ERROR_TOO_MANY_LUIDS_REQUESTED",0x00000535,"Too many local user identifiers (LUIDs) were requested at one time.")

    # (0x00000536) No more LUIDs are available.
    ERROR_LUIDS_EXHAUSTED = WindowsError::ErrorCode.new("ERROR_LUIDS_EXHAUSTED",0x00000536,"No more LUIDs are available.")

    # (0x00000537) The sub-authority part of an SID is invalid for this particular use.
    ERROR_INVALID_SUB_AUTHORITY = WindowsError::ErrorCode.new("ERROR_INVALID_SUB_AUTHORITY",0x00000537,"The sub-authority part of an SID is invalid for this particular use.")

    # (0x00000538) The ACL structure is invalid.
    ERROR_INVALID_ACL = WindowsError::ErrorCode.new("ERROR_INVALID_ACL",0x00000538,"The ACL structure is invalid.")

    # (0x00000539) The SID structure is invalid.
    ERROR_INVALID_SID = WindowsError::ErrorCode.new("ERROR_INVALID_SID",0x00000539,"The SID structure is invalid.")

    # (0x0000053A) The security descriptor structure is invalid.
    ERROR_INVALID_SECURITY_DESCR = WindowsError::ErrorCode.new("ERROR_INVALID_SECURITY_DESCR",0x0000053A,"The security descriptor structure is invalid.")

    # (0x0000053C) The inherited ACL or ACE could not be built.
    ERROR_BAD_INHERITANCE_ACL = WindowsError::ErrorCode.new("ERROR_BAD_INHERITANCE_ACL",0x0000053C,"The inherited ACL or ACE could not be built.")

    # (0x0000053D) The server is currently disabled.
    ERROR_SERVER_DISABLED = WindowsError::ErrorCode.new("ERROR_SERVER_DISABLED",0x0000053D,"The server is currently disabled.")

    # (0x0000053E) The server is currently enabled.
    ERROR_SERVER_NOT_DISABLED = WindowsError::ErrorCode.new("ERROR_SERVER_NOT_DISABLED",0x0000053E,"The server is currently enabled.")

    # (0x0000053F) The value provided was an invalid value for an identifier authority.
    ERROR_INVALID_ID_AUTHORITY = WindowsError::ErrorCode.new("ERROR_INVALID_ID_AUTHORITY",0x0000053F,"The value provided was an invalid value for an identifier authority.")

    # (0x00000540) No more memory is available for security information updates.
    ERROR_ALLOTTED_SPACE_EXCEEDED = WindowsError::ErrorCode.new("ERROR_ALLOTTED_SPACE_EXCEEDED",0x00000540,"No more memory is available for security information updates.")

    # (0x00000541) The specified attributes are invalid, or incompatible with the attributes for the group as a whole.
    ERROR_INVALID_GROUP_ATTRIBUTES = WindowsError::ErrorCode.new("ERROR_INVALID_GROUP_ATTRIBUTES",0x00000541,"The specified attributes are invalid, or incompatible with the attributes for the group as a whole.")

    # (0x00000542) Either a required impersonation level was not provided, or the provided impersonation level is invalid.
    ERROR_BAD_IMPERSONATION_LEVEL = WindowsError::ErrorCode.new("ERROR_BAD_IMPERSONATION_LEVEL",0x00000542,"Either a required impersonation level was not provided, or the provided impersonation level is invalid.")

    # (0x00000543) Cannot open an anonymous level security token.
    ERROR_CANT_OPEN_ANONYMOUS = WindowsError::ErrorCode.new("ERROR_CANT_OPEN_ANONYMOUS",0x00000543,"Cannot open an anonymous level security token.")

    # (0x00000544) The validation information class requested was invalid.
    ERROR_BAD_VALIDATION_CLASS = WindowsError::ErrorCode.new("ERROR_BAD_VALIDATION_CLASS",0x00000544,"The validation information class requested was invalid.")

    # (0x00000545) The type of the token is inappropriate for its attempted use.
    ERROR_BAD_TOKEN_TYPE = WindowsError::ErrorCode.new("ERROR_BAD_TOKEN_TYPE",0x00000545,"The type of the token is inappropriate for its attempted use.")

    # (0x00000546) Unable to perform a security operation on an object that has no associated security.
    ERROR_NO_SECURITY_ON_OBJECT = WindowsError::ErrorCode.new("ERROR_NO_SECURITY_ON_OBJECT",0x00000546,"Unable to perform a security operation on an object that has no associated security.")

    # (0x00000547) Configuration information could not be read from the domain controller, either because the machine is unavailable, or access has been denied.
    ERROR_CANT_ACCESS_DOMAIN_INFO = WindowsError::ErrorCode.new("ERROR_CANT_ACCESS_DOMAIN_INFO",0x00000547,"Configuration information could not be read from the domain controller, either because the machine is unavailable, or access has been denied.")

    # (0x00000548) The SAM or local security authority (LSA) server was in the wrong state to perform the security operation.
    ERROR_INVALID_SERVER_STATE = WindowsError::ErrorCode.new("ERROR_INVALID_SERVER_STATE",0x00000548,"The SAM or local security authority (LSA) server was in the wrong state to perform the security operation.")

    # (0x00000549) The domain was in the wrong state to perform the security operation.
    ERROR_INVALID_DOMAIN_STATE = WindowsError::ErrorCode.new("ERROR_INVALID_DOMAIN_STATE",0x00000549,"The domain was in the wrong state to perform the security operation.")

    # (0x0000054A) This operation is only allowed for the PDC of the domain.
    ERROR_INVALID_DOMAIN_ROLE = WindowsError::ErrorCode.new("ERROR_INVALID_DOMAIN_ROLE",0x0000054A,"This operation is only allowed for the PDC of the domain.")

    # (0x0000054B) The specified domain either does not exist or could not be contacted.
    ERROR_NO_SUCH_DOMAIN = WindowsError::ErrorCode.new("ERROR_NO_SUCH_DOMAIN",0x0000054B,"The specified domain either does not exist or could not be contacted.")

    # (0x0000054C) The specified domain already exists.
    ERROR_DOMAIN_EXISTS = WindowsError::ErrorCode.new("ERROR_DOMAIN_EXISTS",0x0000054C,"The specified domain already exists.")

    # (0x0000054D) An attempt was made to exceed the limit on the number of domains per server.
    ERROR_DOMAIN_LIMIT_EXCEEDED = WindowsError::ErrorCode.new("ERROR_DOMAIN_LIMIT_EXCEEDED",0x0000054D,"An attempt was made to exceed the limit on the number of domains per server.")

    # (0x0000054E) Unable to complete the requested operation because of either a catastrophic media failure or a data structure corruption on the disk.
    ERROR_INTERNAL_DB_CORRUPTION = WindowsError::ErrorCode.new("ERROR_INTERNAL_DB_CORRUPTION",0x0000054E,"Unable to complete the requested operation because of either a catastrophic media failure or a data structure corruption on the disk.")

    # (0x0000054F) An internal error occurred.
    ERROR_INTERNAL_ERROR = WindowsError::ErrorCode.new("ERROR_INTERNAL_ERROR",0x0000054F,"An internal error occurred.")

    # (0x00000550) Generic access types were contained in an access mask that should already be mapped to nongeneric types.
    ERROR_GENERIC_NOT_MAPPED = WindowsError::ErrorCode.new("ERROR_GENERIC_NOT_MAPPED",0x00000550,"Generic access types were contained in an access mask that should already be mapped to nongeneric types.")

    # (0x00000551) A security descriptor is not in the right format (absolute or self-relative).
    ERROR_BAD_DESCRIPTOR_FORMAT = WindowsError::ErrorCode.new("ERROR_BAD_DESCRIPTOR_FORMAT",0x00000551,"A security descriptor is not in the right format (absolute or self-relative).")

    # (0x00000552) The requested action is restricted for use by logon processes only. The calling process has not registered as a logon process.
    ERROR_NOT_LOGON_PROCESS = WindowsError::ErrorCode.new("ERROR_NOT_LOGON_PROCESS",0x00000552,"The requested action is restricted for use by logon processes only. The calling process has not registered as a logon process.")

    # (0x00000553) Cannot start a new logon session with an ID that is already in use.
    ERROR_LOGON_SESSION_EXISTS = WindowsError::ErrorCode.new("ERROR_LOGON_SESSION_EXISTS",0x00000553,"Cannot start a new logon session with an ID that is already in use.")

    # (0x00000554) A specified authentication package is unknown.
    ERROR_NO_SUCH_PACKAGE = WindowsError::ErrorCode.new("ERROR_NO_SUCH_PACKAGE",0x00000554,"A specified authentication package is unknown.")

    # (0x00000555) The logon session is not in a state that is consistent with the requested operation.
    ERROR_BAD_LOGON_SESSION_STATE = WindowsError::ErrorCode.new("ERROR_BAD_LOGON_SESSION_STATE",0x00000555,"The logon session is not in a state that is consistent with the requested operation.")

    # (0x00000556) The logon session ID is already in use.
    ERROR_LOGON_SESSION_COLLISION = WindowsError::ErrorCode.new("ERROR_LOGON_SESSION_COLLISION",0x00000556,"The logon session ID is already in use.")

    # (0x00000557) A logon request contained an invalid logon type value.
    ERROR_INVALID_LOGON_TYPE = WindowsError::ErrorCode.new("ERROR_INVALID_LOGON_TYPE",0x00000557,"A logon request contained an invalid logon type value.")

    # (0x00000558) Unable to impersonate using a named pipe until data has been read from that pipe.
    ERROR_CANNOT_IMPERSONATE = WindowsError::ErrorCode.new("ERROR_CANNOT_IMPERSONATE",0x00000558,"Unable to impersonate using a named pipe until data has been read from that pipe.")

    # (0x00000559) The transaction state of a registry subtree is incompatible with the requested operation.
    ERROR_RXACT_INVALID_STATE = WindowsError::ErrorCode.new("ERROR_RXACT_INVALID_STATE",0x00000559,"The transaction state of a registry subtree is incompatible with the requested operation.")

    # (0x0000055A) An internal security database corruption has been encountered.
    ERROR_RXACT_COMMIT_FAILURE = WindowsError::ErrorCode.new("ERROR_RXACT_COMMIT_FAILURE",0x0000055A,"An internal security database corruption has been encountered.")

    # (0x0000055B) Cannot perform this operation on built-in accounts.
    ERROR_SPECIAL_ACCOUNT = WindowsError::ErrorCode.new("ERROR_SPECIAL_ACCOUNT",0x0000055B,"Cannot perform this operation on built-in accounts.")

    # (0x0000055C) Cannot perform this operation on this built-in special group.
    ERROR_SPECIAL_GROUP = WindowsError::ErrorCode.new("ERROR_SPECIAL_GROUP",0x0000055C,"Cannot perform this operation on this built-in special group.")

    # (0x0000055D) Cannot perform this operation on this built-in special user.
    ERROR_SPECIAL_USER = WindowsError::ErrorCode.new("ERROR_SPECIAL_USER",0x0000055D,"Cannot perform this operation on this built-in special user.")

    # (0x0000055E) The user cannot be removed from a group because the group is currently the user's primary group.
    ERROR_MEMBERS_PRIMARY_GROUP = WindowsError::ErrorCode.new("ERROR_MEMBERS_PRIMARY_GROUP",0x0000055E,"The user cannot be removed from a group because the group is currently the user's primary group.")

    # (0x0000055F) The token is already in use as a primary token.
    ERROR_TOKEN_ALREADY_IN_USE = WindowsError::ErrorCode.new("ERROR_TOKEN_ALREADY_IN_USE",0x0000055F,"The token is already in use as a primary token.")

    # (0x00000560) The specified local group does not exist.
    ERROR_NO_SUCH_ALIAS = WindowsError::ErrorCode.new("ERROR_NO_SUCH_ALIAS",0x00000560,"The specified local group does not exist.")

    # (0x00000561) The specified account name is not a member of the group.
    ERROR_MEMBER_NOT_IN_ALIAS = WindowsError::ErrorCode.new("ERROR_MEMBER_NOT_IN_ALIAS",0x00000561,"The specified account name is not a member of the group.")

    # (0x00000562) The specified account name is already a member of the group.
    ERROR_MEMBER_IN_ALIAS = WindowsError::ErrorCode.new("ERROR_MEMBER_IN_ALIAS",0x00000562,"The specified account name is already a member of the group.")

    # (0x00000563) The specified local group already exists.
    ERROR_ALIAS_EXISTS = WindowsError::ErrorCode.new("ERROR_ALIAS_EXISTS",0x00000563,"The specified local group already exists.")

    # (0x00000564) Logon failure: The user has not been granted the requested logon type at this computer.
    ERROR_LOGON_NOT_GRANTED = WindowsError::ErrorCode.new("ERROR_LOGON_NOT_GRANTED",0x00000564,"Logon failure: The user has not been granted the requested logon type at this computer.")

    # (0x00000565) The maximum number of secrets that may be stored in a single system has been exceeded.
    ERROR_TOO_MANY_SECRETS = WindowsError::ErrorCode.new("ERROR_TOO_MANY_SECRETS",0x00000565,"The maximum number of secrets that may be stored in a single system has been exceeded.")

    # (0x00000566) The length of a secret exceeds the maximum length allowed.
    ERROR_SECRET_TOO_LONG = WindowsError::ErrorCode.new("ERROR_SECRET_TOO_LONG",0x00000566,"The length of a secret exceeds the maximum length allowed.")

    # (0x00000567) The local security authority database contains an internal inconsistency.
    ERROR_INTERNAL_DB_ERROR = WindowsError::ErrorCode.new("ERROR_INTERNAL_DB_ERROR",0x00000567,"The local security authority database contains an internal inconsistency.")

    # (0x00000568) During a logon attempt, the user's security context accumulated too many SIDs.
    ERROR_TOO_MANY_CONTEXT_IDS = WindowsError::ErrorCode.new("ERROR_TOO_MANY_CONTEXT_IDS",0x00000568,"During a logon attempt, the user's security context accumulated too many SIDs.")

    # (0x00000569) Logon failure: The user has not been granted the requested logon type at this computer.
    ERROR_LOGON_TYPE_NOT_GRANTED = WindowsError::ErrorCode.new("ERROR_LOGON_TYPE_NOT_GRANTED",0x00000569,"Logon failure: The user has not been granted the requested logon type at this computer.")

    # (0x0000056A) A cross-encrypted password is necessary to change a user password.
    ERROR_NT_CROSS_ENCRYPTION_REQUIRED = WindowsError::ErrorCode.new("ERROR_NT_CROSS_ENCRYPTION_REQUIRED",0x0000056A,"A cross-encrypted password is necessary to change a user password.")

    # (0x0000056B) A member could not be added to or removed from the local group because the member does not exist.
    ERROR_NO_SUCH_MEMBER = WindowsError::ErrorCode.new("ERROR_NO_SUCH_MEMBER",0x0000056B,"A member could not be added to or removed from the local group because the member does not exist.")

    # (0x0000056C) A new member could not be added to a local group because the member has the wrong account type.
    ERROR_INVALID_MEMBER = WindowsError::ErrorCode.new("ERROR_INVALID_MEMBER",0x0000056C,"A new member could not be added to a local group because the member has the wrong account type.")

    # (0x0000056D) Too many SIDs have been specified.
    ERROR_TOO_MANY_SIDS = WindowsError::ErrorCode.new("ERROR_TOO_MANY_SIDS",0x0000056D,"Too many SIDs have been specified.")

    # (0x0000056E) A cross-encrypted password is necessary to change this user password.
    ERROR_LM_CROSS_ENCRYPTION_REQUIRED = WindowsError::ErrorCode.new("ERROR_LM_CROSS_ENCRYPTION_REQUIRED",0x0000056E,"A cross-encrypted password is necessary to change this user password.")

    # (0x0000056F) Indicates an ACL contains no inheritable components.
    ERROR_NO_INHERITANCE = WindowsError::ErrorCode.new("ERROR_NO_INHERITANCE",0x0000056F,"Indicates an ACL contains no inheritable components.")

    # (0x00000570) The file or directory is corrupted and unreadable.
    ERROR_FILE_CORRUPT = WindowsError::ErrorCode.new("ERROR_FILE_CORRUPT",0x00000570,"The file or directory is corrupted and unreadable.")

    # (0x00000571) The disk structure is corrupted and unreadable.
    ERROR_DISK_CORRUPT = WindowsError::ErrorCode.new("ERROR_DISK_CORRUPT",0x00000571,"The disk structure is corrupted and unreadable.")

    # (0x00000572) There is no user session key for the specified logon session.
    ERROR_NO_USER_SESSION_KEY = WindowsError::ErrorCode.new("ERROR_NO_USER_SESSION_KEY",0x00000572,"There is no user session key for the specified logon session.")

    # (0x00000573) The service being accessed is licensed for a particular number of connections. No more connections can be made to the service at this time because the service has accepted the maximum number of connections.
    ERROR_LICENSE_QUOTA_EXCEEDED = WindowsError::ErrorCode.new("ERROR_LICENSE_QUOTA_EXCEEDED",0x00000573,"The service being accessed is licensed for a particular number of connections. No more connections can be made to the service at this time because the service has accepted the maximum number of connections.")

    # (0x00000574) Logon failure: The target account name is incorrect.
    ERROR_WRONG_TARGET_NAME = WindowsError::ErrorCode.new("ERROR_WRONG_TARGET_NAME",0x00000574,"Logon failure: The target account name is incorrect.")

    # (0x00000575) Mutual authentication failed. The server's password is out of date at the domain controller.
    ERROR_MUTUAL_AUTH_FAILED = WindowsError::ErrorCode.new("ERROR_MUTUAL_AUTH_FAILED",0x00000575,"Mutual authentication failed. The server's password is out of date at the domain controller.")

    # (0x00000576) There is a time and/or date difference between the client and server.
    ERROR_TIME_SKEW = WindowsError::ErrorCode.new("ERROR_TIME_SKEW",0x00000576,"There is a time and/or date difference between the client and server.")

    # (0x00000577) This operation cannot be performed on the current domain.
    ERROR_CURRENT_DOMAIN_NOT_ALLOWED = WindowsError::ErrorCode.new("ERROR_CURRENT_DOMAIN_NOT_ALLOWED",0x00000577,"This operation cannot be performed on the current domain.")

    # (0x00000578) Invalid window handle.
    ERROR_INVALID_WINDOW_HANDLE = WindowsError::ErrorCode.new("ERROR_INVALID_WINDOW_HANDLE",0x00000578,"Invalid window handle.")

    # (0x00000579) Invalid menu handle.
    ERROR_INVALID_MENU_HANDLE = WindowsError::ErrorCode.new("ERROR_INVALID_MENU_HANDLE",0x00000579,"Invalid menu handle.")

    # (0x0000057A) Invalid cursor handle.
    ERROR_INVALID_CURSOR_HANDLE = WindowsError::ErrorCode.new("ERROR_INVALID_CURSOR_HANDLE",0x0000057A,"Invalid cursor handle.")

    # (0x0000057B) Invalid accelerator table handle.
    ERROR_INVALID_ACCEL_HANDLE = WindowsError::ErrorCode.new("ERROR_INVALID_ACCEL_HANDLE",0x0000057B,"Invalid accelerator table handle.")

    # (0x0000057C) Invalid hook handle.
    ERROR_INVALID_HOOK_HANDLE = WindowsError::ErrorCode.new("ERROR_INVALID_HOOK_HANDLE",0x0000057C,"Invalid hook handle.")

    # (0x0000057D) Invalid handle to a multiple-window position structure.
    ERROR_INVALID_DWP_HANDLE = WindowsError::ErrorCode.new("ERROR_INVALID_DWP_HANDLE",0x0000057D,"Invalid handle to a multiple-window position structure.")

    # (0x0000057E) Cannot create a top-level child window.
    ERROR_TLW_WITH_WSCHILD = WindowsError::ErrorCode.new("ERROR_TLW_WITH_WSCHILD",0x0000057E,"Cannot create a top-level child window.")

    # (0x0000057F) Cannot find window class.
    ERROR_CANNOT_FIND_WND_CLASS = WindowsError::ErrorCode.new("ERROR_CANNOT_FIND_WND_CLASS",0x0000057F,"Cannot find window class.")

    # (0x00000580) Invalid window; it belongs to other thread.
    ERROR_WINDOW_OF_OTHER_THREAD = WindowsError::ErrorCode.new("ERROR_WINDOW_OF_OTHER_THREAD",0x00000580,"Invalid window; it belongs to other thread.")

    # (0x00000581) Hot key is already registered.
    ERROR_HOTKEY_ALREADY_REGISTERED = WindowsError::ErrorCode.new("ERROR_HOTKEY_ALREADY_REGISTERED",0x00000581,"Hot key is already registered.")

    # (0x00000582) Class already exists.
    ERROR_CLASS_ALREADY_EXISTS = WindowsError::ErrorCode.new("ERROR_CLASS_ALREADY_EXISTS",0x00000582,"Class already exists.")

    # (0x00000583) Class does not exist.
    ERROR_CLASS_DOES_NOT_EXIST = WindowsError::ErrorCode.new("ERROR_CLASS_DOES_NOT_EXIST",0x00000583,"Class does not exist.")

    # (0x00000584) Class still has open windows.
    ERROR_CLASS_HAS_WINDOWS = WindowsError::ErrorCode.new("ERROR_CLASS_HAS_WINDOWS",0x00000584,"Class still has open windows.")

    # (0x00000585) Invalid index.
    ERROR_INVALID_INDEX = WindowsError::ErrorCode.new("ERROR_INVALID_INDEX",0x00000585,"Invalid index.")

    # (0x00000586) Invalid icon handle.
    ERROR_INVALID_ICON_HANDLE = WindowsError::ErrorCode.new("ERROR_INVALID_ICON_HANDLE",0x00000586,"Invalid icon handle.")

    # (0x00000587) Using private DIALOG window words.
    ERROR_PRIVATE_DIALOG_INDEX = WindowsError::ErrorCode.new("ERROR_PRIVATE_DIALOG_INDEX",0x00000587,"Using private DIALOG window words.")

    # (0x00000588) The list box identifier was not found.
    ERROR_LISTBOX_ID_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_LISTBOX_ID_NOT_FOUND",0x00000588,"The list box identifier was not found.")

    # (0x00000589) No wildcards were found.
    ERROR_NO_WILDCARD_CHARACTERS = WindowsError::ErrorCode.new("ERROR_NO_WILDCARD_CHARACTERS",0x00000589,"No wildcards were found.")

    # (0x0000058A) Thread does not have a clipboard open.
    ERROR_CLIPBOARD_NOT_OPEN = WindowsError::ErrorCode.new("ERROR_CLIPBOARD_NOT_OPEN",0x0000058A,"Thread does not have a clipboard open.")

    # (0x0000058B) Hot key is not registered.
    ERROR_HOTKEY_NOT_REGISTERED = WindowsError::ErrorCode.new("ERROR_HOTKEY_NOT_REGISTERED",0x0000058B,"Hot key is not registered.")

    # (0x0000058C) The window is not a valid dialog window.
    ERROR_WINDOW_NOT_DIALOG = WindowsError::ErrorCode.new("ERROR_WINDOW_NOT_DIALOG",0x0000058C,"The window is not a valid dialog window.")

    # (0x0000058D) Control ID not found.
    ERROR_CONTROL_ID_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_CONTROL_ID_NOT_FOUND",0x0000058D,"Control ID not found.")

    # (0x0000058E) Invalid message for a combo box because it does not have an edit control.
    ERROR_INVALID_COMBOBOX_MESSAGE = WindowsError::ErrorCode.new("ERROR_INVALID_COMBOBOX_MESSAGE",0x0000058E,"Invalid message for a combo box because it does not have an edit control.")

    # (0x0000058F) The window is not a combo box.
    ERROR_WINDOW_NOT_COMBOBOX = WindowsError::ErrorCode.new("ERROR_WINDOW_NOT_COMBOBOX",0x0000058F,"The window is not a combo box.")

    # (0x00000590) Height must be less than 256.
    ERROR_INVALID_EDIT_HEIGHT = WindowsError::ErrorCode.new("ERROR_INVALID_EDIT_HEIGHT",0x00000590,"Height must be less than 256.")

    # (0x00000591) Invalid device context (DC) handle.
    ERROR_DC_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_DC_NOT_FOUND",0x00000591,"Invalid device context (DC) handle.")

    # (0x00000592) Invalid hook procedure type.
    ERROR_INVALID_HOOK_FILTER = WindowsError::ErrorCode.new("ERROR_INVALID_HOOK_FILTER",0x00000592,"Invalid hook procedure type.")

    # (0x00000593) Invalid hook procedure.
    ERROR_INVALID_FILTER_PROC = WindowsError::ErrorCode.new("ERROR_INVALID_FILTER_PROC",0x00000593,"Invalid hook procedure.")

    # (0x00000594) Cannot set nonlocal hook without a module handle.
    ERROR_HOOK_NEEDS_HMOD = WindowsError::ErrorCode.new("ERROR_HOOK_NEEDS_HMOD",0x00000594,"Cannot set nonlocal hook without a module handle.")

    # (0x00000595) This hook procedure can only be set globally.
    ERROR_GLOBAL_ONLY_HOOK = WindowsError::ErrorCode.new("ERROR_GLOBAL_ONLY_HOOK",0x00000595,"This hook procedure can only be set globally.")

    # (0x00000596) The journal hook procedure is already installed.
    ERROR_JOURNAL_HOOK_SET = WindowsError::ErrorCode.new("ERROR_JOURNAL_HOOK_SET",0x00000596,"The journal hook procedure is already installed.")

    # (0x00000597) The hook procedure is not installed.
    ERROR_HOOK_NOT_INSTALLED = WindowsError::ErrorCode.new("ERROR_HOOK_NOT_INSTALLED",0x00000597,"The hook procedure is not installed.")

    # (0x00000598) Invalid message for single-selection list box.
    ERROR_INVALID_LB_MESSAGE = WindowsError::ErrorCode.new("ERROR_INVALID_LB_MESSAGE",0x00000598,"Invalid message for single-selection list box.")

    # (0x00000599) LB_SETCOUNT sent to non-lazy list box.
    ERROR_SETCOUNT_ON_BAD_LB = WindowsError::ErrorCode.new("ERROR_SETCOUNT_ON_BAD_LB",0x00000599,"LB_SETCOUNT sent to non-lazy list box.")

    # (0x0000059A) This list box does not support tab stops.
    ERROR_LB_WITHOUT_TABSTOPS = WindowsError::ErrorCode.new("ERROR_LB_WITHOUT_TABSTOPS",0x0000059A,"This list box does not support tab stops.")

    # (0x0000059B) Cannot destroy object created by another thread.
    ERROR_DESTROY_OBJECT_OF_OTHER_THREAD = WindowsError::ErrorCode.new("ERROR_DESTROY_OBJECT_OF_OTHER_THREAD",0x0000059B,"Cannot destroy object created by another thread.")

    # (0x0000059C) Child windows cannot have menus.
    ERROR_CHILD_WINDOW_MENU = WindowsError::ErrorCode.new("ERROR_CHILD_WINDOW_MENU",0x0000059C,"Child windows cannot have menus.")

    # (0x0000059D) The window does not have a system menu.
    ERROR_NO_SYSTEM_MENU = WindowsError::ErrorCode.new("ERROR_NO_SYSTEM_MENU",0x0000059D,"The window does not have a system menu.")

    # (0x0000059E) Invalid message box style.
    ERROR_INVALID_MSGBOX_STYLE = WindowsError::ErrorCode.new("ERROR_INVALID_MSGBOX_STYLE",0x0000059E,"Invalid message box style.")

    # (0x0000059F) Invalid system-wide (SPI_*) parameter.
    ERROR_INVALID_SPI_VALUE = WindowsError::ErrorCode.new("ERROR_INVALID_SPI_VALUE",0x0000059F,"Invalid system-wide (SPI_*) parameter.")

    # (0x000005A0) Screen already locked.
    ERROR_SCREEN_ALREADY_LOCKED = WindowsError::ErrorCode.new("ERROR_SCREEN_ALREADY_LOCKED",0x000005A0,"Screen already locked.")

    # (0x000005A1) All handles to windows in a multiple-window position structure must have the same parent.
    ERROR_HWNDS_HAVE_DIFF_PARENT = WindowsError::ErrorCode.new("ERROR_HWNDS_HAVE_DIFF_PARENT",0x000005A1,"All handles to windows in a multiple-window position structure must have the same parent.")

    # (0x000005A2) The window is not a child window.
    ERROR_NOT_CHILD_WINDOW = WindowsError::ErrorCode.new("ERROR_NOT_CHILD_WINDOW",0x000005A2,"The window is not a child window.")

    # (0x000005A3) Invalid GW_* command.
    ERROR_INVALID_GW_COMMAND = WindowsError::ErrorCode.new("ERROR_INVALID_GW_COMMAND",0x000005A3,"Invalid GW_* command.")

    # (0x000005A4) Invalid thread identifier.
    ERROR_INVALID_THREAD_ID = WindowsError::ErrorCode.new("ERROR_INVALID_THREAD_ID",0x000005A4,"Invalid thread identifier.")

    # (0x000005A5) Cannot process a message from a window that is not a multiple document interface (MDI) window.
    ERROR_NON_MDICHILD_WINDOW = WindowsError::ErrorCode.new("ERROR_NON_MDICHILD_WINDOW",0x000005A5,"Cannot process a message from a window that is not a multiple document interface (MDI) window.")

    # (0x000005A6) Pop-up menu already active.
    ERROR_POPUP_ALREADY_ACTIVE = WindowsError::ErrorCode.new("ERROR_POPUP_ALREADY_ACTIVE",0x000005A6,"Pop-up menu already active.")

    # (0x000005A7) The window does not have scroll bars.
    ERROR_NO_SCROLLBARS = WindowsError::ErrorCode.new("ERROR_NO_SCROLLBARS",0x000005A7,"The window does not have scroll bars.")

    # (0x000005A8) Scroll bar range cannot be greater than MAXLONG.
    ERROR_INVALID_SCROLLBAR_RANGE = WindowsError::ErrorCode.new("ERROR_INVALID_SCROLLBAR_RANGE",0x000005A8,"Scroll bar range cannot be greater than MAXLONG.")

    # (0x000005A9) Cannot show or remove the window in the way specified.
    ERROR_INVALID_SHOWWIN_COMMAND = WindowsError::ErrorCode.new("ERROR_INVALID_SHOWWIN_COMMAND",0x000005A9,"Cannot show or remove the window in the way specified.")

    # (0x000005AA) Insufficient system resources exist to complete the requested service.
    ERROR_NO_SYSTEM_RESOURCES = WindowsError::ErrorCode.new("ERROR_NO_SYSTEM_RESOURCES",0x000005AA,"Insufficient system resources exist to complete the requested service.")

    # (0x000005AB) Insufficient system resources exist to complete the requested service.
    ERROR_NONPAGED_SYSTEM_RESOURCES = WindowsError::ErrorCode.new("ERROR_NONPAGED_SYSTEM_RESOURCES",0x000005AB,"Insufficient system resources exist to complete the requested service.")

    # (0x000005AC) Insufficient system resources exist to complete the requested service.
    ERROR_PAGED_SYSTEM_RESOURCES = WindowsError::ErrorCode.new("ERROR_PAGED_SYSTEM_RESOURCES",0x000005AC,"Insufficient system resources exist to complete the requested service.")

    # (0x000005AD) Insufficient quota to complete the requested service.
    ERROR_WORKING_SET_QUOTA = WindowsError::ErrorCode.new("ERROR_WORKING_SET_QUOTA",0x000005AD,"Insufficient quota to complete the requested service.")

    # (0x000005AE) Insufficient quota to complete the requested service.
    ERROR_PAGEFILE_QUOTA = WindowsError::ErrorCode.new("ERROR_PAGEFILE_QUOTA",0x000005AE,"Insufficient quota to complete the requested service.")

    # (0x000005AF) The paging file is too small for this operation to complete.
    ERROR_COMMITMENT_LIMIT = WindowsError::ErrorCode.new("ERROR_COMMITMENT_LIMIT",0x000005AF,"The paging file is too small for this operation to complete.")

    # (0x000005B0) A menu item was not found.
    ERROR_MENU_ITEM_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_MENU_ITEM_NOT_FOUND",0x000005B0,"A menu item was not found.")

    # (0x000005B1) Invalid keyboard layout handle.
    ERROR_INVALID_KEYBOARD_HANDLE = WindowsError::ErrorCode.new("ERROR_INVALID_KEYBOARD_HANDLE",0x000005B1,"Invalid keyboard layout handle.")

    # (0x000005B2) Hook type not allowed.
    ERROR_HOOK_TYPE_NOT_ALLOWED = WindowsError::ErrorCode.new("ERROR_HOOK_TYPE_NOT_ALLOWED",0x000005B2,"Hook type not allowed.")

    # (0x000005B3) This operation requires an interactive window station.
    ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION = WindowsError::ErrorCode.new("ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION",0x000005B3,"This operation requires an interactive window station.")

    # (0x000005B4) This operation returned because the time-out period expired.
    ERROR_TIMEOUT = WindowsError::ErrorCode.new("ERROR_TIMEOUT",0x000005B4,"This operation returned because the time-out period expired.")

    # (0x000005B5) Invalid monitor handle.
    ERROR_INVALID_MONITOR_HANDLE = WindowsError::ErrorCode.new("ERROR_INVALID_MONITOR_HANDLE",0x000005B5,"Invalid monitor handle.")

    # (0x000005B6) Incorrect size argument.
    ERROR_INCORRECT_SIZE = WindowsError::ErrorCode.new("ERROR_INCORRECT_SIZE",0x000005B6,"Incorrect size argument.")

    # (0x000005B7) The symbolic link cannot be followed because its type is disabled.
    ERROR_SYMLINK_CLASS_DISABLED = WindowsError::ErrorCode.new("ERROR_SYMLINK_CLASS_DISABLED",0x000005B7,"The symbolic link cannot be followed because its type is disabled.")

    # (0x000005B8) This application does not support the current operation on symbolic links.
    ERROR_SYMLINK_NOT_SUPPORTED = WindowsError::ErrorCode.new("ERROR_SYMLINK_NOT_SUPPORTED",0x000005B8,"This application does not support the current operation on symbolic links.")

    # (0x000005DC) The event log file is corrupted.
    ERROR_EVENTLOG_FILE_CORRUPT = WindowsError::ErrorCode.new("ERROR_EVENTLOG_FILE_CORRUPT",0x000005DC,"The event log file is corrupted.")

    # (0x000005DD) No event log file could be opened, so the event logging service did not start.
    ERROR_EVENTLOG_CANT_START = WindowsError::ErrorCode.new("ERROR_EVENTLOG_CANT_START",0x000005DD,"No event log file could be opened, so the event logging service did not start.")

    # (0x000005DE) The event log file is full.
    ERROR_LOG_FILE_FULL = WindowsError::ErrorCode.new("ERROR_LOG_FILE_FULL",0x000005DE,"The event log file is full.")

    # (0x000005DF) The event log file has changed between read operations.
    ERROR_EVENTLOG_FILE_CHANGED = WindowsError::ErrorCode.new("ERROR_EVENTLOG_FILE_CHANGED",0x000005DF,"The event log file has changed between read operations.")

    # (0x0000060E) The specified task name is invalid.
    ERROR_INVALID_TASK_NAME = WindowsError::ErrorCode.new("ERROR_INVALID_TASK_NAME",0x0000060E,"The specified task name is invalid.")

    # (0x0000060F) The specified task index is invalid.
    ERROR_INVALID_TASK_INDEX = WindowsError::ErrorCode.new("ERROR_INVALID_TASK_INDEX",0x0000060F,"The specified task index is invalid.")

    # (0x00000610) The specified thread is already joining a task.
    ERROR_THREAD_ALREADY_IN_TASK = WindowsError::ErrorCode.new("ERROR_THREAD_ALREADY_IN_TASK",0x00000610,"The specified thread is already joining a task.")

    # (0x00000641) The Windows Installer service could not be accessed. This can occur if the Windows Installer is not correctly installed. Contact your support personnel for assistance.
    ERROR_INSTALL_SERVICE_FAILURE = WindowsError::ErrorCode.new("ERROR_INSTALL_SERVICE_FAILURE",0x00000641,"The Windows Installer service could not be accessed. This can occur if the Windows Installer is not correctly installed. Contact your support personnel for assistance.")

    # (0x00000642) User canceled installation.
    ERROR_INSTALL_USEREXIT = WindowsError::ErrorCode.new("ERROR_INSTALL_USEREXIT",0x00000642,"User canceled installation.")

    # (0x00000643) Fatal error during installation.
    ERROR_INSTALL_FAILURE = WindowsError::ErrorCode.new("ERROR_INSTALL_FAILURE",0x00000643,"Fatal error during installation.")

    # (0x00000644) Installation suspended, incomplete.
    ERROR_INSTALL_SUSPEND = WindowsError::ErrorCode.new("ERROR_INSTALL_SUSPEND",0x00000644,"Installation suspended, incomplete.")

    # (0x00000645) This action is valid only for products that are currently installed.
    ERROR_UNKNOWN_PRODUCT = WindowsError::ErrorCode.new("ERROR_UNKNOWN_PRODUCT",0x00000645,"This action is valid only for products that are currently installed.")

    # (0x00000646) Feature ID not registered.
    ERROR_UNKNOWN_FEATURE = WindowsError::ErrorCode.new("ERROR_UNKNOWN_FEATURE",0x00000646,"Feature ID not registered.")

    # (0x00000647) Component ID not registered.
    ERROR_UNKNOWN_COMPONENT = WindowsError::ErrorCode.new("ERROR_UNKNOWN_COMPONENT",0x00000647,"Component ID not registered.")

    # (0x00000648) Unknown property.
    ERROR_UNKNOWN_PROPERTY = WindowsError::ErrorCode.new("ERROR_UNKNOWN_PROPERTY",0x00000648,"Unknown property.")

    # (0x00000649) Handle is in an invalid state.
    ERROR_INVALID_HANDLE_STATE = WindowsError::ErrorCode.new("ERROR_INVALID_HANDLE_STATE",0x00000649,"Handle is in an invalid state.")

    # (0x0000064A) The configuration data for this product is corrupt. Contact your support personnel.
    ERROR_BAD_CONFIGURATION = WindowsError::ErrorCode.new("ERROR_BAD_CONFIGURATION",0x0000064A,"The configuration data for this product is corrupt. Contact your support personnel.")

    # (0x0000064B) Component qualifier not present.
    ERROR_INDEX_ABSENT = WindowsError::ErrorCode.new("ERROR_INDEX_ABSENT",0x0000064B,"Component qualifier not present.")

    # (0x0000064C) The installation source for this product is not available. Verify that the source exists and that you can access it.
    ERROR_INSTALL_SOURCE_ABSENT = WindowsError::ErrorCode.new("ERROR_INSTALL_SOURCE_ABSENT",0x0000064C,"The installation source for this product is not available. Verify that the source exists and that you can access it.")

    # (0x0000064D) This installation package cannot be installed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service.
    ERROR_INSTALL_PACKAGE_VERSION = WindowsError::ErrorCode.new("ERROR_INSTALL_PACKAGE_VERSION",0x0000064D,"This installation package cannot be installed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service.")

    # (0x0000064E) Product is uninstalled.
    ERROR_PRODUCT_UNINSTALLED = WindowsError::ErrorCode.new("ERROR_PRODUCT_UNINSTALLED",0x0000064E,"Product is uninstalled.")

    # (0x0000064F) SQL query syntax invalid or unsupported.
    ERROR_BAD_QUERY_SYNTAX = WindowsError::ErrorCode.new("ERROR_BAD_QUERY_SYNTAX",0x0000064F,"SQL query syntax invalid or unsupported.")

    # (0x00000650) Record field does not exist.
    ERROR_INVALID_FIELD = WindowsError::ErrorCode.new("ERROR_INVALID_FIELD",0x00000650,"Record field does not exist.")

    # (0x00000651) The device has been removed.
    ERROR_DEVICE_REMOVED = WindowsError::ErrorCode.new("ERROR_DEVICE_REMOVED",0x00000651,"The device has been removed.")

    # (0x00000652) Another installation is already in progress. Complete that installation before proceeding with this install.
    ERROR_INSTALL_ALREADY_RUNNING = WindowsError::ErrorCode.new("ERROR_INSTALL_ALREADY_RUNNING",0x00000652,"Another installation is already in progress. Complete that installation before proceeding with this install.")

    # (0x00000653) This installation package could not be opened. Verify that the package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer package.
    ERROR_INSTALL_PACKAGE_OPEN_FAILED = WindowsError::ErrorCode.new("ERROR_INSTALL_PACKAGE_OPEN_FAILED",0x00000653,"This installation package could not be opened. Verify that the package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer package.")

    # (0x00000654) This installation package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer package.
    ERROR_INSTALL_PACKAGE_INVALID = WindowsError::ErrorCode.new("ERROR_INSTALL_PACKAGE_INVALID",0x00000654,"This installation package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer package.")

    # (0x00000655) There was an error starting the Windows Installer service user interface. Contact your support personnel.
    ERROR_INSTALL_UI_FAILURE = WindowsError::ErrorCode.new("ERROR_INSTALL_UI_FAILURE",0x00000655,"There was an error starting the Windows Installer service user interface. Contact your support personnel.")

    # (0x00000656) Error opening installation log file. Verify that the specified log file location exists and that you can write to it.
    ERROR_INSTALL_LOG_FAILURE = WindowsError::ErrorCode.new("ERROR_INSTALL_LOG_FAILURE",0x00000656,"Error opening installation log file. Verify that the specified log file location exists and that you can write to it.")

    # (0x00000657) The language of this installation package is not supported by your system.
    ERROR_INSTALL_LANGUAGE_UNSUPPORTED = WindowsError::ErrorCode.new("ERROR_INSTALL_LANGUAGE_UNSUPPORTED",0x00000657,"The language of this installation package is not supported by your system.")

    # (0x00000658) Error applying transforms. Verify that the specified transform paths are valid.
    ERROR_INSTALL_TRANSFORM_FAILURE = WindowsError::ErrorCode.new("ERROR_INSTALL_TRANSFORM_FAILURE",0x00000658,"Error applying transforms. Verify that the specified transform paths are valid.")

    # (0x00000659) This installation is forbidden by system policy. Contact your system administrator.
    ERROR_INSTALL_PACKAGE_REJECTED = WindowsError::ErrorCode.new("ERROR_INSTALL_PACKAGE_REJECTED",0x00000659,"This installation is forbidden by system policy. Contact your system administrator.")

    # (0x0000065A) Function could not be executed.
    ERROR_FUNCTION_NOT_CALLED = WindowsError::ErrorCode.new("ERROR_FUNCTION_NOT_CALLED",0x0000065A,"Function could not be executed.")

    # (0x0000065B) Function failed during execution.
    ERROR_FUNCTION_FAILED = WindowsError::ErrorCode.new("ERROR_FUNCTION_FAILED",0x0000065B,"Function failed during execution.")

    # (0x0000065C) Invalid or unknown table specified.
    ERROR_INVALID_TABLE = WindowsError::ErrorCode.new("ERROR_INVALID_TABLE",0x0000065C,"Invalid or unknown table specified.")

    # (0x0000065D) Data supplied is of wrong type.
    ERROR_DATATYPE_MISMATCH = WindowsError::ErrorCode.new("ERROR_DATATYPE_MISMATCH",0x0000065D,"Data supplied is of wrong type.")

    # (0x0000065E) Data of this type is not supported.
    ERROR_UNSUPPORTED_TYPE = WindowsError::ErrorCode.new("ERROR_UNSUPPORTED_TYPE",0x0000065E,"Data of this type is not supported.")

    # (0x0000065F) The Windows Installer service failed to start. Contact your support personnel.
    ERROR_CREATE_FAILED = WindowsError::ErrorCode.new("ERROR_CREATE_FAILED",0x0000065F,"The Windows Installer service failed to start. Contact your support personnel.")

    # (0x00000660) The Temp folder is on a drive that is full or is inaccessible. Free up space on the drive or verify that you have write permission on the Temp folder.
    ERROR_INSTALL_TEMP_UNWRITABLE = WindowsError::ErrorCode.new("ERROR_INSTALL_TEMP_UNWRITABLE",0x00000660,"The Temp folder is on a drive that is full or is inaccessible. Free up space on the drive or verify that you have write permission on the Temp folder.")

    # (0x00000661) This installation package is not supported by this processor type. Contact your product vendor.
    ERROR_INSTALL_PLATFORM_UNSUPPORTED = WindowsError::ErrorCode.new("ERROR_INSTALL_PLATFORM_UNSUPPORTED",0x00000661,"This installation package is not supported by this processor type. Contact your product vendor.")

    # (0x00000662) Component not used on this computer.
    ERROR_INSTALL_NOTUSED = WindowsError::ErrorCode.new("ERROR_INSTALL_NOTUSED",0x00000662,"Component not used on this computer.")

    # (0x00000663) This update package could not be opened. Verify that the update package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer update package.
    ERROR_PATCH_PACKAGE_OPEN_FAILED = WindowsError::ErrorCode.new("ERROR_PATCH_PACKAGE_OPEN_FAILED",0x00000663,"This update package could not be opened. Verify that the update package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer update package.")

    # (0x00000664) This update package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer update package.
    ERROR_PATCH_PACKAGE_INVALID = WindowsError::ErrorCode.new("ERROR_PATCH_PACKAGE_INVALID",0x00000664,"This update package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer update package.")

    # (0x00000665) This update package cannot be processed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service.
    ERROR_PATCH_PACKAGE_UNSUPPORTED = WindowsError::ErrorCode.new("ERROR_PATCH_PACKAGE_UNSUPPORTED",0x00000665,"This update package cannot be processed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service.")

    # (0x00000666) Another version of this product is already installed. Installation of this version cannot continue. To configure or remove the existing version of this product, use Add/Remove Programs in Control Panel.
    ERROR_PRODUCT_VERSION = WindowsError::ErrorCode.new("ERROR_PRODUCT_VERSION",0x00000666,"Another version of this product is already installed. Installation of this version cannot continue. To configure or remove the existing version of this product, use Add/Remove Programs in Control Panel.")

    # (0x00000667) Invalid command-line argument. Consult the Windows Installer SDK for detailed command line help.
    ERROR_INVALID_COMMAND_LINE = WindowsError::ErrorCode.new("ERROR_INVALID_COMMAND_LINE",0x00000667,"Invalid command-line argument. Consult the Windows Installer SDK for detailed command line help.")

    # (0x00000668) Only administrators have permission to add, remove, or configure server software during a Terminal Services remote session. If you want to install or configure software on the server, contact your network administrator.
    ERROR_INSTALL_REMOTE_DISALLOWED = WindowsError::ErrorCode.new("ERROR_INSTALL_REMOTE_DISALLOWED",0x00000668,"Only administrators have permission to add, remove, or configure server software during a Terminal Services remote session. If you want to install or configure software on the server, contact your network administrator.")

    # (0x00000669) The requested operation completed successfully. The system will be restarted so the changes can take effect.
    ERROR_SUCCESS_REBOOT_INITIATED = WindowsError::ErrorCode.new("ERROR_SUCCESS_REBOOT_INITIATED",0x00000669,"The requested operation completed successfully. The system will be restarted so the changes can take effect.")

    # (0x0000066A) The upgrade cannot be installed by the Windows Installer service because the program to be upgraded may be missing, or the upgrade may update a different version of the program. Verify that the program to be upgraded exists on your computer and that you have the correct upgrade.
    ERROR_PATCH_TARGET_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_PATCH_TARGET_NOT_FOUND",0x0000066A,"The upgrade cannot be installed by the Windows Installer service because the program to be upgraded may be missing, or the upgrade may update a different version of the program. Verify that the program to be upgraded exists on your computer and that you have the correct upgrade.")

    # (0x0000066B) The update package is not permitted by a software restriction policy.
    ERROR_PATCH_PACKAGE_REJECTED = WindowsError::ErrorCode.new("ERROR_PATCH_PACKAGE_REJECTED",0x0000066B,"The update package is not permitted by a software restriction policy.")

    # (0x0000066C) One or more customizations are not permitted by a software restriction policy.
    ERROR_INSTALL_TRANSFORM_REJECTED = WindowsError::ErrorCode.new("ERROR_INSTALL_TRANSFORM_REJECTED",0x0000066C,"One or more customizations are not permitted by a software restriction policy.")

    # (0x0000066D) The Windows Installer does not permit installation from a Remote Desktop Connection.
    ERROR_INSTALL_REMOTE_PROHIBITED = WindowsError::ErrorCode.new("ERROR_INSTALL_REMOTE_PROHIBITED",0x0000066D,"The Windows Installer does not permit installation from a Remote Desktop Connection.")

    # (0x0000066E) Uninstallation of the update package is not supported.
    ERROR_PATCH_REMOVAL_UNSUPPORTED = WindowsError::ErrorCode.new("ERROR_PATCH_REMOVAL_UNSUPPORTED",0x0000066E,"Uninstallation of the update package is not supported.")

    # (0x0000066F) The update is not applied to this product.
    ERROR_UNKNOWN_PATCH = WindowsError::ErrorCode.new("ERROR_UNKNOWN_PATCH",0x0000066F,"The update is not applied to this product.")

    # (0x00000670) No valid sequence could be found for the set of updates.
    ERROR_PATCH_NO_SEQUENCE = WindowsError::ErrorCode.new("ERROR_PATCH_NO_SEQUENCE",0x00000670,"No valid sequence could be found for the set of updates.")

    # (0x00000671) Update removal was disallowed by policy.
    ERROR_PATCH_REMOVAL_DISALLOWED = WindowsError::ErrorCode.new("ERROR_PATCH_REMOVAL_DISALLOWED",0x00000671,"Update removal was disallowed by policy.")

    # (0x00000672) The XML update data is invalid.
    ERROR_INVALID_PATCH_XML = WindowsError::ErrorCode.new("ERROR_INVALID_PATCH_XML",0x00000672,"The XML update data is invalid.")

    # (0x00000673) Windows Installer does not permit updating of managed advertised products. At least one feature of the product must be installed before applying the update.
    ERROR_PATCH_MANAGED_ADVERTISED_PRODUCT = WindowsError::ErrorCode.new("ERROR_PATCH_MANAGED_ADVERTISED_PRODUCT",0x00000673,"Windows Installer does not permit updating of managed advertised products. At least one feature of the product must be installed before applying the update.")

    # (0x00000674) The Windows Installer service is not accessible in Safe Mode. Try again when your computer is not in Safe Mode or you can use System Restore to return your machine to a previous good state.
    ERROR_INSTALL_SERVICE_SAFEBOOT = WindowsError::ErrorCode.new("ERROR_INSTALL_SERVICE_SAFEBOOT",0x00000674,"The Windows Installer service is not accessible in Safe Mode. Try again when your computer is not in Safe Mode or you can use System Restore to return your machine to a previous good state.")

    # (0x000006A4) The string binding is invalid.
    RPC_S_INVALID_STRING_BINDING = WindowsError::ErrorCode.new("RPC_S_INVALID_STRING_BINDING",0x000006A4,"The string binding is invalid.")

    # (0x000006A5) The binding handle is not the correct type.
    RPC_S_WRONG_KIND_OF_BINDING = WindowsError::ErrorCode.new("RPC_S_WRONG_KIND_OF_BINDING",0x000006A5,"The binding handle is not the correct type.")

    # (0x000006A6) The binding handle is invalid.
    RPC_S_INVALID_BINDING = WindowsError::ErrorCode.new("RPC_S_INVALID_BINDING",0x000006A6,"The binding handle is invalid.")

    # (0x000006A7) The RPC protocol sequence is not supported.
    RPC_S_PROTSEQ_NOT_SUPPORTED = WindowsError::ErrorCode.new("RPC_S_PROTSEQ_NOT_SUPPORTED",0x000006A7,"The RPC protocol sequence is not supported.")

    # (0x000006A8) The RPC protocol sequence is invalid.
    RPC_S_INVALID_RPC_PROTSEQ = WindowsError::ErrorCode.new("RPC_S_INVALID_RPC_PROTSEQ",0x000006A8,"The RPC protocol sequence is invalid.")

    # (0x000006A9) The string UUID is invalid.
    RPC_S_INVALID_STRING_UUID = WindowsError::ErrorCode.new("RPC_S_INVALID_STRING_UUID",0x000006A9,"The string UUID is invalid.")

    # (0x000006AA) The endpoint format is invalid.
    RPC_S_INVALID_ENDPOINT_FORMAT = WindowsError::ErrorCode.new("RPC_S_INVALID_ENDPOINT_FORMAT",0x000006AA,"The endpoint format is invalid.")

    # (0x000006AB) The network address is invalid.
    RPC_S_INVALID_NET_ADDR = WindowsError::ErrorCode.new("RPC_S_INVALID_NET_ADDR",0x000006AB,"The network address is invalid.")

    # (0x000006AC) No endpoint was found.
    RPC_S_NO_ENDPOINT_FOUND = WindowsError::ErrorCode.new("RPC_S_NO_ENDPOINT_FOUND",0x000006AC,"No endpoint was found.")

    # (0x000006AD) The time-out value is invalid.
    RPC_S_INVALID_TIMEOUT = WindowsError::ErrorCode.new("RPC_S_INVALID_TIMEOUT",0x000006AD,"The time-out value is invalid.")

    # (0x000006AE) The object UUID) was not found.
    RPC_S_OBJECT_NOT_FOUND = WindowsError::ErrorCode.new("RPC_S_OBJECT_NOT_FOUND",0x000006AE,"The object UUID) was not found.")

    # (0x000006AF) The object UUID) has already been registered.
    RPC_S_ALREADY_REGISTERED = WindowsError::ErrorCode.new("RPC_S_ALREADY_REGISTERED",0x000006AF,"The object UUID) has already been registered.")

    # (0x000006B0) The type UUID has already been registered.
    RPC_S_TYPE_ALREADY_REGISTERED = WindowsError::ErrorCode.new("RPC_S_TYPE_ALREADY_REGISTERED",0x000006B0,"The type UUID has already been registered.")

    # (0x000006B1) The RPC server is already listening.
    RPC_S_ALREADY_LISTENING = WindowsError::ErrorCode.new("RPC_S_ALREADY_LISTENING",0x000006B1,"The RPC server is already listening.")

    # (0x000006B2) No protocol sequences have been registered.
    RPC_S_NO_PROTSEQS_REGISTERED = WindowsError::ErrorCode.new("RPC_S_NO_PROTSEQS_REGISTERED",0x000006B2,"No protocol sequences have been registered.")

    # (0x000006B3) The RPC server is not listening.
    RPC_S_NOT_LISTENING = WindowsError::ErrorCode.new("RPC_S_NOT_LISTENING",0x000006B3,"The RPC server is not listening.")

    # (0x000006B4) The manager type is unknown.
    RPC_S_UNKNOWN_MGR_TYPE = WindowsError::ErrorCode.new("RPC_S_UNKNOWN_MGR_TYPE",0x000006B4,"The manager type is unknown.")

    # (0x000006B5) The interface is unknown.
    RPC_S_UNKNOWN_IF = WindowsError::ErrorCode.new("RPC_S_UNKNOWN_IF",0x000006B5,"The interface is unknown.")

    # (0x000006B6) There are no bindings.
    RPC_S_NO_BINDINGS = WindowsError::ErrorCode.new("RPC_S_NO_BINDINGS",0x000006B6,"There are no bindings.")

    # (0x000006B7) There are no protocol sequences.
    RPC_S_NO_PROTSEQS = WindowsError::ErrorCode.new("RPC_S_NO_PROTSEQS",0x000006B7,"There are no protocol sequences.")

    # (0x000006B8) The endpoint cannot be created.
    RPC_S_CANT_CREATE_ENDPOINT = WindowsError::ErrorCode.new("RPC_S_CANT_CREATE_ENDPOINT",0x000006B8,"The endpoint cannot be created.")

    # (0x000006B9) Not enough resources are available to complete this operation.
    RPC_S_OUT_OF_RESOURCES = WindowsError::ErrorCode.new("RPC_S_OUT_OF_RESOURCES",0x000006B9,"Not enough resources are available to complete this operation.")

    # (0x000006BA) The RPC server is unavailable.
    RPC_S_SERVER_UNAVAILABLE = WindowsError::ErrorCode.new("RPC_S_SERVER_UNAVAILABLE",0x000006BA,"The RPC server is unavailable.")

    # (0x000006BB) The RPC server is too busy to complete this operation.
    RPC_S_SERVER_TOO_BUSY = WindowsError::ErrorCode.new("RPC_S_SERVER_TOO_BUSY",0x000006BB,"The RPC server is too busy to complete this operation.")

    # (0x000006BC) The network options are invalid.
    RPC_S_INVALID_NETWORK_OPTIONS = WindowsError::ErrorCode.new("RPC_S_INVALID_NETWORK_OPTIONS",0x000006BC,"The network options are invalid.")

    # (0x000006BD) There are no RPCs active on this thread.
    RPC_S_NO_CALL_ACTIVE = WindowsError::ErrorCode.new("RPC_S_NO_CALL_ACTIVE",0x000006BD,"There are no RPCs active on this thread.")

    # (0x000006BE) The RPC failed.
    RPC_S_CALL_FAILED = WindowsError::ErrorCode.new("RPC_S_CALL_FAILED",0x000006BE,"The RPC failed.")

    # (0x000006BF) The RPC failed and did not execute.
    RPC_S_CALL_FAILED_DNE = WindowsError::ErrorCode.new("RPC_S_CALL_FAILED_DNE",0x000006BF,"The RPC failed and did not execute.")

    # (0x000006C0) An RPC protocol error occurred.
    RPC_S_PROTOCOL_ERROR = WindowsError::ErrorCode.new("RPC_S_PROTOCOL_ERROR",0x000006C0,"An RPC protocol error occurred.")

    # (0x000006C1) Access to the HTTP proxy is denied.
    RPC_S_PROXY_ACCESS_DENIED = WindowsError::ErrorCode.new("RPC_S_PROXY_ACCESS_DENIED",0x000006C1,"Access to the HTTP proxy is denied.")

    # (0x000006C2) The transfer syntax is not supported by the RPC server.
    RPC_S_UNSUPPORTED_TRANS_SYN = WindowsError::ErrorCode.new("RPC_S_UNSUPPORTED_TRANS_SYN",0x000006C2,"The transfer syntax is not supported by the RPC server.")

    # (0x000006C4) The UUID type is not supported.
    RPC_S_UNSUPPORTED_TYPE = WindowsError::ErrorCode.new("RPC_S_UNSUPPORTED_TYPE",0x000006C4,"The UUID type is not supported.")

    # (0x000006C5) The tag is invalid.
    RPC_S_INVALID_TAG = WindowsError::ErrorCode.new("RPC_S_INVALID_TAG",0x000006C5,"The tag is invalid.")

    # (0x000006C6) The array bounds are invalid.
    RPC_S_INVALID_BOUND = WindowsError::ErrorCode.new("RPC_S_INVALID_BOUND",0x000006C6,"The array bounds are invalid.")

    # (0x000006C7) The binding does not contain an entry name.
    RPC_S_NO_ENTRY_NAME = WindowsError::ErrorCode.new("RPC_S_NO_ENTRY_NAME",0x000006C7,"The binding does not contain an entry name.")

    # (0x000006C8) The name syntax is invalid.
    RPC_S_INVALID_NAME_SYNTAX = WindowsError::ErrorCode.new("RPC_S_INVALID_NAME_SYNTAX",0x000006C8,"The name syntax is invalid.")

    # (0x000006C9) The name syntax is not supported.
    RPC_S_UNSUPPORTED_NAME_SYNTAX = WindowsError::ErrorCode.new("RPC_S_UNSUPPORTED_NAME_SYNTAX",0x000006C9,"The name syntax is not supported.")

    # (0x000006CB) No network address is available to use to construct a UUID.
    RPC_S_UUID_NO_ADDRESS = WindowsError::ErrorCode.new("RPC_S_UUID_NO_ADDRESS",0x000006CB,"No network address is available to use to construct a UUID.")

    # (0x000006CC) The endpoint is a duplicate.
    RPC_S_DUPLICATE_ENDPOINT = WindowsError::ErrorCode.new("RPC_S_DUPLICATE_ENDPOINT",0x000006CC,"The endpoint is a duplicate.")

    # (0x000006CD) The authentication type is unknown.
    RPC_S_UNKNOWN_AUTHN_TYPE = WindowsError::ErrorCode.new("RPC_S_UNKNOWN_AUTHN_TYPE",0x000006CD,"The authentication type is unknown.")

    # (0x000006CE) The maximum number of calls is too small.
    RPC_S_MAX_CALLS_TOO_SMALL = WindowsError::ErrorCode.new("RPC_S_MAX_CALLS_TOO_SMALL",0x000006CE,"The maximum number of calls is too small.")

    # (0x000006CF) The string is too long.
    RPC_S_STRING_TOO_LONG = WindowsError::ErrorCode.new("RPC_S_STRING_TOO_LONG",0x000006CF,"The string is too long.")

    # (0x000006D0) The RPC protocol sequence was not found.
    RPC_S_PROTSEQ_NOT_FOUND = WindowsError::ErrorCode.new("RPC_S_PROTSEQ_NOT_FOUND",0x000006D0,"The RPC protocol sequence was not found.")

    # (0x000006D1) The procedure number is out of range.
    RPC_S_PROCNUM_OUT_OF_RANGE = WindowsError::ErrorCode.new("RPC_S_PROCNUM_OUT_OF_RANGE",0x000006D1,"The procedure number is out of range.")

    # (0x000006D2) The binding does not contain any authentication information.
    RPC_S_BINDING_HAS_NO_AUTH = WindowsError::ErrorCode.new("RPC_S_BINDING_HAS_NO_AUTH",0x000006D2,"The binding does not contain any authentication information.")

    # (0x000006D3) The authentication service is unknown.
    RPC_S_UNKNOWN_AUTHN_SERVICE = WindowsError::ErrorCode.new("RPC_S_UNKNOWN_AUTHN_SERVICE",0x000006D3,"The authentication service is unknown.")

    # (0x000006D4) The authentication level is unknown.
    RPC_S_UNKNOWN_AUTHN_LEVEL = WindowsError::ErrorCode.new("RPC_S_UNKNOWN_AUTHN_LEVEL",0x000006D4,"The authentication level is unknown.")

    # (0x000006D5) The security context is invalid.
    RPC_S_INVALID_AUTH_IDENTITY = WindowsError::ErrorCode.new("RPC_S_INVALID_AUTH_IDENTITY",0x000006D5,"The security context is invalid.")

    # (0x000006D6) The authorization service is unknown.
    RPC_S_UNKNOWN_AUTHZ_SERVICE = WindowsError::ErrorCode.new("RPC_S_UNKNOWN_AUTHZ_SERVICE",0x000006D6,"The authorization service is unknown.")

    # (0x000006D7) The entry is invalid.
    EPT_S_INVALID_ENTRY = WindowsError::ErrorCode.new("EPT_S_INVALID_ENTRY",0x000006D7,"The entry is invalid.")

    # (0x000006D8) The server endpoint cannot perform the operation.
    EPT_S_CANT_PERFORM_OP = WindowsError::ErrorCode.new("EPT_S_CANT_PERFORM_OP",0x000006D8,"The server endpoint cannot perform the operation.")

    # (0x000006D9) There are no more endpoints available from the endpoint mapper.
    EPT_S_NOT_REGISTERED = WindowsError::ErrorCode.new("EPT_S_NOT_REGISTERED",0x000006D9,"There are no more endpoints available from the endpoint mapper.")

    # (0x000006DA) No interfaces have been exported.
    RPC_S_NOTHING_TO_EXPORT = WindowsError::ErrorCode.new("RPC_S_NOTHING_TO_EXPORT",0x000006DA,"No interfaces have been exported.")

    # (0x000006DB) The entry name is incomplete.
    RPC_S_INCOMPLETE_NAME = WindowsError::ErrorCode.new("RPC_S_INCOMPLETE_NAME",0x000006DB,"The entry name is incomplete.")

    # (0x000006DC) The version option is invalid.
    RPC_S_INVALID_VERS_OPTION = WindowsError::ErrorCode.new("RPC_S_INVALID_VERS_OPTION",0x000006DC,"The version option is invalid.")

    # (0x000006DD) There are no more members.
    RPC_S_NO_MORE_MEMBERS = WindowsError::ErrorCode.new("RPC_S_NO_MORE_MEMBERS",0x000006DD,"There are no more members.")

    # (0x000006DE) There is nothing to unexport.
    RPC_S_NOT_ALL_OBJS_UNEXPORTED = WindowsError::ErrorCode.new("RPC_S_NOT_ALL_OBJS_UNEXPORTED",0x000006DE,"There is nothing to unexport.")

    # (0x000006DF) The interface was not found.
    RPC_S_INTERFACE_NOT_FOUND = WindowsError::ErrorCode.new("RPC_S_INTERFACE_NOT_FOUND",0x000006DF,"The interface was not found.")

    # (0x000006E0) The entry already exists.
    RPC_S_ENTRY_ALREADY_EXISTS = WindowsError::ErrorCode.new("RPC_S_ENTRY_ALREADY_EXISTS",0x000006E0,"The entry already exists.")

    # (0x000006E1) The entry is not found.
    RPC_S_ENTRY_NOT_FOUND = WindowsError::ErrorCode.new("RPC_S_ENTRY_NOT_FOUND",0x000006E1,"The entry is not found.")

    # (0x000006E2) The name service is unavailable.
    RPC_S_NAME_SERVICE_UNAVAILABLE = WindowsError::ErrorCode.new("RPC_S_NAME_SERVICE_UNAVAILABLE",0x000006E2,"The name service is unavailable.")

    # (0x000006E3) The network address family is invalid.
    RPC_S_INVALID_NAF_ID = WindowsError::ErrorCode.new("RPC_S_INVALID_NAF_ID",0x000006E3,"The network address family is invalid.")

    # (0x000006E4) The requested operation is not supported.
    RPC_S_CANNOT_SUPPORT = WindowsError::ErrorCode.new("RPC_S_CANNOT_SUPPORT",0x000006E4,"The requested operation is not supported.")

    # (0x000006E5) No security context is available to allow impersonation.
    RPC_S_NO_CONTEXT_AVAILABLE = WindowsError::ErrorCode.new("RPC_S_NO_CONTEXT_AVAILABLE",0x000006E5,"No security context is available to allow impersonation.")

    # (0x000006E6) An internal error occurred in an RPC.
    RPC_S_INTERNAL_ERROR = WindowsError::ErrorCode.new("RPC_S_INTERNAL_ERROR",0x000006E6,"An internal error occurred in an RPC.")

    # (0x000006E7) The RPC server attempted an integer division by zero.
    RPC_S_ZERO_DIVIDE = WindowsError::ErrorCode.new("RPC_S_ZERO_DIVIDE",0x000006E7,"The RPC server attempted an integer division by zero.")

    # (0x000006E8) An addressing error occurred in the RPC server.
    RPC_S_ADDRESS_ERROR = WindowsError::ErrorCode.new("RPC_S_ADDRESS_ERROR",0x000006E8,"An addressing error occurred in the RPC server.")

    # (0x000006E9) A floating-point operation at the RPC server caused a division by zero.
    RPC_S_FP_DIV_ZERO = WindowsError::ErrorCode.new("RPC_S_FP_DIV_ZERO",0x000006E9,"A floating-point operation at the RPC server caused a division by zero.")

    # (0x000006EA) A floating-point underflow occurred at the RPC server.
    RPC_S_FP_UNDERFLOW = WindowsError::ErrorCode.new("RPC_S_FP_UNDERFLOW",0x000006EA,"A floating-point underflow occurred at the RPC server.")

    # (0x000006EB) A floating-point overflow occurred at the RPC server.
    RPC_S_FP_OVERFLOW = WindowsError::ErrorCode.new("RPC_S_FP_OVERFLOW",0x000006EB,"A floating-point overflow occurred at the RPC server.")

    # (0x000006EC) The list of RPC servers available for the binding of auto handles has been exhausted.
    RPC_X_NO_MORE_ENTRIES = WindowsError::ErrorCode.new("RPC_X_NO_MORE_ENTRIES",0x000006EC,"The list of RPC servers available for the binding of auto handles has been exhausted.")

    # (0x000006ED) Unable to open the character translation table file.
    RPC_X_SS_CHAR_TRANS_OPEN_FAIL = WindowsError::ErrorCode.new("RPC_X_SS_CHAR_TRANS_OPEN_FAIL",0x000006ED,"Unable to open the character translation table file.")

    # (0x000006EE) The file containing the character translation table has fewer than 512 bytes.
    RPC_X_SS_CHAR_TRANS_SHORT_FILE = WindowsError::ErrorCode.new("RPC_X_SS_CHAR_TRANS_SHORT_FILE",0x000006EE,"The file containing the character translation table has fewer than 512 bytes.")

    # (0x000006EF) A null context handle was passed from the client to the host during an RPC.
    RPC_X_SS_IN_NULL_CONTEXT = WindowsError::ErrorCode.new("RPC_X_SS_IN_NULL_CONTEXT",0x000006EF,"A null context handle was passed from the client to the host during an RPC.")

    # (0x000006F1) The context handle changed during an RPC.
    RPC_X_SS_CONTEXT_DAMAGED = WindowsError::ErrorCode.new("RPC_X_SS_CONTEXT_DAMAGED",0x000006F1,"The context handle changed during an RPC.")

    # (0x000006F2) The binding handles passed to an RPC do not match.
    RPC_X_SS_HANDLES_MISMATCH = WindowsError::ErrorCode.new("RPC_X_SS_HANDLES_MISMATCH",0x000006F2,"The binding handles passed to an RPC do not match.")

    # (0x000006F3) The stub is unable to get the RPC handle.
    RPC_X_SS_CANNOT_GET_CALL_HANDLE = WindowsError::ErrorCode.new("RPC_X_SS_CANNOT_GET_CALL_HANDLE",0x000006F3,"The stub is unable to get the RPC handle.")

    # (0x000006F4) A null reference pointer was passed to the stub.
    RPC_X_NULL_REF_POINTER = WindowsError::ErrorCode.new("RPC_X_NULL_REF_POINTER",0x000006F4,"A null reference pointer was passed to the stub.")

    # (0x000006F5) The enumeration value is out of range.
    RPC_X_ENUM_VALUE_OUT_OF_RANGE = WindowsError::ErrorCode.new("RPC_X_ENUM_VALUE_OUT_OF_RANGE",0x000006F5,"The enumeration value is out of range.")

    # (0x000006F6) The byte count is too small.
    RPC_X_BYTE_COUNT_TOO_SMALL = WindowsError::ErrorCode.new("RPC_X_BYTE_COUNT_TOO_SMALL",0x000006F6,"The byte count is too small.")

    # (0x000006F7) The stub received bad data.
    RPC_X_BAD_STUB_DATA = WindowsError::ErrorCode.new("RPC_X_BAD_STUB_DATA",0x000006F7,"The stub received bad data.")

    # (0x000006F8) The supplied user buffer is not valid for the requested operation.
    ERROR_INVALID_USER_BUFFER = WindowsError::ErrorCode.new("ERROR_INVALID_USER_BUFFER",0x000006F8,"The supplied user buffer is not valid for the requested operation.")

    # (0x000006F9) The disk media is not recognized. It may not be formatted.
    ERROR_UNRECOGNIZED_MEDIA = WindowsError::ErrorCode.new("ERROR_UNRECOGNIZED_MEDIA",0x000006F9,"The disk media is not recognized. It may not be formatted.")

    # (0x000006FA) The workstation does not have a trust secret.
    ERROR_NO_TRUST_LSA_SECRET = WindowsError::ErrorCode.new("ERROR_NO_TRUST_LSA_SECRET",0x000006FA,"The workstation does not have a trust secret.")

    # (0x000006FB) The security database on the server does not have a computer account for this workstation trust relationship.
    ERROR_NO_TRUST_SAM_ACCOUNT = WindowsError::ErrorCode.new("ERROR_NO_TRUST_SAM_ACCOUNT",0x000006FB,"The security database on the server does not have a computer account for this workstation trust relationship.")

    # (0x000006FC) The trust relationship between the primary domain and the trusted domain failed.
    ERROR_TRUSTED_DOMAIN_FAILURE = WindowsError::ErrorCode.new("ERROR_TRUSTED_DOMAIN_FAILURE",0x000006FC,"The trust relationship between the primary domain and the trusted domain failed.")

    # (0x000006FD) The trust relationship between this workstation and the primary domain failed.
    ERROR_TRUSTED_RELATIONSHIP_FAILURE = WindowsError::ErrorCode.new("ERROR_TRUSTED_RELATIONSHIP_FAILURE",0x000006FD,"The trust relationship between this workstation and the primary domain failed.")

    # (0x000006FE) The network logon failed.
    ERROR_TRUST_FAILURE = WindowsError::ErrorCode.new("ERROR_TRUST_FAILURE",0x000006FE,"The network logon failed.")

    # (0x000006FF) An RPC is already in progress for this thread.
    RPC_S_CALL_IN_PROGRESS = WindowsError::ErrorCode.new("RPC_S_CALL_IN_PROGRESS",0x000006FF,"An RPC is already in progress for this thread.")

    # (0x00000700) An attempt was made to log on, but the network logon service was not started.
    ERROR_NETLOGON_NOT_STARTED = WindowsError::ErrorCode.new("ERROR_NETLOGON_NOT_STARTED",0x00000700,"An attempt was made to log on, but the network logon service was not started.")

    # (0x00000701) The user's account has expired.
    ERROR_ACCOUNT_EXPIRED = WindowsError::ErrorCode.new("ERROR_ACCOUNT_EXPIRED",0x00000701,"The user's account has expired.")

    # (0x00000702) The redirector is in use and cannot be unloaded.
    ERROR_REDIRECTOR_HAS_OPEN_HANDLES = WindowsError::ErrorCode.new("ERROR_REDIRECTOR_HAS_OPEN_HANDLES",0x00000702,"The redirector is in use and cannot be unloaded.")

    # (0x00000703) The specified printer driver is already installed.
    ERROR_PRINTER_DRIVER_ALREADY_INSTALLED = WindowsError::ErrorCode.new("ERROR_PRINTER_DRIVER_ALREADY_INSTALLED",0x00000703,"The specified printer driver is already installed.")

    # (0x00000704) The specified port is unknown.
    ERROR_UNKNOWN_PORT = WindowsError::ErrorCode.new("ERROR_UNKNOWN_PORT",0x00000704,"The specified port is unknown.")

    # (0x00000705) The printer driver is unknown.
    ERROR_UNKNOWN_PRINTER_DRIVER = WindowsError::ErrorCode.new("ERROR_UNKNOWN_PRINTER_DRIVER",0x00000705,"The printer driver is unknown.")

    # (0x00000706) The print processor is unknown.
    ERROR_UNKNOWN_PRINTPROCESSOR = WindowsError::ErrorCode.new("ERROR_UNKNOWN_PRINTPROCESSOR",0x00000706,"The print processor is unknown.")

    # (0x00000707) The specified separator file is invalid.
    ERROR_INVALID_SEPARATOR_FILE = WindowsError::ErrorCode.new("ERROR_INVALID_SEPARATOR_FILE",0x00000707,"The specified separator file is invalid.")

    # (0x00000708) The specified priority is invalid.
    ERROR_INVALID_PRIORITY = WindowsError::ErrorCode.new("ERROR_INVALID_PRIORITY",0x00000708,"The specified priority is invalid.")

    # (0x00000709) The printer name is invalid.
    ERROR_INVALID_PRINTER_NAME = WindowsError::ErrorCode.new("ERROR_INVALID_PRINTER_NAME",0x00000709,"The printer name is invalid.")

    # (0x0000070A) The printer already exists.
    ERROR_PRINTER_ALREADY_EXISTS = WindowsError::ErrorCode.new("ERROR_PRINTER_ALREADY_EXISTS",0x0000070A,"The printer already exists.")

    # (0x0000070B) The printer command is invalid.
    ERROR_INVALID_PRINTER_COMMAND = WindowsError::ErrorCode.new("ERROR_INVALID_PRINTER_COMMAND",0x0000070B,"The printer command is invalid.")

    # (0x0000070C) The specified data type is invalid.
    ERROR_INVALID_DATATYPE = WindowsError::ErrorCode.new("ERROR_INVALID_DATATYPE",0x0000070C,"The specified data type is invalid.")

    # (0x0000070D) The environment specified is invalid.
    ERROR_INVALID_ENVIRONMENT = WindowsError::ErrorCode.new("ERROR_INVALID_ENVIRONMENT",0x0000070D,"The environment specified is invalid.")

    # (0x0000070E) There are no more bindings.
    RPC_S_NO_MORE_BINDINGS = WindowsError::ErrorCode.new("RPC_S_NO_MORE_BINDINGS",0x0000070E,"There are no more bindings.")

    # (0x0000070F) The account used is an interdomain trust account. Use your global user account or local user account to access this server.
    ERROR_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT = WindowsError::ErrorCode.new("ERROR_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT",0x0000070F,"The account used is an interdomain trust account. Use your global user account or local user account to access this server.")

    # (0x00000710) The account used is a computer account. Use your global user account or local user account to access this server.
    ERROR_NOLOGON_WORKSTATION_TRUST_ACCOUNT = WindowsError::ErrorCode.new("ERROR_NOLOGON_WORKSTATION_TRUST_ACCOUNT",0x00000710,"The account used is a computer account. Use your global user account or local user account to access this server.")

    # (0x00000711) The account used is a server trust account. Use your global user account or local user account to access this server.
    ERROR_NOLOGON_SERVER_TRUST_ACCOUNT = WindowsError::ErrorCode.new("ERROR_NOLOGON_SERVER_TRUST_ACCOUNT",0x00000711,"The account used is a server trust account. Use your global user account or local user account to access this server.")

    # (0x00000712) The name or SID of the domain specified is inconsistent with the trust information for that domain.
    ERROR_DOMAIN_TRUST_INCONSISTENT = WindowsError::ErrorCode.new("ERROR_DOMAIN_TRUST_INCONSISTENT",0x00000712,"The name or SID of the domain specified is inconsistent with the trust information for that domain.")

    # (0x00000713) The server is in use and cannot be unloaded.
    ERROR_SERVER_HAS_OPEN_HANDLES = WindowsError::ErrorCode.new("ERROR_SERVER_HAS_OPEN_HANDLES",0x00000713,"The server is in use and cannot be unloaded.")

    # (0x00000714) The specified image file did not contain a resource section.
    ERROR_RESOURCE_DATA_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_RESOURCE_DATA_NOT_FOUND",0x00000714,"The specified image file did not contain a resource section.")

    # (0x00000715) The specified resource type cannot be found in the image file.
    ERROR_RESOURCE_TYPE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_RESOURCE_TYPE_NOT_FOUND",0x00000715,"The specified resource type cannot be found in the image file.")

    # (0x00000716) The specified resource name cannot be found in the image file.
    ERROR_RESOURCE_NAME_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_RESOURCE_NAME_NOT_FOUND",0x00000716,"The specified resource name cannot be found in the image file.")

    # (0x00000717) The specified resource language ID cannot be found in the image file.
    ERROR_RESOURCE_LANG_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_RESOURCE_LANG_NOT_FOUND",0x00000717,"The specified resource language ID cannot be found in the image file.")

    # (0x00000718) Not enough quota is available to process this command.
    ERROR_NOT_ENOUGH_QUOTA = WindowsError::ErrorCode.new("ERROR_NOT_ENOUGH_QUOTA",0x00000718,"Not enough quota is available to process this command.")

    # (0x00000719) No interfaces have been registered.
    RPC_S_NO_INTERFACES = WindowsError::ErrorCode.new("RPC_S_NO_INTERFACES",0x00000719,"No interfaces have been registered.")

    # (0x0000071A) The RPC was canceled.
    RPC_S_CALL_CANCELLED = WindowsError::ErrorCode.new("RPC_S_CALL_CANCELLED",0x0000071A,"The RPC was canceled.")

    # (0x0000071B) The binding handle does not contain all the required information.
    RPC_S_BINDING_INCOMPLETE = WindowsError::ErrorCode.new("RPC_S_BINDING_INCOMPLETE",0x0000071B,"The binding handle does not contain all the required information.")

    # (0x0000071C) A communications failure occurred during an RPC.
    RPC_S_COMM_FAILURE = WindowsError::ErrorCode.new("RPC_S_COMM_FAILURE",0x0000071C,"A communications failure occurred during an RPC.")

    # (0x0000071D) The requested authentication level is not supported.
    RPC_S_UNSUPPORTED_AUTHN_LEVEL = WindowsError::ErrorCode.new("RPC_S_UNSUPPORTED_AUTHN_LEVEL",0x0000071D,"The requested authentication level is not supported.")

    # (0x0000071E) No principal name is registered.
    RPC_S_NO_PRINC_NAME = WindowsError::ErrorCode.new("RPC_S_NO_PRINC_NAME",0x0000071E,"No principal name is registered.")

    # (0x0000071F) The error specified is not a valid Windows RPC error code.
    RPC_S_NOT_RPC_ERROR = WindowsError::ErrorCode.new("RPC_S_NOT_RPC_ERROR",0x0000071F,"The error specified is not a valid Windows RPC error code.")

    # (0x00000720) A UUID that is valid only on this computer has been allocated.
    RPC_S_UUID_LOCAL_ONLY = WindowsError::ErrorCode.new("RPC_S_UUID_LOCAL_ONLY",0x00000720,"A UUID that is valid only on this computer has been allocated.")

    # (0x00000721) A security package-specific error occurred.
    RPC_S_SEC_PKG_ERROR = WindowsError::ErrorCode.new("RPC_S_SEC_PKG_ERROR",0x00000721,"A security package-specific error occurred.")

    # (0x00000722) The thread is not canceled.
    RPC_S_NOT_CANCELLED = WindowsError::ErrorCode.new("RPC_S_NOT_CANCELLED",0x00000722,"The thread is not canceled.")

    # (0x00000723) Invalid operation on the encoding/decoding handle.
    RPC_X_INVALID_ES_ACTION = WindowsError::ErrorCode.new("RPC_X_INVALID_ES_ACTION",0x00000723,"Invalid operation on the encoding/decoding handle.")

    # (0x00000724) Incompatible version of the serializing package.
    RPC_X_WRONG_ES_VERSION = WindowsError::ErrorCode.new("RPC_X_WRONG_ES_VERSION",0x00000724,"Incompatible version of the serializing package.")

    # (0x00000725) Incompatible version of the RPC stub.
    RPC_X_WRONG_STUB_VERSION = WindowsError::ErrorCode.new("RPC_X_WRONG_STUB_VERSION",0x00000725,"Incompatible version of the RPC stub.")

    # (0x00000726) The RPC pipe object is invalid or corrupted.
    RPC_X_INVALID_PIPE_OBJECT = WindowsError::ErrorCode.new("RPC_X_INVALID_PIPE_OBJECT",0x00000726,"The RPC pipe object is invalid or corrupted.")

    # (0x00000727) An invalid operation was attempted on an RPC pipe object.
    RPC_X_WRONG_PIPE_ORDER = WindowsError::ErrorCode.new("RPC_X_WRONG_PIPE_ORDER",0x00000727,"An invalid operation was attempted on an RPC pipe object.")

    # (0x00000728) Unsupported RPC pipe version.
    RPC_X_WRONG_PIPE_VERSION = WindowsError::ErrorCode.new("RPC_X_WRONG_PIPE_VERSION",0x00000728,"Unsupported RPC pipe version.")

    # (0x0000076A) The group member was not found.
    RPC_S_GROUP_MEMBER_NOT_FOUND = WindowsError::ErrorCode.new("RPC_S_GROUP_MEMBER_NOT_FOUND",0x0000076A,"The group member was not found.")

    # (0x0000076B) The endpoint mapper database entry could not be created.
    EPT_S_CANT_CREATE = WindowsError::ErrorCode.new("EPT_S_CANT_CREATE",0x0000076B,"The endpoint mapper database entry could not be created.")

    # (0x0000076C) The object UUID is the nil UUID.
    RPC_S_INVALID_OBJECT = WindowsError::ErrorCode.new("RPC_S_INVALID_OBJECT",0x0000076C,"The object UUID is the nil UUID.")

    # (0x0000076D) The specified time is invalid.
    ERROR_INVALID_TIME = WindowsError::ErrorCode.new("ERROR_INVALID_TIME",0x0000076D,"The specified time is invalid.")

    # (0x0000076E) The specified form name is invalid.
    ERROR_INVALID_FORM_NAME = WindowsError::ErrorCode.new("ERROR_INVALID_FORM_NAME",0x0000076E,"The specified form name is invalid.")

    # (0x0000076F) The specified form size is invalid.
    ERROR_INVALID_FORM_SIZE = WindowsError::ErrorCode.new("ERROR_INVALID_FORM_SIZE",0x0000076F,"The specified form size is invalid.")

    # (0x00000770) The specified printer handle is already being waited on.
    ERROR_ALREADY_WAITING = WindowsError::ErrorCode.new("ERROR_ALREADY_WAITING",0x00000770,"The specified printer handle is already being waited on.")

    # (0x00000771) The specified printer has been deleted.
    ERROR_PRINTER_DELETED = WindowsError::ErrorCode.new("ERROR_PRINTER_DELETED",0x00000771,"The specified printer has been deleted.")

    # (0x00000772) The state of the printer is invalid.
    ERROR_INVALID_PRINTER_STATE = WindowsError::ErrorCode.new("ERROR_INVALID_PRINTER_STATE",0x00000772,"The state of the printer is invalid.")

    # (0x00000773) The user's password must be changed before logging on the first time.
    ERROR_PASSWORD_MUST_CHANGE = WindowsError::ErrorCode.new("ERROR_PASSWORD_MUST_CHANGE",0x00000773,"The user's password must be changed before logging on the first time.")

    # (0x00000774) Could not find the domain controller for this domain.
    ERROR_DOMAIN_CONTROLLER_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_DOMAIN_CONTROLLER_NOT_FOUND",0x00000774,"Could not find the domain controller for this domain.")

    # (0x00000775) The referenced account is currently locked out and may not be logged on to.
    ERROR_ACCOUNT_LOCKED_OUT = WindowsError::ErrorCode.new("ERROR_ACCOUNT_LOCKED_OUT",0x00000775,"The referenced account is currently locked out and may not be logged on to.")

    # (0x00000776) The object exporter specified was not found.
    OR_INVALID_OXID = WindowsError::ErrorCode.new("OR_INVALID_OXID",0x00000776,"The object exporter specified was not found.")

    # (0x00000777) The object specified was not found.
    OR_INVALID_OID = WindowsError::ErrorCode.new("OR_INVALID_OID",0x00000777,"The object specified was not found.")

    # (0x00000778) The object set specified was not found.
    OR_INVALID_SET = WindowsError::ErrorCode.new("OR_INVALID_SET",0x00000778,"The object set specified was not found.")

    # (0x00000779) Some data remains to be sent in the request buffer.
    RPC_S_SEND_INCOMPLETE = WindowsError::ErrorCode.new("RPC_S_SEND_INCOMPLETE",0x00000779,"Some data remains to be sent in the request buffer.")

    # (0x0000077A) Invalid asynchronous RPC handle.
    RPC_S_INVALID_ASYNC_HANDLE = WindowsError::ErrorCode.new("RPC_S_INVALID_ASYNC_HANDLE",0x0000077A,"Invalid asynchronous RPC handle.")

    # (0x0000077B) Invalid asynchronous RPC call handle for this operation.
    RPC_S_INVALID_ASYNC_CALL = WindowsError::ErrorCode.new("RPC_S_INVALID_ASYNC_CALL",0x0000077B,"Invalid asynchronous RPC call handle for this operation.")

    # (0x0000077C) The RPC pipe object has already been closed.
    RPC_X_PIPE_CLOSED = WindowsError::ErrorCode.new("RPC_X_PIPE_CLOSED",0x0000077C,"The RPC pipe object has already been closed.")

    # (0x0000077D) The RPC call completed before all pipes were processed.
    RPC_X_PIPE_DISCIPLINE_ERROR = WindowsError::ErrorCode.new("RPC_X_PIPE_DISCIPLINE_ERROR",0x0000077D,"The RPC call completed before all pipes were processed.")

    # (0x0000077E) No more data is available from the RPC pipe.
    RPC_X_PIPE_EMPTY = WindowsError::ErrorCode.new("RPC_X_PIPE_EMPTY",0x0000077E,"No more data is available from the RPC pipe.")

    # (0x0000077F) No site name is available for this machine.
    ERROR_NO_SITENAME = WindowsError::ErrorCode.new("ERROR_NO_SITENAME",0x0000077F,"No site name is available for this machine.")

    # (0x00000780) The file cannot be accessed by the system.
    ERROR_CANT_ACCESS_FILE = WindowsError::ErrorCode.new("ERROR_CANT_ACCESS_FILE",0x00000780,"The file cannot be accessed by the system.")

    # (0x00000781) The name of the file cannot be resolved by the system.
    ERROR_CANT_RESOLVE_FILENAME = WindowsError::ErrorCode.new("ERROR_CANT_RESOLVE_FILENAME",0x00000781,"The name of the file cannot be resolved by the system.")

    # (0x00000782) The entry is not of the expected type.
    RPC_S_ENTRY_TYPE_MISMATCH = WindowsError::ErrorCode.new("RPC_S_ENTRY_TYPE_MISMATCH",0x00000782,"The entry is not of the expected type.")

    # (0x00000783) Not all object UUIDs could be exported to the specified entry.
    RPC_S_NOT_ALL_OBJS_EXPORTED = WindowsError::ErrorCode.new("RPC_S_NOT_ALL_OBJS_EXPORTED",0x00000783,"Not all object UUIDs could be exported to the specified entry.")

    # (0x00000784) The interface could not be exported to the specified entry.
    RPC_S_INTERFACE_NOT_EXPORTED = WindowsError::ErrorCode.new("RPC_S_INTERFACE_NOT_EXPORTED",0x00000784,"The interface could not be exported to the specified entry.")

    # (0x00000785) The specified profile entry could not be added.
    RPC_S_PROFILE_NOT_ADDED = WindowsError::ErrorCode.new("RPC_S_PROFILE_NOT_ADDED",0x00000785,"The specified profile entry could not be added.")

    # (0x00000786) The specified profile element could not be added.
    RPC_S_PRF_ELT_NOT_ADDED = WindowsError::ErrorCode.new("RPC_S_PRF_ELT_NOT_ADDED",0x00000786,"The specified profile element could not be added.")

    # (0x00000787) The specified profile element could not be removed.
    RPC_S_PRF_ELT_NOT_REMOVED = WindowsError::ErrorCode.new("RPC_S_PRF_ELT_NOT_REMOVED",0x00000787,"The specified profile element could not be removed.")

    # (0x00000788) The group element could not be added.
    RPC_S_GRP_ELT_NOT_ADDED = WindowsError::ErrorCode.new("RPC_S_GRP_ELT_NOT_ADDED",0x00000788,"The group element could not be added.")

    # (0x00000789) The group element could not be removed.
    RPC_S_GRP_ELT_NOT_REMOVED = WindowsError::ErrorCode.new("RPC_S_GRP_ELT_NOT_REMOVED",0x00000789,"The group element could not be removed.")

    # (0x0000078A) The printer driver is not compatible with a policy enabled on your computer that blocks Windows NT 4.0 drivers.
    ERROR_KM_DRIVER_BLOCKED = WindowsError::ErrorCode.new("ERROR_KM_DRIVER_BLOCKED",0x0000078A,"The printer driver is not compatible with a policy enabled on your computer that blocks Windows NT 4.0 drivers.")

    # (0x0000078B) The context has expired and can no longer be used.
    ERROR_CONTEXT_EXPIRED = WindowsError::ErrorCode.new("ERROR_CONTEXT_EXPIRED",0x0000078B,"The context has expired and can no longer be used.")

    # (0x0000078C) The current user's delegated trust creation quota has been exceeded.
    ERROR_PER_USER_TRUST_QUOTA_EXCEEDED = WindowsError::ErrorCode.new("ERROR_PER_USER_TRUST_QUOTA_EXCEEDED",0x0000078C,"The current user's delegated trust creation quota has been exceeded.")

    # (0x0000078D) The total delegated trust creation quota has been exceeded.
    ERROR_ALL_USER_TRUST_QUOTA_EXCEEDED = WindowsError::ErrorCode.new("ERROR_ALL_USER_TRUST_QUOTA_EXCEEDED",0x0000078D,"The total delegated trust creation quota has been exceeded.")

    # (0x0000078E) The current user's delegated trust deletion quota has been exceeded.
    ERROR_USER_DELETE_TRUST_QUOTA_EXCEEDED = WindowsError::ErrorCode.new("ERROR_USER_DELETE_TRUST_QUOTA_EXCEEDED",0x0000078E,"The current user's delegated trust deletion quota has been exceeded.")

    # (0x0000078F) Logon failure: The machine you are logging on to is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine.
    ERROR_AUTHENTICATION_FIREWALL_FAILED = WindowsError::ErrorCode.new("ERROR_AUTHENTICATION_FIREWALL_FAILED",0x0000078F,"Logon failure: The machine you are logging on to is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine.")

    # (0x00000790) Remote connections to the Print Spooler are blocked by a policy set on your machine.
    ERROR_REMOTE_PRINT_CONNECTIONS_BLOCKED = WindowsError::ErrorCode.new("ERROR_REMOTE_PRINT_CONNECTIONS_BLOCKED",0x00000790,"Remote connections to the Print Spooler are blocked by a policy set on your machine.")

    # (0x000007D0) The pixel format is invalid.
    ERROR_INVALID_PIXEL_FORMAT = WindowsError::ErrorCode.new("ERROR_INVALID_PIXEL_FORMAT",0x000007D0,"The pixel format is invalid.")

    # (0x000007D1) The specified driver is invalid.
    ERROR_BAD_DRIVER = WindowsError::ErrorCode.new("ERROR_BAD_DRIVER",0x000007D1,"The specified driver is invalid.")

    # (0x000007D2) The window style or class attribute is invalid for this operation.
    ERROR_INVALID_WINDOW_STYLE = WindowsError::ErrorCode.new("ERROR_INVALID_WINDOW_STYLE",0x000007D2,"The window style or class attribute is invalid for this operation.")

    # (0x000007D3) The requested metafile operation is not supported.
    ERROR_METAFILE_NOT_SUPPORTED = WindowsError::ErrorCode.new("ERROR_METAFILE_NOT_SUPPORTED",0x000007D3,"The requested metafile operation is not supported.")

    # (0x000007D4) The requested transformation operation is not supported.
    ERROR_TRANSFORM_NOT_SUPPORTED = WindowsError::ErrorCode.new("ERROR_TRANSFORM_NOT_SUPPORTED",0x000007D4,"The requested transformation operation is not supported.")

    # (0x000007D5) The requested clipping operation is not supported.
    ERROR_CLIPPING_NOT_SUPPORTED = WindowsError::ErrorCode.new("ERROR_CLIPPING_NOT_SUPPORTED",0x000007D5,"The requested clipping operation is not supported.")

    # (0x000007DA) The specified color management module is invalid.
    ERROR_INVALID_CMM = WindowsError::ErrorCode.new("ERROR_INVALID_CMM",0x000007DA,"The specified color management module is invalid.")

    # (0x000007DB) The specified color profile is invalid.
    ERROR_INVALID_PROFILE = WindowsError::ErrorCode.new("ERROR_INVALID_PROFILE",0x000007DB,"The specified color profile is invalid.")

    # (0x000007DC) The specified tag was not found.
    ERROR_TAG_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_TAG_NOT_FOUND",0x000007DC,"The specified tag was not found.")

    # (0x000007DD) A required tag is not present.
    ERROR_TAG_NOT_PRESENT = WindowsError::ErrorCode.new("ERROR_TAG_NOT_PRESENT",0x000007DD,"A required tag is not present.")

    # (0x000007DE) The specified tag is already present.
    ERROR_DUPLICATE_TAG = WindowsError::ErrorCode.new("ERROR_DUPLICATE_TAG",0x000007DE,"The specified tag is already present.")

    # (0x000007DF) The specified color profile is not associated with any device.
    ERROR_PROFILE_NOT_ASSOCIATED_WITH_DEVICE = WindowsError::ErrorCode.new("ERROR_PROFILE_NOT_ASSOCIATED_WITH_DEVICE",0x000007DF,"The specified color profile is not associated with any device.")

    # (0x000007E0) The specified color profile was not found.
    ERROR_PROFILE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_PROFILE_NOT_FOUND",0x000007E0,"The specified color profile was not found.")

    # (0x000007E1) The specified color space is invalid.
    ERROR_INVALID_COLORSPACE = WindowsError::ErrorCode.new("ERROR_INVALID_COLORSPACE",0x000007E1,"The specified color space is invalid.")

    # (0x000007E2) Image Color Management is not enabled.
    ERROR_ICM_NOT_ENABLED = WindowsError::ErrorCode.new("ERROR_ICM_NOT_ENABLED",0x000007E2,"Image Color Management is not enabled.")

    # (0x000007E3) There was an error while deleting the color transform.
    ERROR_DELETING_ICM_XFORM = WindowsError::ErrorCode.new("ERROR_DELETING_ICM_XFORM",0x000007E3,"There was an error while deleting the color transform.")

    # (0x000007E4) The specified color transform is invalid.
    ERROR_INVALID_TRANSFORM = WindowsError::ErrorCode.new("ERROR_INVALID_TRANSFORM",0x000007E4,"The specified color transform is invalid.")

    # (0x000007E5) The specified transform does not match the bitmap's color space.
    ERROR_COLORSPACE_MISMATCH = WindowsError::ErrorCode.new("ERROR_COLORSPACE_MISMATCH",0x000007E5,"The specified transform does not match the bitmap's color space.")

    # (0x000007E6) The specified named color index is not present in the profile.
    ERROR_INVALID_COLORINDEX = WindowsError::ErrorCode.new("ERROR_INVALID_COLORINDEX",0x000007E6,"The specified named color index is not present in the profile.")

    # (0x000007E7) The specified profile is intended for a device of a different type than the specified device.
    ERROR_PROFILE_DOES_NOT_MATCH_DEVICE = WindowsError::ErrorCode.new("ERROR_PROFILE_DOES_NOT_MATCH_DEVICE",0x000007E7,"The specified profile is intended for a device of a different type than the specified device.")

    # (0x00000836) The workstation driver is not installed.
    NERR_NetNotStarted = WindowsError::ErrorCode.new("NERR_NetNotStarted",0x00000836,"The workstation driver is not installed.")

    # (0x00000837) The server could not be located.
    NERR_UnknownServer = WindowsError::ErrorCode.new("NERR_UnknownServer",0x00000837,"The server could not be located.")

    # (0x00000838) An internal error occurred. The network cannot access a shared memory segment.
    NERR_ShareMem = WindowsError::ErrorCode.new("NERR_ShareMem",0x00000838,"An internal error occurred. The network cannot access a shared memory segment.")

    # (0x00000839) A network resource shortage occurred.
    NERR_NoNetworkResource = WindowsError::ErrorCode.new("NERR_NoNetworkResource",0x00000839,"A network resource shortage occurred.")

    # (0x0000083A) This operation is not supported on workstations.
    NERR_RemoteOnly = WindowsError::ErrorCode.new("NERR_RemoteOnly",0x0000083A,"This operation is not supported on workstations.")

    # (0x0000083B) The device is not connected.
    NERR_DevNotRedirected = WindowsError::ErrorCode.new("NERR_DevNotRedirected",0x0000083B,"The device is not connected.")

    # (0x0000083C) The network connection was made successfully, but the user had to be prompted for a password other than the one originally specified.
    ERROR_CONNECTED_OTHER_PASSWORD = WindowsError::ErrorCode.new("ERROR_CONNECTED_OTHER_PASSWORD",0x0000083C,"The network connection was made successfully, but the user had to be prompted for a password other than the one originally specified.")

    # (0x0000083D) The network connection was made successfully using default credentials.
    ERROR_CONNECTED_OTHER_PASSWORD_DEFAULT = WindowsError::ErrorCode.new("ERROR_CONNECTED_OTHER_PASSWORD_DEFAULT",0x0000083D,"The network connection was made successfully using default credentials.")

    # (0x00000842) The Server service is not started.
    NERR_ServerNotStarted = WindowsError::ErrorCode.new("NERR_ServerNotStarted",0x00000842,"The Server service is not started.")

    # (0x00000843) The queue is empty.
    NERR_ItemNotFound = WindowsError::ErrorCode.new("NERR_ItemNotFound",0x00000843,"The queue is empty.")

    # (0x00000844) The device or directory does not exist.
    NERR_UnknownDevDir = WindowsError::ErrorCode.new("NERR_UnknownDevDir",0x00000844,"The device or directory does not exist.")

    # (0x00000845) The operation is invalid on a redirected resource.
    NERR_RedirectedPath = WindowsError::ErrorCode.new("NERR_RedirectedPath",0x00000845,"The operation is invalid on a redirected resource.")

    # (0x00000846) The name has already been shared.
    NERR_DuplicateShare = WindowsError::ErrorCode.new("NERR_DuplicateShare",0x00000846,"The name has already been shared.")

    # (0x00000847) The server is currently out of the requested resource.
    NERR_NoRoom = WindowsError::ErrorCode.new("NERR_NoRoom",0x00000847,"The server is currently out of the requested resource.")

    # (0x00000849) Requested addition of items exceeds the maximum allowed.
    NERR_TooManyItems = WindowsError::ErrorCode.new("NERR_TooManyItems",0x00000849,"Requested addition of items exceeds the maximum allowed.")

    # (0x0000084A) The Peer service supports only two simultaneous users.
    NERR_InvalidMaxUsers = WindowsError::ErrorCode.new("NERR_InvalidMaxUsers",0x0000084A,"The Peer service supports only two simultaneous users.")

    # (0x0000084B) The API return buffer is too small.
    NERR_BufTooSmall = WindowsError::ErrorCode.new("NERR_BufTooSmall",0x0000084B,"The API return buffer is too small.")

    # (0x0000084F) A remote API error occurred.
    NERR_RemoteErr = WindowsError::ErrorCode.new("NERR_RemoteErr",0x0000084F,"A remote API error occurred.")

    # (0x00000853) An error occurred when opening or reading the configuration file.
    NERR_LanmanIniError = WindowsError::ErrorCode.new("NERR_LanmanIniError",0x00000853,"An error occurred when opening or reading the configuration file.")

    # (0x00000858) A general network error occurred.
    NERR_NetworkError = WindowsError::ErrorCode.new("NERR_NetworkError",0x00000858,"A general network error occurred.")

    # (0x00000859) The Workstation service is in an inconsistent state. Restart the computer before restarting the Workstation service.
    NERR_WkstaInconsistentState = WindowsError::ErrorCode.new("NERR_WkstaInconsistentState",0x00000859,"The Workstation service is in an inconsistent state. Restart the computer before restarting the Workstation service.")

    # (0x0000085A) The Workstation service has not been started.
    NERR_WkstaNotStarted = WindowsError::ErrorCode.new("NERR_WkstaNotStarted",0x0000085A,"The Workstation service has not been started.")

    # (0x0000085B) The requested information is not available.
    NERR_BrowserNotStarted = WindowsError::ErrorCode.new("NERR_BrowserNotStarted",0x0000085B,"The requested information is not available.")

    # (0x0000085C) An internal error occurred.
    NERR_InternalError = WindowsError::ErrorCode.new("NERR_InternalError",0x0000085C,"An internal error occurred.")

    # (0x0000085D) The server is not configured for transactions.
    NERR_BadTransactConfig = WindowsError::ErrorCode.new("NERR_BadTransactConfig",0x0000085D,"The server is not configured for transactions.")

    # (0x0000085E) The requested API is not supported on the remote server.
    NERR_InvalidAPI = WindowsError::ErrorCode.new("NERR_InvalidAPI",0x0000085E,"The requested API is not supported on the remote server.")

    # (0x0000085F) The event name is invalid.
    NERR_BadEventName = WindowsError::ErrorCode.new("NERR_BadEventName",0x0000085F,"The event name is invalid.")

    # (0x00000860) The computer name already exists on the network. Change it and reboot the computer.
    NERR_DupNameReboot = WindowsError::ErrorCode.new("NERR_DupNameReboot",0x00000860,"The computer name already exists on the network. Change it and reboot the computer.")

    # (0x00000862) The specified component could not be found in the configuration information.
    NERR_CfgCompNotFound = WindowsError::ErrorCode.new("NERR_CfgCompNotFound",0x00000862,"The specified component could not be found in the configuration information.")

    # (0x00000863) The specified parameter could not be found in the configuration information.
    NERR_CfgParamNotFound = WindowsError::ErrorCode.new("NERR_CfgParamNotFound",0x00000863,"The specified parameter could not be found in the configuration information.")

    # (0x00000865) A line in the configuration file is too long.
    NERR_LineTooLong = WindowsError::ErrorCode.new("NERR_LineTooLong",0x00000865,"A line in the configuration file is too long.")

    # (0x00000866) The printer does not exist.
    NERR_QNotFound = WindowsError::ErrorCode.new("NERR_QNotFound",0x00000866,"The printer does not exist.")

    # (0x00000867) The print job does not exist.
    NERR_JobNotFound = WindowsError::ErrorCode.new("NERR_JobNotFound",0x00000867,"The print job does not exist.")

    # (0x00000868) The printer destination cannot be found.
    NERR_DestNotFound = WindowsError::ErrorCode.new("NERR_DestNotFound",0x00000868,"The printer destination cannot be found.")

    # (0x00000869) The printer destination already exists.
    NERR_DestExists = WindowsError::ErrorCode.new("NERR_DestExists",0x00000869,"The printer destination already exists.")

    # (0x0000086A) The print queue already exists.
    NERR_QExists = WindowsError::ErrorCode.new("NERR_QExists",0x0000086A,"The print queue already exists.")

    # (0x0000086B) No more printers can be added.
    NERR_QNoRoom = WindowsError::ErrorCode.new("NERR_QNoRoom",0x0000086B,"No more printers can be added.")

    # (0x0000086C) No more print jobs can be added.
    NERR_JobNoRoom = WindowsError::ErrorCode.new("NERR_JobNoRoom",0x0000086C,"No more print jobs can be added.")

    # (0x0000086D) No more printer destinations can be added.
    NERR_DestNoRoom = WindowsError::ErrorCode.new("NERR_DestNoRoom",0x0000086D,"No more printer destinations can be added.")

    # (0x0000086E) This printer destination is idle and cannot accept control operations.
    NERR_DestIdle = WindowsError::ErrorCode.new("NERR_DestIdle",0x0000086E,"This printer destination is idle and cannot accept control operations.")

    # (0x0000086F) This printer destination request contains an invalid control function.
    NERR_DestInvalidOp = WindowsError::ErrorCode.new("NERR_DestInvalidOp",0x0000086F,"This printer destination request contains an invalid control function.")

    # (0x00000870) The print processor is not responding.
    NERR_ProcNoRespond = WindowsError::ErrorCode.new("NERR_ProcNoRespond",0x00000870,"The print processor is not responding.")

    # (0x00000871) The spooler is not running.
    NERR_SpoolerNotLoaded = WindowsError::ErrorCode.new("NERR_SpoolerNotLoaded",0x00000871,"The spooler is not running.")

    # (0x00000872) This operation cannot be performed on the print destination in its current state.
    NERR_DestInvalidState = WindowsError::ErrorCode.new("NERR_DestInvalidState",0x00000872,"This operation cannot be performed on the print destination in its current state.")

    # (0x00000873) This operation cannot be performed on the print queue in its current state.
    NERR_QinvalidState = WindowsError::ErrorCode.new("NERR_QinvalidState",0x00000873,"This operation cannot be performed on the print queue in its current state.")

    # (0x00000874) This operation cannot be performed on the print job in its current state.
    NERR_JobInvalidState = WindowsError::ErrorCode.new("NERR_JobInvalidState",0x00000874,"This operation cannot be performed on the print job in its current state.")

    # (0x00000875) A spooler memory allocation failure occurred.
    NERR_SpoolNoMemory = WindowsError::ErrorCode.new("NERR_SpoolNoMemory",0x00000875,"A spooler memory allocation failure occurred.")

    # (0x00000876) The device driver does not exist.
    NERR_DriverNotFound = WindowsError::ErrorCode.new("NERR_DriverNotFound",0x00000876,"The device driver does not exist.")

    # (0x00000877) The data type is not supported by the print processor.
    NERR_DataTypeInvalid = WindowsError::ErrorCode.new("NERR_DataTypeInvalid",0x00000877,"The data type is not supported by the print processor.")

    # (0x00000878) The print processor is not installed.
    NERR_ProcNotFound = WindowsError::ErrorCode.new("NERR_ProcNotFound",0x00000878,"The print processor is not installed.")

    # (0x00000884) The service database is locked.
    NERR_ServiceTableLocked = WindowsError::ErrorCode.new("NERR_ServiceTableLocked",0x00000884,"The service database is locked.")

    # (0x00000885) The service table is full.
    NERR_ServiceTableFull = WindowsError::ErrorCode.new("NERR_ServiceTableFull",0x00000885,"The service table is full.")

    # (0x00000886) The requested service has already been started.
    NERR_ServiceInstalled = WindowsError::ErrorCode.new("NERR_ServiceInstalled",0x00000886,"The requested service has already been started.")

    # (0x00000887) The service does not respond to control actions.
    NERR_ServiceEntryLocked = WindowsError::ErrorCode.new("NERR_ServiceEntryLocked",0x00000887,"The service does not respond to control actions.")

    # (0x00000888) The service has not been started.
    NERR_ServiceNotInstalled = WindowsError::ErrorCode.new("NERR_ServiceNotInstalled",0x00000888,"The service has not been started.")

    # (0x00000889) The service name is invalid.
    NERR_BadServiceName = WindowsError::ErrorCode.new("NERR_BadServiceName",0x00000889,"The service name is invalid.")

    # (0x0000088A) The service is not responding to the control function.
    NERR_ServiceCtlTimeout = WindowsError::ErrorCode.new("NERR_ServiceCtlTimeout",0x0000088A,"The service is not responding to the control function.")

    # (0x0000088B) The service control is busy.
    NERR_ServiceCtlBusy = WindowsError::ErrorCode.new("NERR_ServiceCtlBusy",0x0000088B,"The service control is busy.")

    # (0x0000088C) The configuration file contains an invalid service program name.
    NERR_BadServiceProgName = WindowsError::ErrorCode.new("NERR_BadServiceProgName",0x0000088C,"The configuration file contains an invalid service program name.")

    # (0x0000088D) The service could not be controlled in its present state.
    NERR_ServiceNotCtrl = WindowsError::ErrorCode.new("NERR_ServiceNotCtrl",0x0000088D,"The service could not be controlled in its present state.")

    # (0x0000088E) The service ended abnormally.
    NERR_ServiceKillProc = WindowsError::ErrorCode.new("NERR_ServiceKillProc",0x0000088E,"The service ended abnormally.")

    # (0x0000088F) The requested pause or stop is not valid for this service.
    NERR_ServiceCtlNotValid = WindowsError::ErrorCode.new("NERR_ServiceCtlNotValid",0x0000088F,"The requested pause or stop is not valid for this service.")

    # (0x00000890) The service control dispatcher could not find the service name in the dispatch table.
    NERR_NotInDispatchTbl = WindowsError::ErrorCode.new("NERR_NotInDispatchTbl",0x00000890,"The service control dispatcher could not find the service name in the dispatch table.")

    # (0x00000891) The service control dispatcher pipe read failed.
    NERR_BadControlRecv = WindowsError::ErrorCode.new("NERR_BadControlRecv",0x00000891,"The service control dispatcher pipe read failed.")

    # (0x00000892) A thread for the new service could not be created.
    NERR_ServiceNotStarting = WindowsError::ErrorCode.new("NERR_ServiceNotStarting",0x00000892,"A thread for the new service could not be created.")

    # (0x00000898) This workstation is already logged on to the LAN.
    NERR_AlreadyLoggedOn = WindowsError::ErrorCode.new("NERR_AlreadyLoggedOn",0x00000898,"This workstation is already logged on to the LAN.")

    # (0x00000899) The workstation is not logged on to the LAN.
    NERR_NotLoggedOn = WindowsError::ErrorCode.new("NERR_NotLoggedOn",0x00000899,"The workstation is not logged on to the LAN.")

    # (0x0000089A) The user name or group name parameter is invalid.
    NERR_BadUsername = WindowsError::ErrorCode.new("NERR_BadUsername",0x0000089A,"The user name or group name parameter is invalid.")

    # (0x0000089B) The password parameter is invalid.
    NERR_BadPassword = WindowsError::ErrorCode.new("NERR_BadPassword",0x0000089B,"The password parameter is invalid.")

    # (0x0000089C) The logon processor did not add the message alias.
    NERR_UnableToAddName_W = WindowsError::ErrorCode.new("NERR_UnableToAddName_W",0x0000089C,"The logon processor did not add the message alias.")

    # (0x0000089D) The logon processor did not add the message alias.
    NERR_UnableToAddName_F = WindowsError::ErrorCode.new("NERR_UnableToAddName_F",0x0000089D,"The logon processor did not add the message alias.")

    # (0x0000089E) @W The logoff processor did not delete the message alias.
    NERR_UnableToDelName_W = WindowsError::ErrorCode.new("NERR_UnableToDelName_W",0x0000089E,"@W The logoff processor did not delete the message alias.")

    # (0x0000089F) The logoff processor did not delete the message alias.
    NERR_UnableToDelName_F = WindowsError::ErrorCode.new("NERR_UnableToDelName_F",0x0000089F,"The logoff processor did not delete the message alias.")

    # (0x000008A1) Network logons are paused.
    NERR_LogonsPaused = WindowsError::ErrorCode.new("NERR_LogonsPaused",0x000008A1,"Network logons are paused.")

    # (0x000008A2) A centralized logon server conflict occurred.
    NERR_LogonServerConflict = WindowsError::ErrorCode.new("NERR_LogonServerConflict",0x000008A2,"A centralized logon server conflict occurred.")

    # (0x000008A3) The server is configured without a valid user path.
    NERR_LogonNoUserPath = WindowsError::ErrorCode.new("NERR_LogonNoUserPath",0x000008A3,"The server is configured without a valid user path.")

    # (0x000008A4) An error occurred while loading or running the logon script.
    NERR_LogonScriptError = WindowsError::ErrorCode.new("NERR_LogonScriptError",0x000008A4,"An error occurred while loading or running the logon script.")

    # (0x000008A6) The logon server was not specified. The computer will be logged on as STANDALONE.
    NERR_StandaloneLogon = WindowsError::ErrorCode.new("NERR_StandaloneLogon",0x000008A6,"The logon server was not specified. The computer will be logged on as STANDALONE.")

    # (0x000008A7) The logon server could not be found.
    NERR_LogonServerNotFound = WindowsError::ErrorCode.new("NERR_LogonServerNotFound",0x000008A7,"The logon server could not be found.")

    # (0x000008A8) There is already a logon domain for this computer.
    NERR_LogonDomainExists = WindowsError::ErrorCode.new("NERR_LogonDomainExists",0x000008A8,"There is already a logon domain for this computer.")

    # (0x000008A9) The logon server could not validate the logon.
    NERR_NonValidatedLogon = WindowsError::ErrorCode.new("NERR_NonValidatedLogon",0x000008A9,"The logon server could not validate the logon.")

    # (0x000008AB) The security database could not be found.
    NERR_ACFNotFound = WindowsError::ErrorCode.new("NERR_ACFNotFound",0x000008AB,"The security database could not be found.")

    # (0x000008AC) The group name could not be found.
    NERR_GroupNotFound = WindowsError::ErrorCode.new("NERR_GroupNotFound",0x000008AC,"The group name could not be found.")

    # (0x000008AD) The user name could not be found.
    NERR_UserNotFound = WindowsError::ErrorCode.new("NERR_UserNotFound",0x000008AD,"The user name could not be found.")

    # (0x000008AE) The resource name could not be found.
    NERR_ResourceNotFound = WindowsError::ErrorCode.new("NERR_ResourceNotFound",0x000008AE,"The resource name could not be found.")

    # (0x000008AF) The group already exists.
    NERR_GroupExists = WindowsError::ErrorCode.new("NERR_GroupExists",0x000008AF,"The group already exists.")

    # (0x000008B0) The user account already exists.
    NERR_UserExists = WindowsError::ErrorCode.new("NERR_UserExists",0x000008B0,"The user account already exists.")

    # (0x000008B1) The resource permission list already exists.
    NERR_ResourceExists = WindowsError::ErrorCode.new("NERR_ResourceExists",0x000008B1,"The resource permission list already exists.")

    # (0x000008B2) This operation is allowed only on the PDC of the domain.
    NERR_NotPrimary = WindowsError::ErrorCode.new("NERR_NotPrimary",0x000008B2,"This operation is allowed only on the PDC of the domain.")

    # (0x000008B3) The security database has not been started.
    NERR_ACFNotLoaded = WindowsError::ErrorCode.new("NERR_ACFNotLoaded",0x000008B3,"The security database has not been started.")

    # (0x000008B4) There are too many names in the user accounts database.
    NERR_ACFNoRoom = WindowsError::ErrorCode.new("NERR_ACFNoRoom",0x000008B4,"There are too many names in the user accounts database.")

    # (0x000008B5) A disk I/O failure occurred.
    NERR_ACFFileIOFail = WindowsError::ErrorCode.new("NERR_ACFFileIOFail",0x000008B5,"A disk I/O failure occurred.")

    # (0x000008B6) The limit of 64 entries per resource was exceeded.
    NERR_ACFTooManyLists = WindowsError::ErrorCode.new("NERR_ACFTooManyLists",0x000008B6,"The limit of 64 entries per resource was exceeded.")

    # (0x000008B7) Deleting a user with a session is not allowed.
    NERR_UserLogon = WindowsError::ErrorCode.new("NERR_UserLogon",0x000008B7,"Deleting a user with a session is not allowed.")

    # (0x000008B8) The parent directory could not be located.
    NERR_ACFNoParent = WindowsError::ErrorCode.new("NERR_ACFNoParent",0x000008B8,"The parent directory could not be located.")

    # (0x000008B9) Unable to add to the security database session cache segment.
    NERR_CanNotGrowSegment = WindowsError::ErrorCode.new("NERR_CanNotGrowSegment",0x000008B9,"Unable to add to the security database session cache segment.")

    # (0x000008BA) This operation is not allowed on this special group.
    NERR_SpeGroupOp = WindowsError::ErrorCode.new("NERR_SpeGroupOp",0x000008BA,"This operation is not allowed on this special group.")

    # (0x000008BB) This user is not cached in the user accounts database session cache.
    NERR_NotInCache = WindowsError::ErrorCode.new("NERR_NotInCache",0x000008BB,"This user is not cached in the user accounts database session cache.")

    # (0x000008BC) The user already belongs to this group.
    NERR_UserInGroup = WindowsError::ErrorCode.new("NERR_UserInGroup",0x000008BC,"The user already belongs to this group.")

    # (0x000008BD) The user does not belong to this group.
    NERR_UserNotInGroup = WindowsError::ErrorCode.new("NERR_UserNotInGroup",0x000008BD,"The user does not belong to this group.")

    # (0x000008BE) This user account is undefined.
    NERR_AccountUndefined = WindowsError::ErrorCode.new("NERR_AccountUndefined",0x000008BE,"This user account is undefined.")

    # (0x000008BF) This user account has expired.
    NERR_AccountExpired = WindowsError::ErrorCode.new("NERR_AccountExpired",0x000008BF,"This user account has expired.")

    # (0x000008C0) The user is not allowed to log on from this workstation.
    NERR_InvalidWorkstation = WindowsError::ErrorCode.new("NERR_InvalidWorkstation",0x000008C0,"The user is not allowed to log on from this workstation.")

    # (0x000008C1) The user is not allowed to log on at this time.
    NERR_InvalidLogonHours = WindowsError::ErrorCode.new("NERR_InvalidLogonHours",0x000008C1,"The user is not allowed to log on at this time.")

    # (0x000008C2) The password of this user has expired.
    NERR_PasswordExpired = WindowsError::ErrorCode.new("NERR_PasswordExpired",0x000008C2,"The password of this user has expired.")

    # (0x000008C3) The password of this user cannot change.
    NERR_PasswordCantChange = WindowsError::ErrorCode.new("NERR_PasswordCantChange",0x000008C3,"The password of this user cannot change.")

    # (0x000008C4) This password cannot be used now.
    NERR_PasswordHistConflict = WindowsError::ErrorCode.new("NERR_PasswordHistConflict",0x000008C4,"This password cannot be used now.")

    # (0x000008C5) The password does not meet the password policy requirements. Check the minimum password length, password complexity, and password history requirements.
    NERR_PasswordTooShort = WindowsError::ErrorCode.new("NERR_PasswordTooShort",0x000008C5,"The password does not meet the password policy requirements. Check the minimum password length, password complexity, and password history requirements.")

    # (0x000008C6) The password of this user is too recent to change.
    NERR_PasswordTooRecent = WindowsError::ErrorCode.new("NERR_PasswordTooRecent",0x000008C6,"The password of this user is too recent to change.")

    # (0x000008C7) The security database is corrupted.
    NERR_InvalidDatabase = WindowsError::ErrorCode.new("NERR_InvalidDatabase",0x000008C7,"The security database is corrupted.")

    # (0x000008C8) No updates are necessary to this replicant network or local security database.
    NERR_DatabaseUpToDate = WindowsError::ErrorCode.new("NERR_DatabaseUpToDate",0x000008C8,"No updates are necessary to this replicant network or local security database.")

    # (0x000008C9) This replicant database is outdated; synchronization is required.
    NERR_SyncRequired = WindowsError::ErrorCode.new("NERR_SyncRequired",0x000008C9,"This replicant database is outdated; synchronization is required.")

    # (0x000008CA) The network connection could not be found.
    NERR_UseNotFound = WindowsError::ErrorCode.new("NERR_UseNotFound",0x000008CA,"The network connection could not be found.")

    # (0x000008CB) This asg_type is invalid.
    NERR_BadAsgType = WindowsError::ErrorCode.new("NERR_BadAsgType",0x000008CB,"This asg_type is invalid.")

    # (0x000008CC) This device is currently being shared.
    NERR_DeviceIsShared = WindowsError::ErrorCode.new("NERR_DeviceIsShared",0x000008CC,"This device is currently being shared.")

    # (0x000008DE) The computer name could not be added as a message alias. The name may already exist on the network.
    NERR_NoComputerName = WindowsError::ErrorCode.new("NERR_NoComputerName",0x000008DE,"The computer name could not be added as a message alias. The name may already exist on the network.")

    # (0x000008DF) The Messenger service is already started.
    NERR_MsgAlreadyStarted = WindowsError::ErrorCode.new("NERR_MsgAlreadyStarted",0x000008DF,"The Messenger service is already started.")

    # (0x000008E0) The Messenger service failed to start.
    NERR_MsgInitFailed = WindowsError::ErrorCode.new("NERR_MsgInitFailed",0x000008E0,"The Messenger service failed to start.")

    # (0x000008E1) The message alias could not be found on the network.
    NERR_NameNotFound = WindowsError::ErrorCode.new("NERR_NameNotFound",0x000008E1,"The message alias could not be found on the network.")

    # (0x000008E2) This message alias has already been forwarded.
    NERR_AlreadyForwarded = WindowsError::ErrorCode.new("NERR_AlreadyForwarded",0x000008E2,"This message alias has already been forwarded.")

    # (0x000008E3) This message alias has been added but is still forwarded.
    NERR_AddForwarded = WindowsError::ErrorCode.new("NERR_AddForwarded",0x000008E3,"This message alias has been added but is still forwarded.")

    # (0x000008E4) This message alias already exists locally.
    NERR_AlreadyExists = WindowsError::ErrorCode.new("NERR_AlreadyExists",0x000008E4,"This message alias already exists locally.")

    # (0x000008E5) The maximum number of added message aliases has been exceeded.
    NERR_TooManyNames = WindowsError::ErrorCode.new("NERR_TooManyNames",0x000008E5,"The maximum number of added message aliases has been exceeded.")

    # (0x000008E6) The computer name could not be deleted.
    NERR_DelComputerName = WindowsError::ErrorCode.new("NERR_DelComputerName",0x000008E6,"The computer name could not be deleted.")

    # (0x000008E7) Messages cannot be forwarded back to the same workstation.
    NERR_LocalForward = WindowsError::ErrorCode.new("NERR_LocalForward",0x000008E7,"Messages cannot be forwarded back to the same workstation.")

    # (0x000008E8) An error occurred in the domain message processor.
    NERR_GrpMsgProcessor = WindowsError::ErrorCode.new("NERR_GrpMsgProcessor",0x000008E8,"An error occurred in the domain message processor.")

    # (0x000008E9) The message was sent, but the recipient has paused the Messenger service.
    NERR_PausedRemote = WindowsError::ErrorCode.new("NERR_PausedRemote",0x000008E9,"The message was sent, but the recipient has paused the Messenger service.")

    # (0x000008EA) The message was sent but not received.
    NERR_BadReceive = WindowsError::ErrorCode.new("NERR_BadReceive",0x000008EA,"The message was sent but not received.")

    # (0x000008EB) The message alias is currently in use. Try again later.
    NERR_NameInUse = WindowsError::ErrorCode.new("NERR_NameInUse",0x000008EB,"The message alias is currently in use. Try again later.")

    # (0x000008EC) The Messenger service has not been started.
    NERR_MsgNotStarted = WindowsError::ErrorCode.new("NERR_MsgNotStarted",0x000008EC,"The Messenger service has not been started.")

    # (0x000008ED) The name is not on the local computer.
    NERR_NotLocalName = WindowsError::ErrorCode.new("NERR_NotLocalName",0x000008ED,"The name is not on the local computer.")

    # (0x000008EE) The forwarded message alias could not be found on the network.
    NERR_NoForwardName = WindowsError::ErrorCode.new("NERR_NoForwardName",0x000008EE,"The forwarded message alias could not be found on the network.")

    # (0x000008EF) The message alias table on the remote station is full.
    NERR_RemoteFull = WindowsError::ErrorCode.new("NERR_RemoteFull",0x000008EF,"The message alias table on the remote station is full.")

    # (0x000008F0) Messages for this alias are not currently being forwarded.
    NERR_NameNotForwarded = WindowsError::ErrorCode.new("NERR_NameNotForwarded",0x000008F0,"Messages for this alias are not currently being forwarded.")

    # (0x000008F1) The broadcast message was truncated.
    NERR_TruncatedBroadcast = WindowsError::ErrorCode.new("NERR_TruncatedBroadcast",0x000008F1,"The broadcast message was truncated.")

    # (0x000008F6) This is an invalid device name.
    NERR_InvalidDevice = WindowsError::ErrorCode.new("NERR_InvalidDevice",0x000008F6,"This is an invalid device name.")

    # (0x000008F7) A write fault occurred.
    NERR_WriteFault = WindowsError::ErrorCode.new("NERR_WriteFault",0x000008F7,"A write fault occurred.")

    # (0x000008F9) A duplicate message alias exists on the network.
    NERR_DuplicateName = WindowsError::ErrorCode.new("NERR_DuplicateName",0x000008F9,"A duplicate message alias exists on the network.")

    # (0x000008FA) This message alias will be deleted later.
    NERR_DeleteLater = WindowsError::ErrorCode.new("NERR_DeleteLater",0x000008FA,"This message alias will be deleted later.")

    # (0x000008FB) The message alias was not successfully deleted from all networks.
    NERR_IncompleteDel = WindowsError::ErrorCode.new("NERR_IncompleteDel",0x000008FB,"The message alias was not successfully deleted from all networks.")

    # (0x000008FC) This operation is not supported on computers with multiple networks.
    NERR_MultipleNets = WindowsError::ErrorCode.new("NERR_MultipleNets",0x000008FC,"This operation is not supported on computers with multiple networks.")

    # (0x00000906) This shared resource does not exist.
    NERR_NetNameNotFound = WindowsError::ErrorCode.new("NERR_NetNameNotFound",0x00000906,"This shared resource does not exist.")

    # (0x00000907) This device is not shared.
    NERR_DeviceNotShared = WindowsError::ErrorCode.new("NERR_DeviceNotShared",0x00000907,"This device is not shared.")

    # (0x00000908) A session does not exist with that computer name.
    NERR_ClientNameNotFound = WindowsError::ErrorCode.new("NERR_ClientNameNotFound",0x00000908,"A session does not exist with that computer name.")

    # (0x0000090A) There is not an open file with that identification number.
    NERR_FileIdNotFound = WindowsError::ErrorCode.new("NERR_FileIdNotFound",0x0000090A,"There is not an open file with that identification number.")

    # (0x0000090B) A failure occurred when executing a remote administration command.
    NERR_ExecFailure = WindowsError::ErrorCode.new("NERR_ExecFailure",0x0000090B,"A failure occurred when executing a remote administration command.")

    # (0x0000090C) A failure occurred when opening a remote temporary file.
    NERR_TmpFile = WindowsError::ErrorCode.new("NERR_TmpFile",0x0000090C,"A failure occurred when opening a remote temporary file.")

    # (0x0000090D) The data returned from a remote administration command has been truncated to 64 KB.
    NERR_TooMuchData = WindowsError::ErrorCode.new("NERR_TooMuchData",0x0000090D,"The data returned from a remote administration command has been truncated to 64 KB.")

    # (0x0000090E) This device cannot be shared as both a spooled and a nonspooled resource.
    NERR_DeviceShareConflict = WindowsError::ErrorCode.new("NERR_DeviceShareConflict",0x0000090E,"This device cannot be shared as both a spooled and a nonspooled resource.")

    # (0x0000090F) The information in the list of servers may be incorrect.
    NERR_BrowserTableIncomplete = WindowsError::ErrorCode.new("NERR_BrowserTableIncomplete",0x0000090F,"The information in the list of servers may be incorrect.")

    # (0x00000910) The computer is not active in this domain.
    NERR_NotLocalDomain = WindowsError::ErrorCode.new("NERR_NotLocalDomain",0x00000910,"The computer is not active in this domain.")

    # (0x00000911) The share must be removed from the Distributed File System (DFS) before it can be deleted.
    NERR_IsDfsShare = WindowsError::ErrorCode.new("NERR_IsDfsShare",0x00000911,"The share must be removed from the Distributed File System (DFS) before it can be deleted.")

    # (0x0000091B) The operation is invalid for this device.
    NERR_DevInvalidOpCode = WindowsError::ErrorCode.new("NERR_DevInvalidOpCode",0x0000091B,"The operation is invalid for this device.")

    # (0x0000091C) This device cannot be shared.
    NERR_DevNotFound = WindowsError::ErrorCode.new("NERR_DevNotFound",0x0000091C,"This device cannot be shared.")

    # (0x0000091D) This device was not open.
    NERR_DevNotOpen = WindowsError::ErrorCode.new("NERR_DevNotOpen",0x0000091D,"This device was not open.")

    # (0x0000091E) This device name list is invalid.
    NERR_BadQueueDevString = WindowsError::ErrorCode.new("NERR_BadQueueDevString",0x0000091E,"This device name list is invalid.")

    # (0x0000091F) The queue priority is invalid.
    NERR_BadQueuePriority = WindowsError::ErrorCode.new("NERR_BadQueuePriority",0x0000091F,"The queue priority is invalid.")

    # (0x00000921) There are no shared communication devices.
    NERR_NoCommDevs = WindowsError::ErrorCode.new("NERR_NoCommDevs",0x00000921,"There are no shared communication devices.")

    # (0x00000922) The queue you specified does not exist.
    NERR_QueueNotFound = WindowsError::ErrorCode.new("NERR_QueueNotFound",0x00000922,"The queue you specified does not exist.")

    # (0x00000924) This list of devices is invalid.
    NERR_BadDevString = WindowsError::ErrorCode.new("NERR_BadDevString",0x00000924,"This list of devices is invalid.")

    # (0x00000925) The requested device is invalid.
    NERR_BadDev = WindowsError::ErrorCode.new("NERR_BadDev",0x00000925,"The requested device is invalid.")

    # (0x00000926) This device is already in use by the spooler.
    NERR_InUseBySpooler = WindowsError::ErrorCode.new("NERR_InUseBySpooler",0x00000926,"This device is already in use by the spooler.")

    # (0x00000927) This device is already in use as a communication device.
    NERR_CommDevInUse = WindowsError::ErrorCode.new("NERR_CommDevInUse",0x00000927,"This device is already in use as a communication device.")

    # (0x0000092F) This computer name is invalid.
    NERR_InvalidComputer = WindowsError::ErrorCode.new("NERR_InvalidComputer",0x0000092F,"This computer name is invalid.")

    # (0x00000932) The string and prefix specified are too long.
    NERR_MaxLenExceeded = WindowsError::ErrorCode.new("NERR_MaxLenExceeded",0x00000932,"The string and prefix specified are too long.")

    # (0x00000934) This path component is invalid.
    NERR_BadComponent = WindowsError::ErrorCode.new("NERR_BadComponent",0x00000934,"This path component is invalid.")

    # (0x00000935) Could not determine the type of input.
    NERR_CantType = WindowsError::ErrorCode.new("NERR_CantType",0x00000935,"Could not determine the type of input.")

    # (0x0000093A) The buffer for types is not big enough.
    NERR_TooManyEntries = WindowsError::ErrorCode.new("NERR_TooManyEntries",0x0000093A,"The buffer for types is not big enough.")

    # (0x00000942) Profile files cannot exceed 64 KB.
    NERR_ProfileFileTooBig = WindowsError::ErrorCode.new("NERR_ProfileFileTooBig",0x00000942,"Profile files cannot exceed 64 KB.")

    # (0x00000943) The start offset is out of range.
    NERR_ProfileOffset = WindowsError::ErrorCode.new("NERR_ProfileOffset",0x00000943,"The start offset is out of range.")

    # (0x00000944) The system cannot delete current connections to network resources.
    NERR_ProfileCleanup = WindowsError::ErrorCode.new("NERR_ProfileCleanup",0x00000944,"The system cannot delete current connections to network resources.")

    # (0x00000945) The system was unable to parse the command line in this file.
    NERR_ProfileUnknownCmd = WindowsError::ErrorCode.new("NERR_ProfileUnknownCmd",0x00000945,"The system was unable to parse the command line in this file.")

    # (0x00000946) An error occurred while loading the profile file.
    NERR_ProfileLoadErr = WindowsError::ErrorCode.new("NERR_ProfileLoadErr",0x00000946,"An error occurred while loading the profile file.")

    # (0x00000947) Errors occurred while saving the profile file. The profile was partially saved.
    NERR_ProfileSaveErr = WindowsError::ErrorCode.new("NERR_ProfileSaveErr",0x00000947,"Errors occurred while saving the profile file. The profile was partially saved.")

    # (0x00000949) Log file %1 is full.
    NERR_LogOverflow = WindowsError::ErrorCode.new("NERR_LogOverflow",0x00000949,"Log file %1 is full.")

    # (0x0000094A) This log file has changed between reads.
    NERR_LogFileChanged = WindowsError::ErrorCode.new("NERR_LogFileChanged",0x0000094A,"This log file has changed between reads.")

    # (0x0000094B) Log file %1 is corrupt.
    NERR_LogFileCorrupt = WindowsError::ErrorCode.new("NERR_LogFileCorrupt",0x0000094B,"Log file %1 is corrupt.")

    # (0x0000094C) The source path cannot be a directory.
    NERR_SourceIsDir = WindowsError::ErrorCode.new("NERR_SourceIsDir",0x0000094C,"The source path cannot be a directory.")

    # (0x0000094D) The source path is illegal.
    NERR_BadSource = WindowsError::ErrorCode.new("NERR_BadSource",0x0000094D,"The source path is illegal.")

    # (0x0000094E) The destination path is illegal.
    NERR_BadDest = WindowsError::ErrorCode.new("NERR_BadDest",0x0000094E,"The destination path is illegal.")

    # (0x0000094F) The source and destination paths are on different servers.
    NERR_DifferentServers = WindowsError::ErrorCode.new("NERR_DifferentServers",0x0000094F,"The source and destination paths are on different servers.")

    # (0x00000951) The Run server you requested is paused.
    NERR_RunSrvPaused = WindowsError::ErrorCode.new("NERR_RunSrvPaused",0x00000951,"The Run server you requested is paused.")

    # (0x00000955) An error occurred when communicating with a Run server.
    NERR_ErrCommRunSrv = WindowsError::ErrorCode.new("NERR_ErrCommRunSrv",0x00000955,"An error occurred when communicating with a Run server.")

    # (0x00000957) An error occurred when starting a background process.
    NERR_ErrorExecingGhost = WindowsError::ErrorCode.new("NERR_ErrorExecingGhost",0x00000957,"An error occurred when starting a background process.")

    # (0x00000958) The shared resource you are connected to could not be found.
    NERR_ShareNotFound = WindowsError::ErrorCode.new("NERR_ShareNotFound",0x00000958,"The shared resource you are connected to could not be found.")

    # (0x00000960) The LAN adapter number is invalid.
    NERR_InvalidLana = WindowsError::ErrorCode.new("NERR_InvalidLana",0x00000960,"The LAN adapter number is invalid.")

    # (0x00000961) There are open files on the connection.
    NERR_OpenFiles = WindowsError::ErrorCode.new("NERR_OpenFiles",0x00000961,"There are open files on the connection.")

    # (0x00000962) Active connections still exist.
    NERR_ActiveConns = WindowsError::ErrorCode.new("NERR_ActiveConns",0x00000962,"Active connections still exist.")

    # (0x00000963) This share name or password is invalid.
    NERR_BadPasswordCore = WindowsError::ErrorCode.new("NERR_BadPasswordCore",0x00000963,"This share name or password is invalid.")

    # (0x00000964) The device is being accessed by an active process.
    NERR_DevInUse = WindowsError::ErrorCode.new("NERR_DevInUse",0x00000964,"The device is being accessed by an active process.")

    # (0x00000965) The drive letter is in use locally.
    NERR_LocalDrive = WindowsError::ErrorCode.new("NERR_LocalDrive",0x00000965,"The drive letter is in use locally.")

    # (0x0000097E) The specified client is already registered for the specified event.
    NERR_AlertExists = WindowsError::ErrorCode.new("NERR_AlertExists",0x0000097E,"The specified client is already registered for the specified event.")

    # (0x0000097F) The alert table is full.
    NERR_TooManyAlerts = WindowsError::ErrorCode.new("NERR_TooManyAlerts",0x0000097F,"The alert table is full.")

    # (0x00000980) An invalid or nonexistent alert name was raised.
    NERR_NoSuchAlert = WindowsError::ErrorCode.new("NERR_NoSuchAlert",0x00000980,"An invalid or nonexistent alert name was raised.")

    # (0x00000981) The alert recipient is invalid.
    NERR_BadRecipient = WindowsError::ErrorCode.new("NERR_BadRecipient",0x00000981,"The alert recipient is invalid.")

    # (0x00000982) A user's session with this server has been deleted.
    NERR_AcctLimitExceeded = WindowsError::ErrorCode.new("NERR_AcctLimitExceeded",0x00000982,"A user's session with this server has been deleted.")

    # (0x00000988) The log file does not contain the requested record number.
    NERR_InvalidLogSeek = WindowsError::ErrorCode.new("NERR_InvalidLogSeek",0x00000988,"The log file does not contain the requested record number.")

    # (0x00000992) The user accounts database is not configured correctly.
    NERR_BadUasConfig = WindowsError::ErrorCode.new("NERR_BadUasConfig",0x00000992,"The user accounts database is not configured correctly.")

    # (0x00000993) This operation is not permitted when the Net Logon service is running.
    NERR_InvalidUASOp = WindowsError::ErrorCode.new("NERR_InvalidUASOp",0x00000993,"This operation is not permitted when the Net Logon service is running.")

    # (0x00000994) This operation is not allowed on the last administrative account.
    NERR_LastAdmin = WindowsError::ErrorCode.new("NERR_LastAdmin",0x00000994,"This operation is not allowed on the last administrative account.")

    # (0x00000995) Could not find the domain controller for this domain.
    NERR_DCNotFound = WindowsError::ErrorCode.new("NERR_DCNotFound",0x00000995,"Could not find the domain controller for this domain.")

    # (0x00000996) Could not set logon information for this user.
    NERR_LogonTrackingError = WindowsError::ErrorCode.new("NERR_LogonTrackingError",0x00000996,"Could not set logon information for this user.")

    # (0x00000997) The Net Logon service has not been started.
    NERR_NetlogonNotStarted = WindowsError::ErrorCode.new("NERR_NetlogonNotStarted",0x00000997,"The Net Logon service has not been started.")

    # (0x00000998) Unable to add to the user accounts database.
    NERR_CanNotGrowUASFile = WindowsError::ErrorCode.new("NERR_CanNotGrowUASFile",0x00000998,"Unable to add to the user accounts database.")

    # (0x00000999) This server's clock is not synchronized with the PDC's clock.
    NERR_TimeDiffAtDC = WindowsError::ErrorCode.new("NERR_TimeDiffAtDC",0x00000999,"This server's clock is not synchronized with the PDC's clock.")

    # (0x0000099A) A password mismatch has been detected.
    NERR_PasswordMismatch = WindowsError::ErrorCode.new("NERR_PasswordMismatch",0x0000099A,"A password mismatch has been detected.")

    # (0x0000099C) The server identification does not specify a valid server.
    NERR_NoSuchServer = WindowsError::ErrorCode.new("NERR_NoSuchServer",0x0000099C,"The server identification does not specify a valid server.")

    # (0x0000099D) The session identification does not specify a valid session.
    NERR_NoSuchSession = WindowsError::ErrorCode.new("NERR_NoSuchSession",0x0000099D,"The session identification does not specify a valid session.")

    # (0x0000099E) The connection identification does not specify a valid connection.
    NERR_NoSuchConnection = WindowsError::ErrorCode.new("NERR_NoSuchConnection",0x0000099E,"The connection identification does not specify a valid connection.")

    # (0x0000099F) There is no space for another entry in the table of available servers.
    NERR_TooManyServers = WindowsError::ErrorCode.new("NERR_TooManyServers",0x0000099F,"There is no space for another entry in the table of available servers.")

    # (0x000009A0) The server has reached the maximum number of sessions it supports.
    NERR_TooManySessions = WindowsError::ErrorCode.new("NERR_TooManySessions",0x000009A0,"The server has reached the maximum number of sessions it supports.")

    # (0x000009A1) The server has reached the maximum number of connections it supports.
    NERR_TooManyConnections = WindowsError::ErrorCode.new("NERR_TooManyConnections",0x000009A1,"The server has reached the maximum number of connections it supports.")

    # (0x000009A2) The server cannot open more files because it has reached its maximum number.
    NERR_TooManyFiles = WindowsError::ErrorCode.new("NERR_TooManyFiles",0x000009A2,"The server cannot open more files because it has reached its maximum number.")

    # (0x000009A3) There are no alternate servers registered on this server.
    NERR_NoAlternateServers = WindowsError::ErrorCode.new("NERR_NoAlternateServers",0x000009A3,"There are no alternate servers registered on this server.")

    # (0x000009A6) Try the down-level (remote admin protocol) version of API instead.
    NERR_TryDownLevel = WindowsError::ErrorCode.new("NERR_TryDownLevel",0x000009A6,"Try the down-level (remote admin protocol) version of API instead.")

    # (0x000009B0) The uninterruptible power supply (UPS) driver could not be accessed by the UPS service.
    NERR_UPSDriverNotStarted = WindowsError::ErrorCode.new("NERR_UPSDriverNotStarted",0x000009B0,"The uninterruptible power supply (UPS) driver could not be accessed by the UPS service.")

    # (0x000009B1) The UPS service is not configured correctly.
    NERR_UPSInvalidConfig = WindowsError::ErrorCode.new("NERR_UPSInvalidConfig",0x000009B1,"The UPS service is not configured correctly.")

    # (0x000009B2) The UPS service could not access the specified Comm Port.
    NERR_UPSInvalidCommPort = WindowsError::ErrorCode.new("NERR_UPSInvalidCommPort",0x000009B2,"The UPS service could not access the specified Comm Port.")

    # (0x000009B3) The UPS indicated a line fail or low battery situation. Service not started.
    NERR_UPSSignalAsserted = WindowsError::ErrorCode.new("NERR_UPSSignalAsserted",0x000009B3,"The UPS indicated a line fail or low battery situation. Service not started.")

    # (0x000009B4) The UPS service failed to perform a system shut down.
    NERR_UPSShutdownFailed = WindowsError::ErrorCode.new("NERR_UPSShutdownFailed",0x000009B4,"The UPS service failed to perform a system shut down.")

    # (0x000009C4) The program below returned an MS-DOS error code.
    NERR_BadDosRetCode = WindowsError::ErrorCode.new("NERR_BadDosRetCode",0x000009C4,"The program below returned an MS-DOS error code.")

    # (0x000009C5) The program below needs more memory.
    NERR_ProgNeedsExtraMem = WindowsError::ErrorCode.new("NERR_ProgNeedsExtraMem",0x000009C5,"The program below needs more memory.")

    # (0x000009C6) The program below called an unsupported MS-DOS function.
    NERR_BadDosFunction = WindowsError::ErrorCode.new("NERR_BadDosFunction",0x000009C6,"The program below called an unsupported MS-DOS function.")

    # (0x000009C7) The workstation failed to boot.
    NERR_RemoteBootFailed = WindowsError::ErrorCode.new("NERR_RemoteBootFailed",0x000009C7,"The workstation failed to boot.")

    # (0x000009C8) The file below is corrupt.
    NERR_BadFileCheckSum = WindowsError::ErrorCode.new("NERR_BadFileCheckSum",0x000009C8,"The file below is corrupt.")

    # (0x000009C9) No loader is specified in the boot-block definition file.
    NERR_NoRplBootSystem = WindowsError::ErrorCode.new("NERR_NoRplBootSystem",0x000009C9,"No loader is specified in the boot-block definition file.")

    # (0x000009CA) NetBIOS returned an error: The network control blocks (NCBs) and Server Message Block (SMB) are dumped above.
    NERR_RplLoadrNetBiosErr = WindowsError::ErrorCode.new("NERR_RplLoadrNetBiosErr",0x000009CA,"NetBIOS returned an error: The network control blocks (NCBs) and Server Message Block (SMB) are dumped above.")

    # (0x000009CB) A disk I/O error occurred.
    NERR_RplLoadrDiskErr = WindowsError::ErrorCode.new("NERR_RplLoadrDiskErr",0x000009CB,"A disk I/O error occurred.")

    # (0x000009CC) Image parameter substitution failed.
    NERR_ImageParamErr = WindowsError::ErrorCode.new("NERR_ImageParamErr",0x000009CC,"Image parameter substitution failed.")

    # (0x000009CD) Too many image parameters cross disk sector boundaries.
    NERR_TooManyImageParams = WindowsError::ErrorCode.new("NERR_TooManyImageParams",0x000009CD,"Too many image parameters cross disk sector boundaries.")

    # (0x000009CE) The image was not generated from an MS-DOS disk formatted with /S.
    NERR_NonDosFloppyUsed = WindowsError::ErrorCode.new("NERR_NonDosFloppyUsed",0x000009CE,"The image was not generated from an MS-DOS disk formatted with /S.")

    # (0x000009CF) Remote boot will be restarted later.
    NERR_RplBootRestart = WindowsError::ErrorCode.new("NERR_RplBootRestart",0x000009CF,"Remote boot will be restarted later.")

    # (0x000009D0) The call to the Remoteboot server failed.
    NERR_RplSrvrCallFailed = WindowsError::ErrorCode.new("NERR_RplSrvrCallFailed",0x000009D0,"The call to the Remoteboot server failed.")

    # (0x000009D1) Cannot connect to the Remoteboot server.
    NERR_CantConnectRplSrvr = WindowsError::ErrorCode.new("NERR_CantConnectRplSrvr",0x000009D1,"Cannot connect to the Remoteboot server.")

    # (0x000009D2) Cannot open image file on the Remoteboot server.
    NERR_CantOpenImageFile = WindowsError::ErrorCode.new("NERR_CantOpenImageFile",0x000009D2,"Cannot open image file on the Remoteboot server.")

    # (0x000009D3) Connecting to the Remoteboot server.
    NERR_CallingRplSrvr = WindowsError::ErrorCode.new("NERR_CallingRplSrvr",0x000009D3,"Connecting to the Remoteboot server.")

    # (0x000009D4) Connecting to the Remoteboot server.
    NERR_StartingRplBoot = WindowsError::ErrorCode.new("NERR_StartingRplBoot",0x000009D4,"Connecting to the Remoteboot server.")

    # (0x000009D5) Remote boot service was stopped, check the error log for the cause of the problem.
    NERR_RplBootServiceTerm = WindowsError::ErrorCode.new("NERR_RplBootServiceTerm",0x000009D5,"Remote boot service was stopped, check the error log for the cause of the problem.")

    # (0x000009D6) Remote boot startup failed; check the error log for the cause of the problem.
    NERR_RplBootStartFailed = WindowsError::ErrorCode.new("NERR_RplBootStartFailed",0x000009D6,"Remote boot startup failed; check the error log for the cause of the problem.")

    # (0x000009D7) A second connection to a Remoteboot resource is not allowed.
    NERR_RPL_CONNECTED = WindowsError::ErrorCode.new("NERR_RPL_CONNECTED",0x000009D7,"A second connection to a Remoteboot resource is not allowed.")

    # (0x000009F6) The browser service was configured with MaintainServerList=No.
    NERR_BrowserConfiguredToNotRun = WindowsError::ErrorCode.new("NERR_BrowserConfiguredToNotRun",0x000009F6,"The browser service was configured with MaintainServerList=No.")

    # (0x00000A32) Service failed to start because none of the network adapters started with this service.
    NERR_RplNoAdaptersStarted = WindowsError::ErrorCode.new("NERR_RplNoAdaptersStarted",0x00000A32,"Service failed to start because none of the network adapters started with this service.")

    # (0x00000A33) Service failed to start due to bad startup information in the registry.
    NERR_RplBadRegistry = WindowsError::ErrorCode.new("NERR_RplBadRegistry",0x00000A33,"Service failed to start due to bad startup information in the registry.")

    # (0x00000A34) Service failed to start because its database is absent or corrupt.
    NERR_RplBadDatabase = WindowsError::ErrorCode.new("NERR_RplBadDatabase",0x00000A34,"Service failed to start because its database is absent or corrupt.")

    # (0x00000A35) Service failed to start because the RPLFILES share is absent.
    NERR_RplRplfilesShare = WindowsError::ErrorCode.new("NERR_RplRplfilesShare",0x00000A35,"Service failed to start because the RPLFILES share is absent.")

    # (0x00000A36) Service failed to start because the RPLUSER group is absent.
    NERR_RplNotRplServer = WindowsError::ErrorCode.new("NERR_RplNotRplServer",0x00000A36,"Service failed to start because the RPLUSER group is absent.")

    # (0x00000A37) Cannot enumerate service records.
    NERR_RplCannotEnum = WindowsError::ErrorCode.new("NERR_RplCannotEnum",0x00000A37,"Cannot enumerate service records.")

    # (0x00000A38) Workstation record information has been corrupted.
    NERR_RplWkstaInfoCorrupted = WindowsError::ErrorCode.new("NERR_RplWkstaInfoCorrupted",0x00000A38,"Workstation record information has been corrupted.")

    # (0x00000A39) Workstation record was not found.
    NERR_RplWkstaNotFound = WindowsError::ErrorCode.new("NERR_RplWkstaNotFound",0x00000A39,"Workstation record was not found.")

    # (0x00000A3A) Workstation name is in use by some other workstation.
    NERR_RplWkstaNameUnavailable = WindowsError::ErrorCode.new("NERR_RplWkstaNameUnavailable",0x00000A3A,"Workstation name is in use by some other workstation.")

    # (0x00000A3B) Profile record information has been corrupted.
    NERR_RplProfileInfoCorrupted = WindowsError::ErrorCode.new("NERR_RplProfileInfoCorrupted",0x00000A3B,"Profile record information has been corrupted.")

    # (0x00000A3C) Profile record was not found.
    NERR_RplProfileNotFound = WindowsError::ErrorCode.new("NERR_RplProfileNotFound",0x00000A3C,"Profile record was not found.")

    # (0x00000A3D) Profile name is in use by some other profile.
    NERR_RplProfileNameUnavailable = WindowsError::ErrorCode.new("NERR_RplProfileNameUnavailable",0x00000A3D,"Profile name is in use by some other profile.")

    # (0x00000A3E) There are workstations using this profile.
    NERR_RplProfileNotEmpty = WindowsError::ErrorCode.new("NERR_RplProfileNotEmpty",0x00000A3E,"There are workstations using this profile.")

    # (0x00000A3F) Configuration record information has been corrupted.
    NERR_RplConfigInfoCorrupted = WindowsError::ErrorCode.new("NERR_RplConfigInfoCorrupted",0x00000A3F,"Configuration record information has been corrupted.")

    # (0x00000A40) Configuration record was not found.
    NERR_RplConfigNotFound = WindowsError::ErrorCode.new("NERR_RplConfigNotFound",0x00000A40,"Configuration record was not found.")

    # (0x00000A41) Adapter ID record information has been corrupted.
    NERR_RplAdapterInfoCorrupted = WindowsError::ErrorCode.new("NERR_RplAdapterInfoCorrupted",0x00000A41,"Adapter ID record information has been corrupted.")

    # (0x00000A42) An internal service error has occurred.
    NERR_RplInternal = WindowsError::ErrorCode.new("NERR_RplInternal",0x00000A42,"An internal service error has occurred.")

    # (0x00000A43) Vendor ID record information has been corrupted.
    NERR_RplVendorInfoCorrupted = WindowsError::ErrorCode.new("NERR_RplVendorInfoCorrupted",0x00000A43,"Vendor ID record information has been corrupted.")

    # (0x00000A44) Boot block record information has been corrupted.
    NERR_RplBootInfoCorrupted = WindowsError::ErrorCode.new("NERR_RplBootInfoCorrupted",0x00000A44,"Boot block record information has been corrupted.")

    # (0x00000A45) The user account for this workstation record is missing.
    NERR_RplWkstaNeedsUserAcct = WindowsError::ErrorCode.new("NERR_RplWkstaNeedsUserAcct",0x00000A45,"The user account for this workstation record is missing.")

    # (0x00000A46) The RPLUSER local group could not be found.
    NERR_RplNeedsRPLUSERAcct = WindowsError::ErrorCode.new("NERR_RplNeedsRPLUSERAcct",0x00000A46,"The RPLUSER local group could not be found.")

    # (0x00000A47) Boot block record was not found.
    NERR_RplBootNotFound = WindowsError::ErrorCode.new("NERR_RplBootNotFound",0x00000A47,"Boot block record was not found.")

    # (0x00000A48) Chosen profile is incompatible with this workstation.
    NERR_RplIncompatibleProfile = WindowsError::ErrorCode.new("NERR_RplIncompatibleProfile",0x00000A48,"Chosen profile is incompatible with this workstation.")

    # (0x00000A49) Chosen network adapter ID is in use by some other workstation.
    NERR_RplAdapterNameUnavailable = WindowsError::ErrorCode.new("NERR_RplAdapterNameUnavailable",0x00000A49,"Chosen network adapter ID is in use by some other workstation.")

    # (0x00000A4A) There are profiles using this configuration.
    NERR_RplConfigNotEmpty = WindowsError::ErrorCode.new("NERR_RplConfigNotEmpty",0x00000A4A,"There are profiles using this configuration.")

    # (0x00000A4B) There are workstations, profiles, or configurations using this boot block.
    NERR_RplBootInUse = WindowsError::ErrorCode.new("NERR_RplBootInUse",0x00000A4B,"There are workstations, profiles, or configurations using this boot block.")

    # (0x00000A4C) Service failed to back up the Remoteboot database.
    NERR_RplBackupDatabase = WindowsError::ErrorCode.new("NERR_RplBackupDatabase",0x00000A4C,"Service failed to back up the Remoteboot database.")

    # (0x00000A4D) Adapter record was not found.
    NERR_RplAdapterNotFound = WindowsError::ErrorCode.new("NERR_RplAdapterNotFound",0x00000A4D,"Adapter record was not found.")

    # (0x00000A4E) Vendor record was not found.
    NERR_RplVendorNotFound = WindowsError::ErrorCode.new("NERR_RplVendorNotFound",0x00000A4E,"Vendor record was not found.")

    # (0x00000A4F) Vendor name is in use by some other vendor record.
    NERR_RplVendorNameUnavailable = WindowsError::ErrorCode.new("NERR_RplVendorNameUnavailable",0x00000A4F,"Vendor name is in use by some other vendor record.")

    # (0x00000A50) The boot name or vendor ID is in use by some other boot block record.
    NERR_RplBootNameUnavailable = WindowsError::ErrorCode.new("NERR_RplBootNameUnavailable",0x00000A50,"The boot name or vendor ID is in use by some other boot block record.")

    # (0x00000A51) The configuration name is in use by some other configuration.
    NERR_RplConfigNameUnavailable = WindowsError::ErrorCode.new("NERR_RplConfigNameUnavailable",0x00000A51,"The configuration name is in use by some other configuration.")

    # (0x00000A64) The internal database maintained by the DFS service is corrupt.
    NERR_DfsInternalCorruption = WindowsError::ErrorCode.new("NERR_DfsInternalCorruption",0x00000A64,"The internal database maintained by the DFS service is corrupt.")

    # (0x00000A65) One of the records in the internal DFS database is corrupt.
    NERR_DfsVolumeDataCorrupt = WindowsError::ErrorCode.new("NERR_DfsVolumeDataCorrupt",0x00000A65,"One of the records in the internal DFS database is corrupt.")

    # (0x00000A66) There is no DFS name whose entry path matches the input entry path.
    NERR_DfsNoSuchVolume = WindowsError::ErrorCode.new("NERR_DfsNoSuchVolume",0x00000A66,"There is no DFS name whose entry path matches the input entry path.")

    # (0x00000A67) A root or link with the given name already exists.
    NERR_DfsVolumeAlreadyExists = WindowsError::ErrorCode.new("NERR_DfsVolumeAlreadyExists",0x00000A67,"A root or link with the given name already exists.")

    # (0x00000A68) The server share specified is already shared in the DFS.
    NERR_DfsAlreadyShared = WindowsError::ErrorCode.new("NERR_DfsAlreadyShared",0x00000A68,"The server share specified is already shared in the DFS.")

    # (0x00000A69) The indicated server share does not support the indicated DFS namespace.
    NERR_DfsNoSuchShare = WindowsError::ErrorCode.new("NERR_DfsNoSuchShare",0x00000A69,"The indicated server share does not support the indicated DFS namespace.")

    # (0x00000A6A) The operation is not valid in this portion of the namespace.
    NERR_DfsNotALeafVolume = WindowsError::ErrorCode.new("NERR_DfsNotALeafVolume",0x00000A6A,"The operation is not valid in this portion of the namespace.")

    # (0x00000A6B) The operation is not valid in this portion of the namespace.
    NERR_DfsLeafVolume = WindowsError::ErrorCode.new("NERR_DfsLeafVolume",0x00000A6B,"The operation is not valid in this portion of the namespace.")

    # (0x00000A6C) The operation is ambiguous because the link has multiple servers.
    NERR_DfsVolumeHasMultipleServers = WindowsError::ErrorCode.new("NERR_DfsVolumeHasMultipleServers",0x00000A6C,"The operation is ambiguous because the link has multiple servers.")

    # (0x00000A6D) Unable to create a link.
    NERR_DfsCantCreateJunctionPoint = WindowsError::ErrorCode.new("NERR_DfsCantCreateJunctionPoint",0x00000A6D,"Unable to create a link.")

    # (0x00000A6E) The server is not DFS-aware.
    NERR_DfsServerNotDfsAware = WindowsError::ErrorCode.new("NERR_DfsServerNotDfsAware",0x00000A6E,"The server is not DFS-aware.")

    # (0x00000A6F) The specified rename target path is invalid.
    NERR_DfsBadRenamePath = WindowsError::ErrorCode.new("NERR_DfsBadRenamePath",0x00000A6F,"The specified rename target path is invalid.")

    # (0x00000A70) The specified DFS link is offline.
    NERR_DfsVolumeIsOffline = WindowsError::ErrorCode.new("NERR_DfsVolumeIsOffline",0x00000A70,"The specified DFS link is offline.")

    # (0x00000A71) The specified server is not a server for this link.
    NERR_DfsNoSuchServer = WindowsError::ErrorCode.new("NERR_DfsNoSuchServer",0x00000A71,"The specified server is not a server for this link.")

    # (0x00000A72) A cycle in the DFS name was detected.
    NERR_DfsCyclicalName = WindowsError::ErrorCode.new("NERR_DfsCyclicalName",0x00000A72,"A cycle in the DFS name was detected.")

    # (0x00000A73) The operation is not supported on a server-based DFS.
    NERR_DfsNotSupportedInServerDfs = WindowsError::ErrorCode.new("NERR_DfsNotSupportedInServerDfs",0x00000A73,"The operation is not supported on a server-based DFS.")

    # (0x00000A74) This link is already supported by the specified server share.
    NERR_DfsDuplicateService = WindowsError::ErrorCode.new("NERR_DfsDuplicateService",0x00000A74,"This link is already supported by the specified server share.")

    # (0x00000A75) Cannot remove the last server share supporting this root or link.
    NERR_DfsCantRemoveLastServerShare = WindowsError::ErrorCode.new("NERR_DfsCantRemoveLastServerShare",0x00000A75,"Cannot remove the last server share supporting this root or link.")

    # (0x00000A76) The operation is not supported for an inter-DFS link.
    NERR_DfsVolumeIsInterDfs = WindowsError::ErrorCode.new("NERR_DfsVolumeIsInterDfs",0x00000A76,"The operation is not supported for an inter-DFS link.")

    # (0x00000A77) The internal state of the DFS Service has become inconsistent.
    NERR_DfsInconsistent = WindowsError::ErrorCode.new("NERR_DfsInconsistent",0x00000A77,"The internal state of the DFS Service has become inconsistent.")

    # (0x00000A78) The DFS Service has been installed on the specified server.
    NERR_DfsServerUpgraded = WindowsError::ErrorCode.new("NERR_DfsServerUpgraded",0x00000A78,"The DFS Service has been installed on the specified server.")

    # (0x00000A79) The DFS data being reconciled is identical.
    NERR_DfsDataIsIdentical = WindowsError::ErrorCode.new("NERR_DfsDataIsIdentical",0x00000A79,"The DFS data being reconciled is identical.")

    # (0x00000A7A) The DFS root cannot be deleted. Uninstall DFS if required.
    NERR_DfsCantRemoveDfsRoot = WindowsError::ErrorCode.new("NERR_DfsCantRemoveDfsRoot",0x00000A7A,"The DFS root cannot be deleted. Uninstall DFS if required.")

    # (0x00000A7B) A child or parent directory of the share is already in a DFS.
    NERR_DfsChildOrParentInDfs = WindowsError::ErrorCode.new("NERR_DfsChildOrParentInDfs",0x00000A7B,"A child or parent directory of the share is already in a DFS.")

    # (0x00000A82) DFS internal error.
    NERR_DfsInternalError = WindowsError::ErrorCode.new("NERR_DfsInternalError",0x00000A82,"DFS internal error.")

    # (0x00000A83) This machine is already joined to a domain.
    NERR_SetupAlreadyJoined = WindowsError::ErrorCode.new("NERR_SetupAlreadyJoined",0x00000A83,"This machine is already joined to a domain.")

    # (0x00000A84) This machine is not currently joined to a domain.
    NERR_SetupNotJoined = WindowsError::ErrorCode.new("NERR_SetupNotJoined",0x00000A84,"This machine is not currently joined to a domain.")

    # (0x00000A85) This machine is a domain controller and cannot be unjoined from a domain.
    NERR_SetupDomainController = WindowsError::ErrorCode.new("NERR_SetupDomainController",0x00000A85,"This machine is a domain controller and cannot be unjoined from a domain.")

    # (0x00000A86) The destination domain controller does not support creating machine accounts in organizational units (OUs).
    NERR_DefaultJoinRequired = WindowsError::ErrorCode.new("NERR_DefaultJoinRequired",0x00000A86,"The destination domain controller does not support creating machine accounts in organizational units (OUs).")

    # (0x00000A87) The specified workgroup name is invalid.
    NERR_InvalidWorkgroupName = WindowsError::ErrorCode.new("NERR_InvalidWorkgroupName",0x00000A87,"The specified workgroup name is invalid.")

    # (0x00000A88) The specified computer name is incompatible with the default language used on the domain controller.
    NERR_NameUsesIncompatibleCodePage = WindowsError::ErrorCode.new("NERR_NameUsesIncompatibleCodePage",0x00000A88,"The specified computer name is incompatible with the default language used on the domain controller.")

    # (0x00000A89) The specified computer account could not be found.
    NERR_ComputerAccountNotFound = WindowsError::ErrorCode.new("NERR_ComputerAccountNotFound",0x00000A89,"The specified computer account could not be found.")

    # (0x00000A8A) This version of Windows cannot be joined to a domain.
    NERR_PersonalSku = WindowsError::ErrorCode.new("NERR_PersonalSku",0x00000A8A,"This version of Windows cannot be joined to a domain.")

    # (0x00000A8D) The password must change at the next logon.
    NERR_PasswordMustChange = WindowsError::ErrorCode.new("NERR_PasswordMustChange",0x00000A8D,"The password must change at the next logon.")

    # (0x00000A8E) The account is locked out.
    NERR_AccountLockedOut = WindowsError::ErrorCode.new("NERR_AccountLockedOut",0x00000A8E,"The account is locked out.")

    # (0x00000A8F) The password is too long.
    NERR_PasswordTooLong = WindowsError::ErrorCode.new("NERR_PasswordTooLong",0x00000A8F,"The password is too long.")

    # (0x00000A90) The password does not meet the complexity policy.
    NERR_PasswordNotComplexEnough = WindowsError::ErrorCode.new("NERR_PasswordNotComplexEnough",0x00000A90,"The password does not meet the complexity policy.")

    # (0x00000A91) The password does not meet the requirements of the password filter DLLs.
    NERR_PasswordFilterError = WindowsError::ErrorCode.new("NERR_PasswordFilterError",0x00000A91,"The password does not meet the requirements of the password filter DLLs.")

    # (0x00000BB8) The specified print monitor is unknown.
    ERROR_UNKNOWN_PRINT_MONITOR = WindowsError::ErrorCode.new("ERROR_UNKNOWN_PRINT_MONITOR",0x00000BB8,"The specified print monitor is unknown.")

    # (0x00000BB9) The specified printer driver is currently in use.
    ERROR_PRINTER_DRIVER_IN_USE = WindowsError::ErrorCode.new("ERROR_PRINTER_DRIVER_IN_USE",0x00000BB9,"The specified printer driver is currently in use.")

    # (0x00000BBA) The spool file was not found.
    ERROR_SPOOL_FILE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_SPOOL_FILE_NOT_FOUND",0x00000BBA,"The spool file was not found.")

    # (0x00000BBB) A StartDocPrinter call was not issued.
    ERROR_SPL_NO_STARTDOC = WindowsError::ErrorCode.new("ERROR_SPL_NO_STARTDOC",0x00000BBB,"A StartDocPrinter call was not issued.")

    # (0x00000BBC) An AddJob call was not issued.
    ERROR_SPL_NO_ADDJOB = WindowsError::ErrorCode.new("ERROR_SPL_NO_ADDJOB",0x00000BBC,"An AddJob call was not issued.")

    # (0x00000BBD) The specified print processor has already been installed.
    ERROR_PRINT_PROCESSOR_ALREADY_INSTALLED = WindowsError::ErrorCode.new("ERROR_PRINT_PROCESSOR_ALREADY_INSTALLED",0x00000BBD,"The specified print processor has already been installed.")

    # (0x00000BBE) The specified print monitor has already been installed.
    ERROR_PRINT_MONITOR_ALREADY_INSTALLED = WindowsError::ErrorCode.new("ERROR_PRINT_MONITOR_ALREADY_INSTALLED",0x00000BBE,"The specified print monitor has already been installed.")

    # (0x00000BBF) The specified print monitor does not have the required functions.
    ERROR_INVALID_PRINT_MONITOR = WindowsError::ErrorCode.new("ERROR_INVALID_PRINT_MONITOR",0x00000BBF,"The specified print monitor does not have the required functions.")

    # (0x00000BC0) The specified print monitor is currently in use.
    ERROR_PRINT_MONITOR_IN_USE = WindowsError::ErrorCode.new("ERROR_PRINT_MONITOR_IN_USE",0x00000BC0,"The specified print monitor is currently in use.")

    # (0x00000BC1) The requested operation is not allowed when there are jobs queued to the printer.
    ERROR_PRINTER_HAS_JOBS_QUEUED = WindowsError::ErrorCode.new("ERROR_PRINTER_HAS_JOBS_QUEUED",0x00000BC1,"The requested operation is not allowed when there are jobs queued to the printer.")

    # (0x00000BC2) The requested operation is successful. Changes will not be effective until the system is rebooted.
    ERROR_SUCCESS_REBOOT_REQUIRED = WindowsError::ErrorCode.new("ERROR_SUCCESS_REBOOT_REQUIRED",0x00000BC2,"The requested operation is successful. Changes will not be effective until the system is rebooted.")

    # (0x00000BC3) The requested operation is successful. Changes will not be effective until the service is restarted.
    ERROR_SUCCESS_RESTART_REQUIRED = WindowsError::ErrorCode.new("ERROR_SUCCESS_RESTART_REQUIRED",0x00000BC3,"The requested operation is successful. Changes will not be effective until the service is restarted.")

    # (0x00000BC4) No printers were found.
    ERROR_PRINTER_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_PRINTER_NOT_FOUND",0x00000BC4,"No printers were found.")

    # (0x00000BC5) The printer driver is known to be unreliable.
    ERROR_PRINTER_DRIVER_WARNED = WindowsError::ErrorCode.new("ERROR_PRINTER_DRIVER_WARNED",0x00000BC5,"The printer driver is known to be unreliable.")

    # (0x00000BC6) The printer driver is known to harm the system.
    ERROR_PRINTER_DRIVER_BLOCKED = WindowsError::ErrorCode.new("ERROR_PRINTER_DRIVER_BLOCKED",0x00000BC6,"The printer driver is known to harm the system.")

    # (0x00000BC7) The specified printer driver package is currently in use.
    ERROR_PRINTER_DRIVER_PACKAGE_IN_USE = WindowsError::ErrorCode.new("ERROR_PRINTER_DRIVER_PACKAGE_IN_USE",0x00000BC7,"The specified printer driver package is currently in use.")

    # (0x00000BC8) Unable to find a core driver package that is required by the printer driver package.
    ERROR_CORE_DRIVER_PACKAGE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_CORE_DRIVER_PACKAGE_NOT_FOUND",0x00000BC8,"Unable to find a core driver package that is required by the printer driver package.")

    # (0x00000BC9) The requested operation failed. A system reboot is required to roll back changes made.
    ERROR_FAIL_REBOOT_REQUIRED = WindowsError::ErrorCode.new("ERROR_FAIL_REBOOT_REQUIRED",0x00000BC9,"The requested operation failed. A system reboot is required to roll back changes made.")

    # (0x00000BCA) The requested operation failed. A system reboot has been initiated to roll back changes made.
    ERROR_FAIL_REBOOT_INITIATED = WindowsError::ErrorCode.new("ERROR_FAIL_REBOOT_INITIATED",0x00000BCA,"The requested operation failed. A system reboot has been initiated to roll back changes made.")

    # (0x00000F6E) Reissue the given operation as a cached I/O operation.
    ERROR_IO_REISSUE_AS_CACHED = WindowsError::ErrorCode.new("ERROR_IO_REISSUE_AS_CACHED",0x00000F6E,"Reissue the given operation as a cached I/O operation.")

    # (0x00000FA0) Windows Internet Name Service (WINS) encountered an error while processing the command.
    ERROR_WINS_INTERNAL = WindowsError::ErrorCode.new("ERROR_WINS_INTERNAL",0x00000FA0,"Windows Internet Name Service (WINS) encountered an error while processing the command.")

    # (0x00000FA1) The local WINS cannot be deleted.
    ERROR_CAN_NOT_DEL_LOCAL_WINS = WindowsError::ErrorCode.new("ERROR_CAN_NOT_DEL_LOCAL_WINS",0x00000FA1,"The local WINS cannot be deleted.")

    # (0x00000FA2) The importation from the file failed.
    ERROR_STATIC_INIT = WindowsError::ErrorCode.new("ERROR_STATIC_INIT",0x00000FA2,"The importation from the file failed.")

    # (0x00000FA3) The backup failed. Was a full backup done before?
    ERROR_INC_BACKUP = WindowsError::ErrorCode.new("ERROR_INC_BACKUP",0x00000FA3,"The backup failed. Was a full backup done before?")

    # (0x00000FA4) The backup failed. Check the directory to which you are backing the database.
    ERROR_FULL_BACKUP = WindowsError::ErrorCode.new("ERROR_FULL_BACKUP",0x00000FA4,"The backup failed. Check the directory to which you are backing the database.")

    # (0x00000FA5) The name does not exist in the WINS database.
    ERROR_REC_NON_EXISTENT = WindowsError::ErrorCode.new("ERROR_REC_NON_EXISTENT",0x00000FA5,"The name does not exist in the WINS database.")

    # (0x00000FA6) Replication with a nonconfigured partner is not allowed.
    ERROR_RPL_NOT_ALLOWED = WindowsError::ErrorCode.new("ERROR_RPL_NOT_ALLOWED",0x00000FA6,"Replication with a nonconfigured partner is not allowed.")

    # (0x00000FD2) The version of the supplied content information is not supported.
    PEERDIST_ERROR_CONTENTINFO_VERSION_UNSUPPORTED = WindowsError::ErrorCode.new("PEERDIST_ERROR_CONTENTINFO_VERSION_UNSUPPORTED",0x00000FD2,"The version of the supplied content information is not supported.")

    # (0x00000FD3) The supplied content information is malformed.
    PEERDIST_ERROR_CANNOT_PARSE_CONTENTINFO = WindowsError::ErrorCode.new("PEERDIST_ERROR_CANNOT_PARSE_CONTENTINFO",0x00000FD3,"The supplied content information is malformed.")

    # (0x00000FD4) The requested data cannot be found in local or peer caches.
    PEERDIST_ERROR_MISSING_DATA = WindowsError::ErrorCode.new("PEERDIST_ERROR_MISSING_DATA",0x00000FD4,"The requested data cannot be found in local or peer caches.")

    # (0x00000FD5) No more data is available or required.
    PEERDIST_ERROR_NO_MORE = WindowsError::ErrorCode.new("PEERDIST_ERROR_NO_MORE",0x00000FD5,"No more data is available or required.")

    # (0x00000FD6) The supplied object has not been initialized.
    PEERDIST_ERROR_NOT_INITIALIZED = WindowsError::ErrorCode.new("PEERDIST_ERROR_NOT_INITIALIZED",0x00000FD6,"The supplied object has not been initialized.")

    # (0x00000FD7) The supplied object has already been initialized.
    PEERDIST_ERROR_ALREADY_INITIALIZED = WindowsError::ErrorCode.new("PEERDIST_ERROR_ALREADY_INITIALIZED",0x00000FD7,"The supplied object has already been initialized.")

    # (0x00000FD8) A shutdown operation is already in progress.
    PEERDIST_ERROR_SHUTDOWN_IN_PROGRESS = WindowsError::ErrorCode.new("PEERDIST_ERROR_SHUTDOWN_IN_PROGRESS",0x00000FD8,"A shutdown operation is already in progress.")

    # (0x00000FD9) The supplied object has already been invalidated.
    PEERDIST_ERROR_INVALIDATED = WindowsError::ErrorCode.new("PEERDIST_ERROR_INVALIDATED",0x00000FD9,"The supplied object has already been invalidated.")

    # (0x00000FDA) An element already exists and was not replaced.
    PEERDIST_ERROR_ALREADY_EXISTS = WindowsError::ErrorCode.new("PEERDIST_ERROR_ALREADY_EXISTS",0x00000FDA,"An element already exists and was not replaced.")

    # (0x00000FDB) Can not cancel the requested operation as it has already been completed.
    PEERDIST_ERROR_OPERATION_NOTFOUND = WindowsError::ErrorCode.new("PEERDIST_ERROR_OPERATION_NOTFOUND",0x00000FDB,"Can not cancel the requested operation as it has already been completed.")

    # (0x00000FDC) Can not perform the reqested operation because it has already been carried out.
    PEERDIST_ERROR_ALREADY_COMPLETED = WindowsError::ErrorCode.new("PEERDIST_ERROR_ALREADY_COMPLETED",0x00000FDC,"Can not perform the reqested operation because it has already been carried out.")

    # (0x00000FDD) An operation accessed data beyond the bounds of valid data.
    PEERDIST_ERROR_OUT_OF_BOUNDS = WindowsError::ErrorCode.new("PEERDIST_ERROR_OUT_OF_BOUNDS",0x00000FDD,"An operation accessed data beyond the bounds of valid data.")

    # (0x00000FDE) The requested version is not supported.
    PEERDIST_ERROR_VERSION_UNSUPPORTED = WindowsError::ErrorCode.new("PEERDIST_ERROR_VERSION_UNSUPPORTED",0x00000FDE,"The requested version is not supported.")

    # (0x00000FDF) A configuration value is invalid.
    PEERDIST_ERROR_INVALID_CONFIGURATION = WindowsError::ErrorCode.new("PEERDIST_ERROR_INVALID_CONFIGURATION",0x00000FDF,"A configuration value is invalid.")

    # (0x00000FE0) The SKU is not licensed.
    PEERDIST_ERROR_NOT_LICENSED = WindowsError::ErrorCode.new("PEERDIST_ERROR_NOT_LICENSED",0x00000FE0,"The SKU is not licensed.")

    # (0x00000FE1) PeerDist Service is still initializing and will be available shortly.
    PEERDIST_ERROR_SERVICE_UNAVAILABLE = WindowsError::ErrorCode.new("PEERDIST_ERROR_SERVICE_UNAVAILABLE",0x00000FE1,"PeerDist Service is still initializing and will be available shortly.")

    # (0x00001004) The Dynamic Host Configuration Protocol (DHCP) client has obtained an IP address that is already in use on the network. The local interface will be disabled until the DHCP client can obtain a new address.
    ERROR_DHCP_ADDRESS_CONFLICT = WindowsError::ErrorCode.new("ERROR_DHCP_ADDRESS_CONFLICT",0x00001004,"The Dynamic Host Configuration Protocol (DHCP) client has obtained an IP address that is already in use on the network. The local interface will be disabled until the DHCP client can obtain a new address.")

    # (0x00001068) The GUID passed was not recognized as valid by a WMI data provider.
    ERROR_WMI_GUID_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_WMI_GUID_NOT_FOUND",0x00001068,"The GUID passed was not recognized as valid by a WMI data provider.")

    # (0x00001069) The instance name passed was not recognized as valid by a WMI data provider.
    ERROR_WMI_INSTANCE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_WMI_INSTANCE_NOT_FOUND",0x00001069,"The instance name passed was not recognized as valid by a WMI data provider.")

    # (0x0000106A) The data item ID passed was not recognized as valid by a WMI data provider.
    ERROR_WMI_ITEMID_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_WMI_ITEMID_NOT_FOUND",0x0000106A,"The data item ID passed was not recognized as valid by a WMI data provider.")

    # (0x0000106B) The WMI request could not be completed and should be retried.
    ERROR_WMI_TRY_AGAIN = WindowsError::ErrorCode.new("ERROR_WMI_TRY_AGAIN",0x0000106B,"The WMI request could not be completed and should be retried.")

    # (0x0000106C) The WMI data provider could not be located.
    ERROR_WMI_DP_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_WMI_DP_NOT_FOUND",0x0000106C,"The WMI data provider could not be located.")

    # (0x0000106D) The WMI data provider references an instance set that has not been registered.
    ERROR_WMI_UNRESOLVED_INSTANCE_REF = WindowsError::ErrorCode.new("ERROR_WMI_UNRESOLVED_INSTANCE_REF",0x0000106D,"The WMI data provider references an instance set that has not been registered.")

    # (0x0000106E) The WMI data block or event notification has already been enabled.
    ERROR_WMI_ALREADY_ENABLED = WindowsError::ErrorCode.new("ERROR_WMI_ALREADY_ENABLED",0x0000106E,"The WMI data block or event notification has already been enabled.")

    # (0x0000106F) The WMI data block is no longer available.
    ERROR_WMI_GUID_DISCONNECTED = WindowsError::ErrorCode.new("ERROR_WMI_GUID_DISCONNECTED",0x0000106F,"The WMI data block is no longer available.")

    # (0x00001070) The WMI data service is not available.
    ERROR_WMI_SERVER_UNAVAILABLE = WindowsError::ErrorCode.new("ERROR_WMI_SERVER_UNAVAILABLE",0x00001070,"The WMI data service is not available.")

    # (0x00001071) The WMI data provider failed to carry out the request.
    ERROR_WMI_DP_FAILED = WindowsError::ErrorCode.new("ERROR_WMI_DP_FAILED",0x00001071,"The WMI data provider failed to carry out the request.")

    # (0x00001072) The WMI Managed Object Format (MOF) information is not valid.
    ERROR_WMI_INVALID_MOF = WindowsError::ErrorCode.new("ERROR_WMI_INVALID_MOF",0x00001072,"The WMI Managed Object Format (MOF) information is not valid.")

    # (0x00001073) The WMI registration information is not valid.
    ERROR_WMI_INVALID_REGINFO = WindowsError::ErrorCode.new("ERROR_WMI_INVALID_REGINFO",0x00001073,"The WMI registration information is not valid.")

    # (0x00001074) The WMI data block or event notification has already been disabled.
    ERROR_WMI_ALREADY_DISABLED = WindowsError::ErrorCode.new("ERROR_WMI_ALREADY_DISABLED",0x00001074,"The WMI data block or event notification has already been disabled.")

    # (0x00001075) The WMI data item or data block is read-only.
    ERROR_WMI_READ_ONLY = WindowsError::ErrorCode.new("ERROR_WMI_READ_ONLY",0x00001075,"The WMI data item or data block is read-only.")

    # (0x00001076) The WMI data item or data block could not be changed.
    ERROR_WMI_SET_FAILURE = WindowsError::ErrorCode.new("ERROR_WMI_SET_FAILURE",0x00001076,"The WMI data item or data block could not be changed.")

    # (0x000010CC) The media identifier does not represent a valid medium.
    ERROR_INVALID_MEDIA = WindowsError::ErrorCode.new("ERROR_INVALID_MEDIA",0x000010CC,"The media identifier does not represent a valid medium.")

    # (0x000010CD) The library identifier does not represent a valid library.
    ERROR_INVALID_LIBRARY = WindowsError::ErrorCode.new("ERROR_INVALID_LIBRARY",0x000010CD,"The library identifier does not represent a valid library.")

    # (0x000010CE) The media pool identifier does not represent a valid media pool.
    ERROR_INVALID_MEDIA_POOL = WindowsError::ErrorCode.new("ERROR_INVALID_MEDIA_POOL",0x000010CE,"The media pool identifier does not represent a valid media pool.")

    # (0x000010CF) The drive and medium are not compatible, or they exist in different libraries.
    ERROR_DRIVE_MEDIA_MISMATCH = WindowsError::ErrorCode.new("ERROR_DRIVE_MEDIA_MISMATCH",0x000010CF,"The drive and medium are not compatible, or they exist in different libraries.")

    # (0x000010D0) The medium currently exists in an offline library and must be online to perform this operation.
    ERROR_MEDIA_OFFLINE = WindowsError::ErrorCode.new("ERROR_MEDIA_OFFLINE",0x000010D0,"The medium currently exists in an offline library and must be online to perform this operation.")

    # (0x000010D1) The operation cannot be performed on an offline library.
    ERROR_LIBRARY_OFFLINE = WindowsError::ErrorCode.new("ERROR_LIBRARY_OFFLINE",0x000010D1,"The operation cannot be performed on an offline library.")

    # (0x000010D2) The library, drive, or media pool is empty.
    ERROR_EMPTY = WindowsError::ErrorCode.new("ERROR_EMPTY",0x000010D2,"The library, drive, or media pool is empty.")

    # (0x000010D3) The library, drive, or media pool must be empty to perform this operation.
    ERROR_NOT_EMPTY = WindowsError::ErrorCode.new("ERROR_NOT_EMPTY",0x000010D3,"The library, drive, or media pool must be empty to perform this operation.")

    # (0x000010D4) No media is currently available in this media pool or library.
    ERROR_MEDIA_UNAVAILABLE = WindowsError::ErrorCode.new("ERROR_MEDIA_UNAVAILABLE",0x000010D4,"No media is currently available in this media pool or library.")

    # (0x000010D5) A resource required for this operation is disabled.
    ERROR_RESOURCE_DISABLED = WindowsError::ErrorCode.new("ERROR_RESOURCE_DISABLED",0x000010D5,"A resource required for this operation is disabled.")

    # (0x000010D6) The media identifier does not represent a valid cleaner.
    ERROR_INVALID_CLEANER = WindowsError::ErrorCode.new("ERROR_INVALID_CLEANER",0x000010D6,"The media identifier does not represent a valid cleaner.")

    # (0x000010D7) The drive cannot be cleaned or does not support cleaning.
    ERROR_UNABLE_TO_CLEAN = WindowsError::ErrorCode.new("ERROR_UNABLE_TO_CLEAN",0x000010D7,"The drive cannot be cleaned or does not support cleaning.")

    # (0x000010D8) The object identifier does not represent a valid object.
    ERROR_OBJECT_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_OBJECT_NOT_FOUND",0x000010D8,"The object identifier does not represent a valid object.")

    # (0x000010D9) Unable to read from or write to the database.
    ERROR_DATABASE_FAILURE = WindowsError::ErrorCode.new("ERROR_DATABASE_FAILURE",0x000010D9,"Unable to read from or write to the database.")

    # (0x000010DA) The database is full.
    ERROR_DATABASE_FULL = WindowsError::ErrorCode.new("ERROR_DATABASE_FULL",0x000010DA,"The database is full.")

    # (0x000010DB) The medium is not compatible with the device or media pool.
    ERROR_MEDIA_INCOMPATIBLE = WindowsError::ErrorCode.new("ERROR_MEDIA_INCOMPATIBLE",0x000010DB,"The medium is not compatible with the device or media pool.")

    # (0x000010DC) The resource required for this operation does not exist.
    ERROR_RESOURCE_NOT_PRESENT = WindowsError::ErrorCode.new("ERROR_RESOURCE_NOT_PRESENT",0x000010DC,"The resource required for this operation does not exist.")

    # (0x000010DD) The operation identifier is not valid.
    ERROR_INVALID_OPERATION = WindowsError::ErrorCode.new("ERROR_INVALID_OPERATION",0x000010DD,"The operation identifier is not valid.")

    # (0x000010DE) The media is not mounted or ready for use.
    ERROR_MEDIA_NOT_AVAILABLE = WindowsError::ErrorCode.new("ERROR_MEDIA_NOT_AVAILABLE",0x000010DE,"The media is not mounted or ready for use.")

    # (0x000010DF) The device is not ready for use.
    ERROR_DEVICE_NOT_AVAILABLE = WindowsError::ErrorCode.new("ERROR_DEVICE_NOT_AVAILABLE",0x000010DF,"The device is not ready for use.")

    # (0x000010E0) The operator or administrator has refused the request.
    ERROR_REQUEST_REFUSED = WindowsError::ErrorCode.new("ERROR_REQUEST_REFUSED",0x000010E0,"The operator or administrator has refused the request.")

    # (0x000010E1) The drive identifier does not represent a valid drive.
    ERROR_INVALID_DRIVE_OBJECT = WindowsError::ErrorCode.new("ERROR_INVALID_DRIVE_OBJECT",0x000010E1,"The drive identifier does not represent a valid drive.")

    # (0x000010E2) Library is full. No slot is available for use.
    ERROR_LIBRARY_FULL = WindowsError::ErrorCode.new("ERROR_LIBRARY_FULL",0x000010E2,"Library is full. No slot is available for use.")

    # (0x000010E3) The transport cannot access the medium.
    ERROR_MEDIUM_NOT_ACCESSIBLE = WindowsError::ErrorCode.new("ERROR_MEDIUM_NOT_ACCESSIBLE",0x000010E3,"The transport cannot access the medium.")

    # (0x000010E4) Unable to load the medium into the drive.
    ERROR_UNABLE_TO_LOAD_MEDIUM = WindowsError::ErrorCode.new("ERROR_UNABLE_TO_LOAD_MEDIUM",0x000010E4,"Unable to load the medium into the drive.")

    # (0x000010E5) Unable to retrieve the drive status.
    ERROR_UNABLE_TO_INVENTORY_DRIVE = WindowsError::ErrorCode.new("ERROR_UNABLE_TO_INVENTORY_DRIVE",0x000010E5,"Unable to retrieve the drive status.")

    # (0x000010E6) Unable to retrieve the slot status.
    ERROR_UNABLE_TO_INVENTORY_SLOT = WindowsError::ErrorCode.new("ERROR_UNABLE_TO_INVENTORY_SLOT",0x000010E6,"Unable to retrieve the slot status.")

    # (0x000010E7) Unable to retrieve status about the transport.
    ERROR_UNABLE_TO_INVENTORY_TRANSPORT = WindowsError::ErrorCode.new("ERROR_UNABLE_TO_INVENTORY_TRANSPORT",0x000010E7,"Unable to retrieve status about the transport.")

    # (0x000010E8) Cannot use the transport because it is already in use.
    ERROR_TRANSPORT_FULL = WindowsError::ErrorCode.new("ERROR_TRANSPORT_FULL",0x000010E8,"Cannot use the transport because it is already in use.")

    # (0x000010E9) Unable to open or close the inject/eject port.
    ERROR_CONTROLLING_IEPORT = WindowsError::ErrorCode.new("ERROR_CONTROLLING_IEPORT",0x000010E9,"Unable to open or close the inject/eject port.")

    # (0x000010EA) Unable to eject the medium because it is in a drive.
    ERROR_UNABLE_TO_EJECT_MOUNTED_MEDIA = WindowsError::ErrorCode.new("ERROR_UNABLE_TO_EJECT_MOUNTED_MEDIA",0x000010EA,"Unable to eject the medium because it is in a drive.")

    # (0x000010EB) A cleaner slot is already reserved.
    ERROR_CLEANER_SLOT_SET = WindowsError::ErrorCode.new("ERROR_CLEANER_SLOT_SET",0x000010EB,"A cleaner slot is already reserved.")

    # (0x000010EC) A cleaner slot is not reserved.
    ERROR_CLEANER_SLOT_NOT_SET = WindowsError::ErrorCode.new("ERROR_CLEANER_SLOT_NOT_SET",0x000010EC,"A cleaner slot is not reserved.")

    # (0x000010ED) The cleaner cartridge has performed the maximum number of drive cleanings.
    ERROR_CLEANER_CARTRIDGE_SPENT = WindowsError::ErrorCode.new("ERROR_CLEANER_CARTRIDGE_SPENT",0x000010ED,"The cleaner cartridge has performed the maximum number of drive cleanings.")

    # (0x000010EE) Unexpected on-medium identifier.
    ERROR_UNEXPECTED_OMID = WindowsError::ErrorCode.new("ERROR_UNEXPECTED_OMID",0x000010EE,"Unexpected on-medium identifier.")

    # (0x000010EF) The last remaining item in this group or resource cannot be deleted.
    ERROR_CANT_DELETE_LAST_ITEM = WindowsError::ErrorCode.new("ERROR_CANT_DELETE_LAST_ITEM",0x000010EF,"The last remaining item in this group or resource cannot be deleted.")

    # (0x000010F0) The message provided exceeds the maximum size allowed for this parameter.
    ERROR_MESSAGE_EXCEEDS_MAX_SIZE = WindowsError::ErrorCode.new("ERROR_MESSAGE_EXCEEDS_MAX_SIZE",0x000010F0,"The message provided exceeds the maximum size allowed for this parameter.")

    # (0x000010F1) The volume contains system or paging files.
    ERROR_VOLUME_CONTAINS_SYS_FILES = WindowsError::ErrorCode.new("ERROR_VOLUME_CONTAINS_SYS_FILES",0x000010F1,"The volume contains system or paging files.")

    # (0x000010F2) The media type cannot be removed from this library because at least one drive in the library reports it can support this media type.
    ERROR_INDIGENOUS_TYPE = WindowsError::ErrorCode.new("ERROR_INDIGENOUS_TYPE",0x000010F2,"The media type cannot be removed from this library because at least one drive in the library reports it can support this media type.")

    # (0x000010F3) This offline media cannot be mounted on this system because no enabled drives are present that can be used.
    ERROR_NO_SUPPORTING_DRIVES = WindowsError::ErrorCode.new("ERROR_NO_SUPPORTING_DRIVES",0x000010F3,"This offline media cannot be mounted on this system because no enabled drives are present that can be used.")

    # (0x000010F4) A cleaner cartridge is present in the tape library.
    ERROR_CLEANER_CARTRIDGE_INSTALLED = WindowsError::ErrorCode.new("ERROR_CLEANER_CARTRIDGE_INSTALLED",0x000010F4,"A cleaner cartridge is present in the tape library.")

    # (0x000010F5) Cannot use the IEport because it is not empty.
    ERROR_IEPORT_FULL = WindowsError::ErrorCode.new("ERROR_IEPORT_FULL",0x000010F5,"Cannot use the IEport because it is not empty.")

    # (0x000010FE) The remote storage service was not able to recall the file.
    ERROR_FILE_OFFLINE = WindowsError::ErrorCode.new("ERROR_FILE_OFFLINE",0x000010FE,"The remote storage service was not able to recall the file.")

    # (0x000010FF) The remote storage service is not operational at this time.
    ERROR_REMOTE_STORAGE_NOT_ACTIVE = WindowsError::ErrorCode.new("ERROR_REMOTE_STORAGE_NOT_ACTIVE",0x000010FF,"The remote storage service is not operational at this time.")

    # (0x00001100) The remote storage service encountered a media error.
    ERROR_REMOTE_STORAGE_MEDIA_ERROR = WindowsError::ErrorCode.new("ERROR_REMOTE_STORAGE_MEDIA_ERROR",0x00001100,"The remote storage service encountered a media error.")

    # (0x00001126) The file or directory is not a reparse point.
    ERROR_NOT_A_REPARSE_POINT = WindowsError::ErrorCode.new("ERROR_NOT_A_REPARSE_POINT",0x00001126,"The file or directory is not a reparse point.")

    # (0x00001127) The reparse point attribute cannot be set because it conflicts with an existing attribute.
    ERROR_REPARSE_ATTRIBUTE_CONFLICT = WindowsError::ErrorCode.new("ERROR_REPARSE_ATTRIBUTE_CONFLICT",0x00001127,"The reparse point attribute cannot be set because it conflicts with an existing attribute.")

    # (0x00001128) The data present in the reparse point buffer is invalid.
    ERROR_INVALID_REPARSE_DATA = WindowsError::ErrorCode.new("ERROR_INVALID_REPARSE_DATA",0x00001128,"The data present in the reparse point buffer is invalid.")

    # (0x00001129) The tag present in the reparse point buffer is invalid.
    ERROR_REPARSE_TAG_INVALID = WindowsError::ErrorCode.new("ERROR_REPARSE_TAG_INVALID",0x00001129,"The tag present in the reparse point buffer is invalid.")

    # (0x0000112A) There is a mismatch between the tag specified in the request and the tag present in the reparse point.
    ERROR_REPARSE_TAG_MISMATCH = WindowsError::ErrorCode.new("ERROR_REPARSE_TAG_MISMATCH",0x0000112A,"There is a mismatch between the tag specified in the request and the tag present in the reparse point.")

    # (0x00001194) Single Instance Storage (SIS) is not available on this volume.
    ERROR_VOLUME_NOT_SIS_ENABLED = WindowsError::ErrorCode.new("ERROR_VOLUME_NOT_SIS_ENABLED",0x00001194,"Single Instance Storage (SIS) is not available on this volume.")

    # (0x00001389) The operation cannot be completed because other resources depend on this resource.
    ERROR_DEPENDENT_RESOURCE_EXISTS = WindowsError::ErrorCode.new("ERROR_DEPENDENT_RESOURCE_EXISTS",0x00001389,"The operation cannot be completed because other resources depend on this resource.")

    # (0x0000138A) The cluster resource dependency cannot be found.
    ERROR_DEPENDENCY_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_DEPENDENCY_NOT_FOUND",0x0000138A,"The cluster resource dependency cannot be found.")

    # (0x0000138B) The cluster resource cannot be made dependent on the specified resource because it is already dependent.
    ERROR_DEPENDENCY_ALREADY_EXISTS = WindowsError::ErrorCode.new("ERROR_DEPENDENCY_ALREADY_EXISTS",0x0000138B,"The cluster resource cannot be made dependent on the specified resource because it is already dependent.")

    # (0x0000138C) The cluster resource is not online.
    ERROR_RESOURCE_NOT_ONLINE = WindowsError::ErrorCode.new("ERROR_RESOURCE_NOT_ONLINE",0x0000138C,"The cluster resource is not online.")

    # (0x0000138D) A cluster node is not available for this operation.
    ERROR_HOST_NODE_NOT_AVAILABLE = WindowsError::ErrorCode.new("ERROR_HOST_NODE_NOT_AVAILABLE",0x0000138D,"A cluster node is not available for this operation.")

    # (0x0000138E) The cluster resource is not available.
    ERROR_RESOURCE_NOT_AVAILABLE = WindowsError::ErrorCode.new("ERROR_RESOURCE_NOT_AVAILABLE",0x0000138E,"The cluster resource is not available.")

    # (0x0000138F) The cluster resource could not be found.
    ERROR_RESOURCE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_RESOURCE_NOT_FOUND",0x0000138F,"The cluster resource could not be found.")

    # (0x00001390) The cluster is being shut down.
    ERROR_SHUTDOWN_CLUSTER = WindowsError::ErrorCode.new("ERROR_SHUTDOWN_CLUSTER",0x00001390,"The cluster is being shut down.")

    # (0x00001391) A cluster node cannot be evicted from the cluster unless the node is down or it is the last node.
    ERROR_CANT_EVICT_ACTIVE_NODE = WindowsError::ErrorCode.new("ERROR_CANT_EVICT_ACTIVE_NODE",0x00001391,"A cluster node cannot be evicted from the cluster unless the node is down or it is the last node.")

    # (0x00001392) The object already exists.
    ERROR_OBJECT_ALREADY_EXISTS = WindowsError::ErrorCode.new("ERROR_OBJECT_ALREADY_EXISTS",0x00001392,"The object already exists.")

    # (0x00001393) The object is already in the list.
    ERROR_OBJECT_IN_LIST = WindowsError::ErrorCode.new("ERROR_OBJECT_IN_LIST",0x00001393,"The object is already in the list.")

    # (0x00001394) The cluster group is not available for any new requests.
    ERROR_GROUP_NOT_AVAILABLE = WindowsError::ErrorCode.new("ERROR_GROUP_NOT_AVAILABLE",0x00001394,"The cluster group is not available for any new requests.")

    # (0x00001395) The cluster group could not be found.
    ERROR_GROUP_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_GROUP_NOT_FOUND",0x00001395,"The cluster group could not be found.")

    # (0x00001396) The operation could not be completed because the cluster group is not online.
    ERROR_GROUP_NOT_ONLINE = WindowsError::ErrorCode.new("ERROR_GROUP_NOT_ONLINE",0x00001396,"The operation could not be completed because the cluster group is not online.")

    # (0x00001397) The operation failed because either the specified cluster node is not the owner of the resource, or the node is not a possible owner of the resource.
    ERROR_HOST_NODE_NOT_RESOURCE_OWNER = WindowsError::ErrorCode.new("ERROR_HOST_NODE_NOT_RESOURCE_OWNER",0x00001397,"The operation failed because either the specified cluster node is not the owner of the resource, or the node is not a possible owner of the resource.")

    # (0x00001398) The operation failed because either the specified cluster node is not the owner of the group, or the node is not a possible owner of the group.
    ERROR_HOST_NODE_NOT_GROUP_OWNER = WindowsError::ErrorCode.new("ERROR_HOST_NODE_NOT_GROUP_OWNER",0x00001398,"The operation failed because either the specified cluster node is not the owner of the group, or the node is not a possible owner of the group.")

    # (0x00001399) The cluster resource could not be created in the specified resource monitor.
    ERROR_RESMON_CREATE_FAILED = WindowsError::ErrorCode.new("ERROR_RESMON_CREATE_FAILED",0x00001399,"The cluster resource could not be created in the specified resource monitor.")

    # (0x0000139A) The cluster resource could not be brought online by the resource monitor.
    ERROR_RESMON_ONLINE_FAILED = WindowsError::ErrorCode.new("ERROR_RESMON_ONLINE_FAILED",0x0000139A,"The cluster resource could not be brought online by the resource monitor.")

    # (0x0000139B) The operation could not be completed because the cluster resource is online.
    ERROR_RESOURCE_ONLINE = WindowsError::ErrorCode.new("ERROR_RESOURCE_ONLINE",0x0000139B,"The operation could not be completed because the cluster resource is online.")

    # (0x0000139C) The cluster resource could not be deleted or brought offline because it is the quorum resource.
    ERROR_QUORUM_RESOURCE = WindowsError::ErrorCode.new("ERROR_QUORUM_RESOURCE",0x0000139C,"The cluster resource could not be deleted or brought offline because it is the quorum resource.")

    # (0x0000139D) The cluster could not make the specified resource a quorum resource because it is not capable of being a quorum resource.
    ERROR_NOT_QUORUM_CAPABLE = WindowsError::ErrorCode.new("ERROR_NOT_QUORUM_CAPABLE",0x0000139D,"The cluster could not make the specified resource a quorum resource because it is not capable of being a quorum resource.")

    # (0x0000139E) The cluster software is shutting down.
    ERROR_CLUSTER_SHUTTING_DOWN = WindowsError::ErrorCode.new("ERROR_CLUSTER_SHUTTING_DOWN",0x0000139E,"The cluster software is shutting down.")

    # (0x0000139F) The group or resource is not in the correct state to perform the requested operation.
    ERROR_INVALID_STATE = WindowsError::ErrorCode.new("ERROR_INVALID_STATE",0x0000139F,"The group or resource is not in the correct state to perform the requested operation.")

    # (0x000013A0) The properties were stored but not all changes will take effect until the next time the resource is brought online.
    ERROR_RESOURCE_PROPERTIES_STORED = WindowsError::ErrorCode.new("ERROR_RESOURCE_PROPERTIES_STORED",0x000013A0,"The properties were stored but not all changes will take effect until the next time the resource is brought online.")

    # (0x000013A1) The cluster could not make the specified resource a quorum resource because it does not belong to a shared storage class.
    ERROR_NOT_QUORUM_CLASS = WindowsError::ErrorCode.new("ERROR_NOT_QUORUM_CLASS",0x000013A1,"The cluster could not make the specified resource a quorum resource because it does not belong to a shared storage class.")

    # (0x000013A2) The cluster resource could not be deleted because it is a core resource.
    ERROR_CORE_RESOURCE = WindowsError::ErrorCode.new("ERROR_CORE_RESOURCE",0x000013A2,"The cluster resource could not be deleted because it is a core resource.")

    # (0x000013A3) The quorum resource failed to come online.
    ERROR_QUORUM_RESOURCE_ONLINE_FAILED = WindowsError::ErrorCode.new("ERROR_QUORUM_RESOURCE_ONLINE_FAILED",0x000013A3,"The quorum resource failed to come online.")

    # (0x000013A4) The quorum log could not be created or mounted successfully.
    ERROR_QUORUMLOG_OPEN_FAILED = WindowsError::ErrorCode.new("ERROR_QUORUMLOG_OPEN_FAILED",0x000013A4,"The quorum log could not be created or mounted successfully.")

    # (0x000013A5) The cluster log is corrupt.
    ERROR_CLUSTERLOG_CORRUPT = WindowsError::ErrorCode.new("ERROR_CLUSTERLOG_CORRUPT",0x000013A5,"The cluster log is corrupt.")

    # (0x000013A6) The record could not be written to the cluster log because it exceeds the maximum size.
    ERROR_CLUSTERLOG_RECORD_EXCEEDS_MAXSIZE = WindowsError::ErrorCode.new("ERROR_CLUSTERLOG_RECORD_EXCEEDS_MAXSIZE",0x000013A6,"The record could not be written to the cluster log because it exceeds the maximum size.")

    # (0x000013A7) The cluster log exceeds its maximum size.
    ERROR_CLUSTERLOG_EXCEEDS_MAXSIZE = WindowsError::ErrorCode.new("ERROR_CLUSTERLOG_EXCEEDS_MAXSIZE",0x000013A7,"The cluster log exceeds its maximum size.")

    # (0x000013A8) No checkpoint record was found in the cluster log.
    ERROR_CLUSTERLOG_CHKPOINT_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_CLUSTERLOG_CHKPOINT_NOT_FOUND",0x000013A8,"No checkpoint record was found in the cluster log.")

    # (0x000013A9) The minimum required disk space needed for logging is not available.
    ERROR_CLUSTERLOG_NOT_ENOUGH_SPACE = WindowsError::ErrorCode.new("ERROR_CLUSTERLOG_NOT_ENOUGH_SPACE",0x000013A9,"The minimum required disk space needed for logging is not available.")

    # (0x000013AA) The cluster node failed to take control of the quorum resource because the resource is owned by another active node.
    ERROR_QUORUM_OWNER_ALIVE = WindowsError::ErrorCode.new("ERROR_QUORUM_OWNER_ALIVE",0x000013AA,"The cluster node failed to take control of the quorum resource because the resource is owned by another active node.")

    # (0x000013AB) A cluster network is not available for this operation.
    ERROR_NETWORK_NOT_AVAILABLE = WindowsError::ErrorCode.new("ERROR_NETWORK_NOT_AVAILABLE",0x000013AB,"A cluster network is not available for this operation.")

    # (0x000013AC) A cluster node is not available for this operation.
    ERROR_NODE_NOT_AVAILABLE = WindowsError::ErrorCode.new("ERROR_NODE_NOT_AVAILABLE",0x000013AC,"A cluster node is not available for this operation.")

    # (0x000013AD) All cluster nodes must be running to perform this operation.
    ERROR_ALL_NODES_NOT_AVAILABLE = WindowsError::ErrorCode.new("ERROR_ALL_NODES_NOT_AVAILABLE",0x000013AD,"All cluster nodes must be running to perform this operation.")

    # (0x000013AE) A cluster resource failed.
    ERROR_RESOURCE_FAILED = WindowsError::ErrorCode.new("ERROR_RESOURCE_FAILED",0x000013AE,"A cluster resource failed.")

    # (0x000013AF) The cluster node is not valid.
    ERROR_CLUSTER_INVALID_NODE = WindowsError::ErrorCode.new("ERROR_CLUSTER_INVALID_NODE",0x000013AF,"The cluster node is not valid.")

    # (0x000013B0) The cluster node already exists.
    ERROR_CLUSTER_NODE_EXISTS = WindowsError::ErrorCode.new("ERROR_CLUSTER_NODE_EXISTS",0x000013B0,"The cluster node already exists.")

    # (0x000013B1) A node is in the process of joining the cluster.
    ERROR_CLUSTER_JOIN_IN_PROGRESS = WindowsError::ErrorCode.new("ERROR_CLUSTER_JOIN_IN_PROGRESS",0x000013B1,"A node is in the process of joining the cluster.")

    # (0x000013B2) The cluster node was not found.
    ERROR_CLUSTER_NODE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_CLUSTER_NODE_NOT_FOUND",0x000013B2,"The cluster node was not found.")

    # (0x000013B3) The cluster local node information was not found.
    ERROR_CLUSTER_LOCAL_NODE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_CLUSTER_LOCAL_NODE_NOT_FOUND",0x000013B3,"The cluster local node information was not found.")

    # (0x000013B4) The cluster network already exists.
    ERROR_CLUSTER_NETWORK_EXISTS = WindowsError::ErrorCode.new("ERROR_CLUSTER_NETWORK_EXISTS",0x000013B4,"The cluster network already exists.")

    # (0x000013B5) The cluster network was not found.
    ERROR_CLUSTER_NETWORK_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_CLUSTER_NETWORK_NOT_FOUND",0x000013B5,"The cluster network was not found.")

    # (0x000013B6) The cluster network interface already exists.
    ERROR_CLUSTER_NETINTERFACE_EXISTS = WindowsError::ErrorCode.new("ERROR_CLUSTER_NETINTERFACE_EXISTS",0x000013B6,"The cluster network interface already exists.")

    # (0x000013B7) The cluster network interface was not found.
    ERROR_CLUSTER_NETINTERFACE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_CLUSTER_NETINTERFACE_NOT_FOUND",0x000013B7,"The cluster network interface was not found.")

    # (0x000013B8) The cluster request is not valid for this object.
    ERROR_CLUSTER_INVALID_REQUEST = WindowsError::ErrorCode.new("ERROR_CLUSTER_INVALID_REQUEST",0x000013B8,"The cluster request is not valid for this object.")

    # (0x000013B9) The cluster network provider is not valid.
    ERROR_CLUSTER_INVALID_NETWORK_PROVIDER = WindowsError::ErrorCode.new("ERROR_CLUSTER_INVALID_NETWORK_PROVIDER",0x000013B9,"The cluster network provider is not valid.")

    # (0x000013BA) The cluster node is down.
    ERROR_CLUSTER_NODE_DOWN = WindowsError::ErrorCode.new("ERROR_CLUSTER_NODE_DOWN",0x000013BA,"The cluster node is down.")

    # (0x000013BB) The cluster node is not reachable.
    ERROR_CLUSTER_NODE_UNREACHABLE = WindowsError::ErrorCode.new("ERROR_CLUSTER_NODE_UNREACHABLE",0x000013BB,"The cluster node is not reachable.")

    # (0x000013BC) The cluster node is not a member of the cluster.
    ERROR_CLUSTER_NODE_NOT_MEMBER = WindowsError::ErrorCode.new("ERROR_CLUSTER_NODE_NOT_MEMBER",0x000013BC,"The cluster node is not a member of the cluster.")

    # (0x000013BD) A cluster join operation is not in progress.
    ERROR_CLUSTER_JOIN_NOT_IN_PROGRESS = WindowsError::ErrorCode.new("ERROR_CLUSTER_JOIN_NOT_IN_PROGRESS",0x000013BD,"A cluster join operation is not in progress.")

    # (0x000013BE) The cluster network is not valid.
    ERROR_CLUSTER_INVALID_NETWORK = WindowsError::ErrorCode.new("ERROR_CLUSTER_INVALID_NETWORK",0x000013BE,"The cluster network is not valid.")

    # (0x000013C0) The cluster node is up.
    ERROR_CLUSTER_NODE_UP = WindowsError::ErrorCode.new("ERROR_CLUSTER_NODE_UP",0x000013C0,"The cluster node is up.")

    # (0x000013C1) The cluster IP address is already in use.
    ERROR_CLUSTER_IPADDR_IN_USE = WindowsError::ErrorCode.new("ERROR_CLUSTER_IPADDR_IN_USE",0x000013C1,"The cluster IP address is already in use.")

    # (0x000013C2) The cluster node is not paused.
    ERROR_CLUSTER_NODE_NOT_PAUSED = WindowsError::ErrorCode.new("ERROR_CLUSTER_NODE_NOT_PAUSED",0x000013C2,"The cluster node is not paused.")

    # (0x000013C3) No cluster security context is available.
    ERROR_CLUSTER_NO_SECURITY_CONTEXT = WindowsError::ErrorCode.new("ERROR_CLUSTER_NO_SECURITY_CONTEXT",0x000013C3,"No cluster security context is available.")

    # (0x000013C4) The cluster network is not configured for internal cluster communication.
    ERROR_CLUSTER_NETWORK_NOT_INTERNAL = WindowsError::ErrorCode.new("ERROR_CLUSTER_NETWORK_NOT_INTERNAL",0x000013C4,"The cluster network is not configured for internal cluster communication.")

    # (0x000013C5) The cluster node is already up.
    ERROR_CLUSTER_NODE_ALREADY_UP = WindowsError::ErrorCode.new("ERROR_CLUSTER_NODE_ALREADY_UP",0x000013C5,"The cluster node is already up.")

    # (0x000013C6) The cluster node is already down.
    ERROR_CLUSTER_NODE_ALREADY_DOWN = WindowsError::ErrorCode.new("ERROR_CLUSTER_NODE_ALREADY_DOWN",0x000013C6,"The cluster node is already down.")

    # (0x000013C7) The cluster network is already online.
    ERROR_CLUSTER_NETWORK_ALREADY_ONLINE = WindowsError::ErrorCode.new("ERROR_CLUSTER_NETWORK_ALREADY_ONLINE",0x000013C7,"The cluster network is already online.")

    # (0x000013C8) The cluster network is already offline.
    ERROR_CLUSTER_NETWORK_ALREADY_OFFLINE = WindowsError::ErrorCode.new("ERROR_CLUSTER_NETWORK_ALREADY_OFFLINE",0x000013C8,"The cluster network is already offline.")

    # (0x000013C9) The cluster node is already a member of the cluster.
    ERROR_CLUSTER_NODE_ALREADY_MEMBER = WindowsError::ErrorCode.new("ERROR_CLUSTER_NODE_ALREADY_MEMBER",0x000013C9,"The cluster node is already a member of the cluster.")

    # (0x000013CA) The cluster network is the only one configured for internal cluster communication between two or more active cluster nodes. The internal communication capability cannot be removed from the network.
    ERROR_CLUSTER_LAST_INTERNAL_NETWORK = WindowsError::ErrorCode.new("ERROR_CLUSTER_LAST_INTERNAL_NETWORK",0x000013CA,"The cluster network is the only one configured for internal cluster communication between two or more active cluster nodes. The internal communication capability cannot be removed from the network.")

    # (0x000013CB) One or more cluster resources depend on the network to provide service to clients. The client access capability cannot be removed from the network.
    ERROR_CLUSTER_NETWORK_HAS_DEPENDENTS = WindowsError::ErrorCode.new("ERROR_CLUSTER_NETWORK_HAS_DEPENDENTS",0x000013CB,"One or more cluster resources depend on the network to provide service to clients. The client access capability cannot be removed from the network.")

    # (0x000013CC) This operation cannot be performed on the cluster resource because it is the quorum resource. You may not bring the quorum resource offline or modify its possible owners list.
    ERROR_INVALID_OPERATION_ON_QUORUM = WindowsError::ErrorCode.new("ERROR_INVALID_OPERATION_ON_QUORUM",0x000013CC,"This operation cannot be performed on the cluster resource because it is the quorum resource. You may not bring the quorum resource offline or modify its possible owners list.")

    # (0x000013CD) The cluster quorum resource is not allowed to have any dependencies.
    ERROR_DEPENDENCY_NOT_ALLOWED = WindowsError::ErrorCode.new("ERROR_DEPENDENCY_NOT_ALLOWED",0x000013CD,"The cluster quorum resource is not allowed to have any dependencies.")

    # (0x000013CE) The cluster node is paused.
    ERROR_CLUSTER_NODE_PAUSED = WindowsError::ErrorCode.new("ERROR_CLUSTER_NODE_PAUSED",0x000013CE,"The cluster node is paused.")

    # (0x000013CF) The cluster resource cannot be brought online. The owner node cannot run this resource.
    ERROR_NODE_CANT_HOST_RESOURCE = WindowsError::ErrorCode.new("ERROR_NODE_CANT_HOST_RESOURCE",0x000013CF,"The cluster resource cannot be brought online. The owner node cannot run this resource.")

    # (0x000013D0) The cluster node is not ready to perform the requested operation.
    ERROR_CLUSTER_NODE_NOT_READY = WindowsError::ErrorCode.new("ERROR_CLUSTER_NODE_NOT_READY",0x000013D0,"The cluster node is not ready to perform the requested operation.")

    # (0x000013D1) The cluster node is shutting down.
    ERROR_CLUSTER_NODE_SHUTTING_DOWN = WindowsError::ErrorCode.new("ERROR_CLUSTER_NODE_SHUTTING_DOWN",0x000013D1,"The cluster node is shutting down.")

    # (0x000013D2) The cluster join operation was aborted.
    ERROR_CLUSTER_JOIN_ABORTED = WindowsError::ErrorCode.new("ERROR_CLUSTER_JOIN_ABORTED",0x000013D2,"The cluster join operation was aborted.")

    # (0x000013D3) The cluster join operation failed due to incompatible software versions between the joining node and its sponsor.
    ERROR_CLUSTER_INCOMPATIBLE_VERSIONS = WindowsError::ErrorCode.new("ERROR_CLUSTER_INCOMPATIBLE_VERSIONS",0x000013D3,"The cluster join operation failed due to incompatible software versions between the joining node and its sponsor.")

    # (0x000013D4) This resource cannot be created because the cluster has reached the limit on the number of resources it can monitor.
    ERROR_CLUSTER_MAXNUM_OF_RESOURCES_EXCEEDED = WindowsError::ErrorCode.new("ERROR_CLUSTER_MAXNUM_OF_RESOURCES_EXCEEDED",0x000013D4,"This resource cannot be created because the cluster has reached the limit on the number of resources it can monitor.")

    # (0x000013D5) The system configuration changed during the cluster join or form operation. The join or form operation was aborted.
    ERROR_CLUSTER_SYSTEM_CONFIG_CHANGED = WindowsError::ErrorCode.new("ERROR_CLUSTER_SYSTEM_CONFIG_CHANGED",0x000013D5,"The system configuration changed during the cluster join or form operation. The join or form operation was aborted.")

    # (0x000013D6) The specified resource type was not found.
    ERROR_CLUSTER_RESOURCE_TYPE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_CLUSTER_RESOURCE_TYPE_NOT_FOUND",0x000013D6,"The specified resource type was not found.")

    # (0x000013D7) The specified node does not support a resource of this type. This may be due to version inconsistencies or due to the absence of the resource DLL on this node.
    ERROR_CLUSTER_RESTYPE_NOT_SUPPORTED = WindowsError::ErrorCode.new("ERROR_CLUSTER_RESTYPE_NOT_SUPPORTED",0x000013D7,"The specified node does not support a resource of this type. This may be due to version inconsistencies or due to the absence of the resource DLL on this node.")

    # (0x000013D8) The specified resource name is not supported by this resource DLL. This may be due to a bad (or changed) name supplied to the resource DLL.
    ERROR_CLUSTER_RESNAME_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_CLUSTER_RESNAME_NOT_FOUND",0x000013D8,"The specified resource name is not supported by this resource DLL. This may be due to a bad (or changed) name supplied to the resource DLL.")

    # (0x000013D9) No authentication package could be registered with the RPC server.
    ERROR_CLUSTER_NO_RPC_PACKAGES_REGISTERED = WindowsError::ErrorCode.new("ERROR_CLUSTER_NO_RPC_PACKAGES_REGISTERED",0x000013D9,"No authentication package could be registered with the RPC server.")

    # (0x000013DA) You cannot bring the group online because the owner of the group is not in the preferred list for the group. To change the owner node for the group, move the group.
    ERROR_CLUSTER_OWNER_NOT_IN_PREFLIST = WindowsError::ErrorCode.new("ERROR_CLUSTER_OWNER_NOT_IN_PREFLIST",0x000013DA,"You cannot bring the group online because the owner of the group is not in the preferred list for the group. To change the owner node for the group, move the group.")

    # (0x000013DB) The join operation failed because the cluster database sequence number has changed or is incompatible with the locker node. This may happen during a join operation if the cluster database was changing during the join.
    ERROR_CLUSTER_DATABASE_SEQMISMATCH = WindowsError::ErrorCode.new("ERROR_CLUSTER_DATABASE_SEQMISMATCH",0x000013DB,"The join operation failed because the cluster database sequence number has changed or is incompatible with the locker node. This may happen during a join operation if the cluster database was changing during the join.")

    # (0x000013DC) The resource monitor will not allow the fail operation to be performed while the resource is in its current state. This may happen if the resource is in a pending state.
    ERROR_RESMON_INVALID_STATE = WindowsError::ErrorCode.new("ERROR_RESMON_INVALID_STATE",0x000013DC,"The resource monitor will not allow the fail operation to be performed while the resource is in its current state. This may happen if the resource is in a pending state.")

    # (0x000013DD) A non-locker code received a request to reserve the lock for making global updates.
    ERROR_CLUSTER_GUM_NOT_LOCKER = WindowsError::ErrorCode.new("ERROR_CLUSTER_GUM_NOT_LOCKER",0x000013DD,"A non-locker code received a request to reserve the lock for making global updates.")

    # (0x000013DE) The quorum disk could not be located by the cluster service.
    ERROR_QUORUM_DISK_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_QUORUM_DISK_NOT_FOUND",0x000013DE,"The quorum disk could not be located by the cluster service.")

    # (0x000013DF) The backed-up cluster database is possibly corrupt.
    ERROR_DATABASE_BACKUP_CORRUPT = WindowsError::ErrorCode.new("ERROR_DATABASE_BACKUP_CORRUPT",0x000013DF,"The backed-up cluster database is possibly corrupt.")

    # (0x000013E0) A DFS root already exists in this cluster node.
    ERROR_CLUSTER_NODE_ALREADY_HAS_DFS_ROOT = WindowsError::ErrorCode.new("ERROR_CLUSTER_NODE_ALREADY_HAS_DFS_ROOT",0x000013E0,"A DFS root already exists in this cluster node.")

    # (0x000013E1) An attempt to modify a resource property failed because it conflicts with another existing property.
    ERROR_RESOURCE_PROPERTY_UNCHANGEABLE = WindowsError::ErrorCode.new("ERROR_RESOURCE_PROPERTY_UNCHANGEABLE",0x000013E1,"An attempt to modify a resource property failed because it conflicts with another existing property.")

    # (0x00001702) An operation was attempted that is incompatible with the current membership state of the node.
    ERROR_CLUSTER_MEMBERSHIP_INVALID_STATE = WindowsError::ErrorCode.new("ERROR_CLUSTER_MEMBERSHIP_INVALID_STATE",0x00001702,"An operation was attempted that is incompatible with the current membership state of the node.")

    # (0x00001703) The quorum resource does not contain the quorum log.
    ERROR_CLUSTER_QUORUMLOG_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_CLUSTER_QUORUMLOG_NOT_FOUND",0x00001703,"The quorum resource does not contain the quorum log.")

    # (0x00001704) The membership engine requested shutdown of the cluster service on this node.
    ERROR_CLUSTER_MEMBERSHIP_HALT = WindowsError::ErrorCode.new("ERROR_CLUSTER_MEMBERSHIP_HALT",0x00001704,"The membership engine requested shutdown of the cluster service on this node.")

    # (0x00001705) The join operation failed because the cluster instance ID of the joining node does not match the cluster instance ID of the sponsor node.
    ERROR_CLUSTER_INSTANCE_ID_MISMATCH = WindowsError::ErrorCode.new("ERROR_CLUSTER_INSTANCE_ID_MISMATCH",0x00001705,"The join operation failed because the cluster instance ID of the joining node does not match the cluster instance ID of the sponsor node.")

    # (0x00001706) A matching cluster network for the specified IP address could not be found.
    ERROR_CLUSTER_NETWORK_NOT_FOUND_FOR_IP = WindowsError::ErrorCode.new("ERROR_CLUSTER_NETWORK_NOT_FOUND_FOR_IP",0x00001706,"A matching cluster network for the specified IP address could not be found.")

    # (0x00001707) The actual data type of the property did not match the expected data type of the property.
    ERROR_CLUSTER_PROPERTY_DATA_TYPE_MISMATCH = WindowsError::ErrorCode.new("ERROR_CLUSTER_PROPERTY_DATA_TYPE_MISMATCH",0x00001707,"The actual data type of the property did not match the expected data type of the property.")

    # (0x00001708) The cluster node was evicted from the cluster successfully, but the node was not cleaned up. To determine what clean-up steps failed and how to recover, see the Failover Clustering application event log using Event Viewer.
    ERROR_CLUSTER_EVICT_WITHOUT_CLEANUP = WindowsError::ErrorCode.new("ERROR_CLUSTER_EVICT_WITHOUT_CLEANUP",0x00001708,"The cluster node was evicted from the cluster successfully, but the node was not cleaned up. To determine what clean-up steps failed and how to recover, see the Failover Clustering application event log using Event Viewer.")

    # (0x00001709) Two or more parameter values specified for a resource's properties are in conflict.
    ERROR_CLUSTER_PARAMETER_MISMATCH = WindowsError::ErrorCode.new("ERROR_CLUSTER_PARAMETER_MISMATCH",0x00001709,"Two or more parameter values specified for a resource's properties are in conflict.")

    # (0x0000170A) This computer cannot be made a member of a cluster.
    ERROR_NODE_CANNOT_BE_CLUSTERED = WindowsError::ErrorCode.new("ERROR_NODE_CANNOT_BE_CLUSTERED",0x0000170A,"This computer cannot be made a member of a cluster.")

    # (0x0000170B) This computer cannot be made a member of a cluster because it does not have the correct version of Windows installed.
    ERROR_CLUSTER_WRONG_OS_VERSION = WindowsError::ErrorCode.new("ERROR_CLUSTER_WRONG_OS_VERSION",0x0000170B,"This computer cannot be made a member of a cluster because it does not have the correct version of Windows installed.")

    # (0x0000170C) A cluster cannot be created with the specified cluster name because that cluster name is already in use. Specify a different name for the cluster.
    ERROR_CLUSTER_CANT_CREATE_DUP_CLUSTER_NAME = WindowsError::ErrorCode.new("ERROR_CLUSTER_CANT_CREATE_DUP_CLUSTER_NAME",0x0000170C,"A cluster cannot be created with the specified cluster name because that cluster name is already in use. Specify a different name for the cluster.")

    # (0x0000170D) The cluster configuration action has already been committed.
    ERROR_CLUSCFG_ALREADY_COMMITTED = WindowsError::ErrorCode.new("ERROR_CLUSCFG_ALREADY_COMMITTED",0x0000170D,"The cluster configuration action has already been committed.")

    # (0x0000170E) The cluster configuration action could not be rolled back.
    ERROR_CLUSCFG_ROLLBACK_FAILED = WindowsError::ErrorCode.new("ERROR_CLUSCFG_ROLLBACK_FAILED",0x0000170E,"The cluster configuration action could not be rolled back.")

    # (0x0000170F) The drive letter assigned to a system disk on one node conflicted with the drive letter assigned to a disk on another node.
    ERROR_CLUSCFG_SYSTEM_DISK_DRIVE_LETTER_CONFLICT = WindowsError::ErrorCode.new("ERROR_CLUSCFG_SYSTEM_DISK_DRIVE_LETTER_CONFLICT",0x0000170F,"The drive letter assigned to a system disk on one node conflicted with the drive letter assigned to a disk on another node.")

    # (0x00001710) One or more nodes in the cluster are running a version of Windows that does not support this operation.
    ERROR_CLUSTER_OLD_VERSION = WindowsError::ErrorCode.new("ERROR_CLUSTER_OLD_VERSION",0x00001710,"One or more nodes in the cluster are running a version of Windows that does not support this operation.")

    # (0x00001711) The name of the corresponding computer account does not match the network name for this resource.
    ERROR_CLUSTER_MISMATCHED_COMPUTER_ACCT_NAME = WindowsError::ErrorCode.new("ERROR_CLUSTER_MISMATCHED_COMPUTER_ACCT_NAME",0x00001711,"The name of the corresponding computer account does not match the network name for this resource.")

    # (0x00001712) No network adapters are available.
    ERROR_CLUSTER_NO_NET_ADAPTERS = WindowsError::ErrorCode.new("ERROR_CLUSTER_NO_NET_ADAPTERS",0x00001712,"No network adapters are available.")

    # (0x00001713) The cluster node has been poisoned.
    ERROR_CLUSTER_POISONED = WindowsError::ErrorCode.new("ERROR_CLUSTER_POISONED",0x00001713,"The cluster node has been poisoned.")

    # (0x00001714) The group is unable to accept the request because it is moving to another node.
    ERROR_CLUSTER_GROUP_MOVING = WindowsError::ErrorCode.new("ERROR_CLUSTER_GROUP_MOVING",0x00001714,"The group is unable to accept the request because it is moving to another node.")

    # (0x00001715) The resource type cannot accept the request because it is too busy performing another operation.
    ERROR_CLUSTER_RESOURCE_TYPE_BUSY = WindowsError::ErrorCode.new("ERROR_CLUSTER_RESOURCE_TYPE_BUSY",0x00001715,"The resource type cannot accept the request because it is too busy performing another operation.")

    # (0x00001716) The call to the cluster resource DLL timed out.
    ERROR_RESOURCE_CALL_TIMED_OUT = WindowsError::ErrorCode.new("ERROR_RESOURCE_CALL_TIMED_OUT",0x00001716,"The call to the cluster resource DLL timed out.")

    # (0x00001717) The address is not valid for an IPv6 Address resource. A global IPv6 address is required, and it must match a cluster network. Compatibility addresses are not permitted.
    ERROR_INVALID_CLUSTER_IPV6_ADDRESS = WindowsError::ErrorCode.new("ERROR_INVALID_CLUSTER_IPV6_ADDRESS",0x00001717,"The address is not valid for an IPv6 Address resource. A global IPv6 address is required, and it must match a cluster network. Compatibility addresses are not permitted.")

    # (0x00001718) An internal cluster error occurred. A call to an invalid function was attempted.
    ERROR_CLUSTER_INTERNAL_INVALID_FUNCTION = WindowsError::ErrorCode.new("ERROR_CLUSTER_INTERNAL_INVALID_FUNCTION",0x00001718,"An internal cluster error occurred. A call to an invalid function was attempted.")

    # (0x00001719) A parameter value is out of acceptable range.
    ERROR_CLUSTER_PARAMETER_OUT_OF_BOUNDS = WindowsError::ErrorCode.new("ERROR_CLUSTER_PARAMETER_OUT_OF_BOUNDS",0x00001719,"A parameter value is out of acceptable range.")

    # (0x0000171A) A network error occurred while sending data to another node in the cluster. The number of bytes transmitted was less than required.
    ERROR_CLUSTER_PARTIAL_SEND = WindowsError::ErrorCode.new("ERROR_CLUSTER_PARTIAL_SEND",0x0000171A,"A network error occurred while sending data to another node in the cluster. The number of bytes transmitted was less than required.")

    # (0x0000171B) An invalid cluster registry operation was attempted.
    ERROR_CLUSTER_REGISTRY_INVALID_FUNCTION = WindowsError::ErrorCode.new("ERROR_CLUSTER_REGISTRY_INVALID_FUNCTION",0x0000171B,"An invalid cluster registry operation was attempted.")

    # (0x0000171C) An input string of characters is not properly terminated.
    ERROR_CLUSTER_INVALID_STRING_TERMINATION = WindowsError::ErrorCode.new("ERROR_CLUSTER_INVALID_STRING_TERMINATION",0x0000171C,"An input string of characters is not properly terminated.")

    # (0x0000171D) An input string of characters is not in a valid format for the data it represents.
    ERROR_CLUSTER_INVALID_STRING_FORMAT = WindowsError::ErrorCode.new("ERROR_CLUSTER_INVALID_STRING_FORMAT",0x0000171D,"An input string of characters is not in a valid format for the data it represents.")

    # (0x0000171E) An internal cluster error occurred. A cluster database transaction was attempted while a transaction was already in progress.
    ERROR_CLUSTER_DATABASE_TRANSACTION_IN_PROGRESS = WindowsError::ErrorCode.new("ERROR_CLUSTER_DATABASE_TRANSACTION_IN_PROGRESS",0x0000171E,"An internal cluster error occurred. A cluster database transaction was attempted while a transaction was already in progress.")

    # (0x0000171F) An internal cluster error occurred. There was an attempt to commit a cluster database transaction while no transaction was in progress.
    ERROR_CLUSTER_DATABASE_TRANSACTION_NOT_IN_PROGRESS = WindowsError::ErrorCode.new("ERROR_CLUSTER_DATABASE_TRANSACTION_NOT_IN_PROGRESS",0x0000171F,"An internal cluster error occurred. There was an attempt to commit a cluster database transaction while no transaction was in progress.")

    # (0x00001720) An internal cluster error occurred. Data was not properly initialized.
    ERROR_CLUSTER_NULL_DATA = WindowsError::ErrorCode.new("ERROR_CLUSTER_NULL_DATA",0x00001720,"An internal cluster error occurred. Data was not properly initialized.")

    # (0x00001721) An error occurred while reading from a stream of data. An unexpected number of bytes was returned.
    ERROR_CLUSTER_PARTIAL_READ = WindowsError::ErrorCode.new("ERROR_CLUSTER_PARTIAL_READ",0x00001721,"An error occurred while reading from a stream of data. An unexpected number of bytes was returned.")

    # (0x00001722) An error occurred while writing to a stream of data. The required number of bytes could not be written.
    ERROR_CLUSTER_PARTIAL_WRITE = WindowsError::ErrorCode.new("ERROR_CLUSTER_PARTIAL_WRITE",0x00001722,"An error occurred while writing to a stream of data. The required number of bytes could not be written.")

    # (0x00001723) An error occurred while deserializing a stream of cluster data.
    ERROR_CLUSTER_CANT_DESERIALIZE_DATA = WindowsError::ErrorCode.new("ERROR_CLUSTER_CANT_DESERIALIZE_DATA",0x00001723,"An error occurred while deserializing a stream of cluster data.")

    # (0x00001724) One or more property values for this resource are in conflict with one or more property values associated with its dependent resources.
    ERROR_DEPENDENT_RESOURCE_PROPERTY_CONFLICT = WindowsError::ErrorCode.new("ERROR_DEPENDENT_RESOURCE_PROPERTY_CONFLICT",0x00001724,"One or more property values for this resource are in conflict with one or more property values associated with its dependent resources.")

    # (0x00001725) A quorum of cluster nodes was not present to form a cluster.
    ERROR_CLUSTER_NO_QUORUM = WindowsError::ErrorCode.new("ERROR_CLUSTER_NO_QUORUM",0x00001725,"A quorum of cluster nodes was not present to form a cluster.")

    # (0x00001726) The cluster network is not valid for an IPv6 address resource, or it does not match the configured address.
    ERROR_CLUSTER_INVALID_IPV6_NETWORK = WindowsError::ErrorCode.new("ERROR_CLUSTER_INVALID_IPV6_NETWORK",0x00001726,"The cluster network is not valid for an IPv6 address resource, or it does not match the configured address.")

    # (0x00001727) The cluster network is not valid for an IPv6 tunnel resource. Check the configuration of the IP Address resource on which the IPv6 tunnel resource depends.
    ERROR_CLUSTER_INVALID_IPV6_TUNNEL_NETWORK = WindowsError::ErrorCode.new("ERROR_CLUSTER_INVALID_IPV6_TUNNEL_NETWORK",0x00001727,"The cluster network is not valid for an IPv6 tunnel resource. Check the configuration of the IP Address resource on which the IPv6 tunnel resource depends.")

    # (0x00001728) Quorum resource cannot reside in the available storage group.
    ERROR_QUORUM_NOT_ALLOWED_IN_THIS_GROUP = WindowsError::ErrorCode.new("ERROR_QUORUM_NOT_ALLOWED_IN_THIS_GROUP",0x00001728,"Quorum resource cannot reside in the available storage group.")

    # (0x00001770) The specified file could not be encrypted.
    ERROR_ENCRYPTION_FAILED = WindowsError::ErrorCode.new("ERROR_ENCRYPTION_FAILED",0x00001770,"The specified file could not be encrypted.")

    # (0x00001771) The specified file could not be decrypted.
    ERROR_DECRYPTION_FAILED = WindowsError::ErrorCode.new("ERROR_DECRYPTION_FAILED",0x00001771,"The specified file could not be decrypted.")

    # (0x00001772) The specified file is encrypted and the user does not have the ability to decrypt it.
    ERROR_FILE_ENCRYPTED = WindowsError::ErrorCode.new("ERROR_FILE_ENCRYPTED",0x00001772,"The specified file is encrypted and the user does not have the ability to decrypt it.")

    # (0x00001773) There is no valid encryption recovery policy configured for this system.
    ERROR_NO_RECOVERY_POLICY = WindowsError::ErrorCode.new("ERROR_NO_RECOVERY_POLICY",0x00001773,"There is no valid encryption recovery policy configured for this system.")

    # (0x00001774) The required encryption driver is not loaded for this system.
    ERROR_NO_EFS = WindowsError::ErrorCode.new("ERROR_NO_EFS",0x00001774,"The required encryption driver is not loaded for this system.")

    # (0x00001775) The file was encrypted with a different encryption driver than is currently loaded.
    ERROR_WRONG_EFS = WindowsError::ErrorCode.new("ERROR_WRONG_EFS",0x00001775,"The file was encrypted with a different encryption driver than is currently loaded.")

    # (0x00001776) There are no Encrypting File System (EFS) keys defined for the user.
    ERROR_NO_USER_KEYS = WindowsError::ErrorCode.new("ERROR_NO_USER_KEYS",0x00001776,"There are no Encrypting File System (EFS) keys defined for the user.")

    # (0x00001777) The specified file is not encrypted.
    ERROR_FILE_NOT_ENCRYPTED = WindowsError::ErrorCode.new("ERROR_FILE_NOT_ENCRYPTED",0x00001777,"The specified file is not encrypted.")

    # (0x00001778) The specified file is not in the defined EFS export format.
    ERROR_NOT_EXPORT_FORMAT = WindowsError::ErrorCode.new("ERROR_NOT_EXPORT_FORMAT",0x00001778,"The specified file is not in the defined EFS export format.")

    # (0x00001779) The specified file is read-only.
    ERROR_FILE_READ_ONLY = WindowsError::ErrorCode.new("ERROR_FILE_READ_ONLY",0x00001779,"The specified file is read-only.")

    # (0x0000177A) The directory has been disabled for encryption.
    ERROR_DIR_EFS_DISALLOWED = WindowsError::ErrorCode.new("ERROR_DIR_EFS_DISALLOWED",0x0000177A,"The directory has been disabled for encryption.")

    # (0x0000177B) The server is not trusted for remote encryption operation.
    ERROR_EFS_SERVER_NOT_TRUSTED = WindowsError::ErrorCode.new("ERROR_EFS_SERVER_NOT_TRUSTED",0x0000177B,"The server is not trusted for remote encryption operation.")

    # (0x0000177C) Recovery policy configured for this system contains invalid recovery certificate.
    ERROR_BAD_RECOVERY_POLICY = WindowsError::ErrorCode.new("ERROR_BAD_RECOVERY_POLICY",0x0000177C,"Recovery policy configured for this system contains invalid recovery certificate.")

    # (0x0000177D) The encryption algorithm used on the source file needs a bigger key buffer than the one on the destination file.
    ERROR_EFS_ALG_BLOB_TOO_BIG = WindowsError::ErrorCode.new("ERROR_EFS_ALG_BLOB_TOO_BIG",0x0000177D,"The encryption algorithm used on the source file needs a bigger key buffer than the one on the destination file.")

    # (0x0000177E) The disk partition does not support file encryption.
    ERROR_VOLUME_NOT_SUPPORT_EFS = WindowsError::ErrorCode.new("ERROR_VOLUME_NOT_SUPPORT_EFS",0x0000177E,"The disk partition does not support file encryption.")

    # (0x0000177F) This machine is disabled for file encryption.
    ERROR_EFS_DISABLED = WindowsError::ErrorCode.new("ERROR_EFS_DISABLED",0x0000177F,"This machine is disabled for file encryption.")

    # (0x00001780) A newer system is required to decrypt this encrypted file.
    ERROR_EFS_VERSION_NOT_SUPPORT = WindowsError::ErrorCode.new("ERROR_EFS_VERSION_NOT_SUPPORT",0x00001780,"A newer system is required to decrypt this encrypted file.")

    # (0x00001781) The remote server sent an invalid response for a file being opened with client-side encryption.
    ERROR_CS_ENCRYPTION_INVALID_SERVER_RESPONSE = WindowsError::ErrorCode.new("ERROR_CS_ENCRYPTION_INVALID_SERVER_RESPONSE",0x00001781,"The remote server sent an invalid response for a file being opened with client-side encryption.")

    # (0x00001782) Client-side encryption is not supported by the remote server even though it claims to support it.
    ERROR_CS_ENCRYPTION_UNSUPPORTED_SERVER = WindowsError::ErrorCode.new("ERROR_CS_ENCRYPTION_UNSUPPORTED_SERVER",0x00001782,"Client-side encryption is not supported by the remote server even though it claims to support it.")

    # (0x00001783) File is encrypted and should be opened in client-side encryption mode.
    ERROR_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE = WindowsError::ErrorCode.new("ERROR_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE",0x00001783,"File is encrypted and should be opened in client-side encryption mode.")

    # (0x00001784) A new encrypted file is being created and a $EFS needs to be provided.
    ERROR_CS_ENCRYPTION_NEW_ENCRYPTED_FILE = WindowsError::ErrorCode.new("ERROR_CS_ENCRYPTION_NEW_ENCRYPTED_FILE",0x00001784,"A new encrypted file is being created and a $EFS needs to be provided.")

    # (0x00001785) The SMB client requested a client-side extension (CSE) file system control (FSCTL) on a non-CSE file.
    ERROR_CS_ENCRYPTION_FILE_NOT_CSE = WindowsError::ErrorCode.new("ERROR_CS_ENCRYPTION_FILE_NOT_CSE",0x00001785,"The SMB client requested a client-side extension (CSE) file system control (FSCTL) on a non-CSE file.")

    # (0x000017E6) The list of servers for this workgroup is not currently available
    ERROR_NO_BROWSER_SERVERS_FOUND = WindowsError::ErrorCode.new("ERROR_NO_BROWSER_SERVERS_FOUND",0x000017E6,"The list of servers for this workgroup is not currently available")

    # (0x00001838) The Task Scheduler service must be configured to run in the System account to function properly. Individual tasks may be configured to run in other accounts.
    SCHED_E_SERVICE_NOT_LOCALSYSTEM = WindowsError::ErrorCode.new("SCHED_E_SERVICE_NOT_LOCALSYSTEM",0x00001838,"The Task Scheduler service must be configured to run in the System account to function properly. Individual tasks may be configured to run in other accounts.")

    # (0x000019C8) The log service encountered an invalid log sector.
    ERROR_LOG_SECTOR_INVALID = WindowsError::ErrorCode.new("ERROR_LOG_SECTOR_INVALID",0x000019C8,"The log service encountered an invalid log sector.")

    # (0x000019C9) The log service encountered a log sector with invalid block parity.
    ERROR_LOG_SECTOR_PARITY_INVALID = WindowsError::ErrorCode.new("ERROR_LOG_SECTOR_PARITY_INVALID",0x000019C9,"The log service encountered a log sector with invalid block parity.")

    # (0x000019CA) The log service encountered a remapped log sector.
    ERROR_LOG_SECTOR_REMAPPED = WindowsError::ErrorCode.new("ERROR_LOG_SECTOR_REMAPPED",0x000019CA,"The log service encountered a remapped log sector.")

    # (0x000019CB) The log service encountered a partial or incomplete log block.
    ERROR_LOG_BLOCK_INCOMPLETE = WindowsError::ErrorCode.new("ERROR_LOG_BLOCK_INCOMPLETE",0x000019CB,"The log service encountered a partial or incomplete log block.")

    # (0x000019CC) The log service encountered an attempt to access data outside the active log range.
    ERROR_LOG_INVALID_RANGE = WindowsError::ErrorCode.new("ERROR_LOG_INVALID_RANGE",0x000019CC,"The log service encountered an attempt to access data outside the active log range.")

    # (0x000019CD) The log service user marshaling buffers are exhausted.
    ERROR_LOG_BLOCKS_EXHAUSTED = WindowsError::ErrorCode.new("ERROR_LOG_BLOCKS_EXHAUSTED",0x000019CD,"The log service user marshaling buffers are exhausted.")

    # (0x000019CE) The log service encountered an attempt to read from a marshaling area with an invalid read context.
    ERROR_LOG_READ_CONTEXT_INVALID = WindowsError::ErrorCode.new("ERROR_LOG_READ_CONTEXT_INVALID",0x000019CE,"The log service encountered an attempt to read from a marshaling area with an invalid read context.")

    # (0x000019CF) The log service encountered an invalid log restart area.
    ERROR_LOG_RESTART_INVALID = WindowsError::ErrorCode.new("ERROR_LOG_RESTART_INVALID",0x000019CF,"The log service encountered an invalid log restart area.")

    # (0x000019D0) The log service encountered an invalid log block version.
    ERROR_LOG_BLOCK_VERSION = WindowsError::ErrorCode.new("ERROR_LOG_BLOCK_VERSION",0x000019D0,"The log service encountered an invalid log block version.")

    # (0x000019D1) The log service encountered an invalid log block.
    ERROR_LOG_BLOCK_INVALID = WindowsError::ErrorCode.new("ERROR_LOG_BLOCK_INVALID",0x000019D1,"The log service encountered an invalid log block.")

    # (0x000019D2) The log service encountered an attempt to read the log with an invalid read mode.
    ERROR_LOG_READ_MODE_INVALID = WindowsError::ErrorCode.new("ERROR_LOG_READ_MODE_INVALID",0x000019D2,"The log service encountered an attempt to read the log with an invalid read mode.")

    # (0x000019D3) The log service encountered a log stream with no restart area.
    ERROR_LOG_NO_RESTART = WindowsError::ErrorCode.new("ERROR_LOG_NO_RESTART",0x000019D3,"The log service encountered a log stream with no restart area.")

    # (0x000019D4) The log service encountered a corrupted metadata file.
    ERROR_LOG_METADATA_CORRUPT = WindowsError::ErrorCode.new("ERROR_LOG_METADATA_CORRUPT",0x000019D4,"The log service encountered a corrupted metadata file.")

    # (0x000019D5) The log service encountered a metadata file that could not be created by the log file system.
    ERROR_LOG_METADATA_INVALID = WindowsError::ErrorCode.new("ERROR_LOG_METADATA_INVALID",0x000019D5,"The log service encountered a metadata file that could not be created by the log file system.")

    # (0x000019D6) The log service encountered a metadata file with inconsistent data.
    ERROR_LOG_METADATA_INCONSISTENT = WindowsError::ErrorCode.new("ERROR_LOG_METADATA_INCONSISTENT",0x000019D6,"The log service encountered a metadata file with inconsistent data.")

    # (0x000019D7) The log service encountered an attempt to erroneous allocate or dispose reservation space.
    ERROR_LOG_RESERVATION_INVALID = WindowsError::ErrorCode.new("ERROR_LOG_RESERVATION_INVALID",0x000019D7,"The log service encountered an attempt to erroneous allocate or dispose reservation space.")

    # (0x000019D8) The log service cannot delete a log file or file system container.
    ERROR_LOG_CANT_DELETE = WindowsError::ErrorCode.new("ERROR_LOG_CANT_DELETE",0x000019D8,"The log service cannot delete a log file or file system container.")

    # (0x000019D9) The log service has reached the maximum allowable containers allocated to a log file.
    ERROR_LOG_CONTAINER_LIMIT_EXCEEDED = WindowsError::ErrorCode.new("ERROR_LOG_CONTAINER_LIMIT_EXCEEDED",0x000019D9,"The log service has reached the maximum allowable containers allocated to a log file.")

    # (0x000019DA) The log service has attempted to read or write backward past the start of the log.
    ERROR_LOG_START_OF_LOG = WindowsError::ErrorCode.new("ERROR_LOG_START_OF_LOG",0x000019DA,"The log service has attempted to read or write backward past the start of the log.")

    # (0x000019DB) The log policy could not be installed because a policy of the same type is already present.
    ERROR_LOG_POLICY_ALREADY_INSTALLED = WindowsError::ErrorCode.new("ERROR_LOG_POLICY_ALREADY_INSTALLED",0x000019DB,"The log policy could not be installed because a policy of the same type is already present.")

    # (0x000019DC) The log policy in question was not installed at the time of the request.
    ERROR_LOG_POLICY_NOT_INSTALLED = WindowsError::ErrorCode.new("ERROR_LOG_POLICY_NOT_INSTALLED",0x000019DC,"The log policy in question was not installed at the time of the request.")

    # (0x000019DD) The installed set of policies on the log is invalid.
    ERROR_LOG_POLICY_INVALID = WindowsError::ErrorCode.new("ERROR_LOG_POLICY_INVALID",0x000019DD,"The installed set of policies on the log is invalid.")

    # (0x000019DE) A policy on the log in question prevented the operation from completing.
    ERROR_LOG_POLICY_CONFLICT = WindowsError::ErrorCode.new("ERROR_LOG_POLICY_CONFLICT",0x000019DE,"A policy on the log in question prevented the operation from completing.")

    # (0x000019DF) Log space cannot be reclaimed because the log is pinned by the archive tail.
    ERROR_LOG_PINNED_ARCHIVE_TAIL = WindowsError::ErrorCode.new("ERROR_LOG_PINNED_ARCHIVE_TAIL",0x000019DF,"Log space cannot be reclaimed because the log is pinned by the archive tail.")

    # (0x000019E0) The log record is not a record in the log file.
    ERROR_LOG_RECORD_NONEXISTENT = WindowsError::ErrorCode.new("ERROR_LOG_RECORD_NONEXISTENT",0x000019E0,"The log record is not a record in the log file.")

    # (0x000019E1) The number of reserved log records or the adjustment of the number of reserved log records is invalid.
    ERROR_LOG_RECORDS_RESERVED_INVALID = WindowsError::ErrorCode.new("ERROR_LOG_RECORDS_RESERVED_INVALID",0x000019E1,"The number of reserved log records or the adjustment of the number of reserved log records is invalid.")

    # (0x000019E2) The reserved log space or the adjustment of the log space is invalid.
    ERROR_LOG_SPACE_RESERVED_INVALID = WindowsError::ErrorCode.new("ERROR_LOG_SPACE_RESERVED_INVALID",0x000019E2,"The reserved log space or the adjustment of the log space is invalid.")

    # (0x000019E3) A new or existing archive tail or base of the active log is invalid.
    ERROR_LOG_TAIL_INVALID = WindowsError::ErrorCode.new("ERROR_LOG_TAIL_INVALID",0x000019E3,"A new or existing archive tail or base of the active log is invalid.")

    # (0x000019E4) The log space is exhausted.
    ERROR_LOG_FULL = WindowsError::ErrorCode.new("ERROR_LOG_FULL",0x000019E4,"The log space is exhausted.")

    # (0x000019E5) The log could not be set to the requested size.
    ERROR_COULD_NOT_RESIZE_LOG = WindowsError::ErrorCode.new("ERROR_COULD_NOT_RESIZE_LOG",0x000019E5,"The log could not be set to the requested size.")

    # (0x000019E6) The log is multiplexed; no direct writes to the physical log are allowed.
    ERROR_LOG_MULTIPLEXED = WindowsError::ErrorCode.new("ERROR_LOG_MULTIPLEXED",0x000019E6,"The log is multiplexed; no direct writes to the physical log are allowed.")

    # (0x000019E7) The operation failed because the log is a dedicated log.
    ERROR_LOG_DEDICATED = WindowsError::ErrorCode.new("ERROR_LOG_DEDICATED",0x000019E7,"The operation failed because the log is a dedicated log.")

    # (0x000019E8) The operation requires an archive context.
    ERROR_LOG_ARCHIVE_NOT_IN_PROGRESS = WindowsError::ErrorCode.new("ERROR_LOG_ARCHIVE_NOT_IN_PROGRESS",0x000019E8,"The operation requires an archive context.")

    # (0x000019E9) Log archival is in progress.
    ERROR_LOG_ARCHIVE_IN_PROGRESS = WindowsError::ErrorCode.new("ERROR_LOG_ARCHIVE_IN_PROGRESS",0x000019E9,"Log archival is in progress.")

    # (0x000019EA) The operation requires a non-ephemeral log, but the log is ephemeral.
    ERROR_LOG_EPHEMERAL = WindowsError::ErrorCode.new("ERROR_LOG_EPHEMERAL",0x000019EA,"The operation requires a non-ephemeral log, but the log is ephemeral.")

    # (0x000019EB) The log must have at least two containers before it can be read from or written to.
    ERROR_LOG_NOT_ENOUGH_CONTAINERS = WindowsError::ErrorCode.new("ERROR_LOG_NOT_ENOUGH_CONTAINERS",0x000019EB,"The log must have at least two containers before it can be read from or written to.")

    # (0x000019EC) A log client has already registered on the stream.
    ERROR_LOG_CLIENT_ALREADY_REGISTERED = WindowsError::ErrorCode.new("ERROR_LOG_CLIENT_ALREADY_REGISTERED",0x000019EC,"A log client has already registered on the stream.")

    # (0x000019ED) A log client has not been registered on the stream.
    ERROR_LOG_CLIENT_NOT_REGISTERED = WindowsError::ErrorCode.new("ERROR_LOG_CLIENT_NOT_REGISTERED",0x000019ED,"A log client has not been registered on the stream.")

    # (0x000019EE) A request has already been made to handle the log full condition.
    ERROR_LOG_FULL_HANDLER_IN_PROGRESS = WindowsError::ErrorCode.new("ERROR_LOG_FULL_HANDLER_IN_PROGRESS",0x000019EE,"A request has already been made to handle the log full condition.")

    # (0x000019EF) The log service encountered an error when attempting to read from a log container.
    ERROR_LOG_CONTAINER_READ_FAILED = WindowsError::ErrorCode.new("ERROR_LOG_CONTAINER_READ_FAILED",0x000019EF,"The log service encountered an error when attempting to read from a log container.")

    # (0x000019F0) The log service encountered an error when attempting to write to a log container.
    ERROR_LOG_CONTAINER_WRITE_FAILED = WindowsError::ErrorCode.new("ERROR_LOG_CONTAINER_WRITE_FAILED",0x000019F0,"The log service encountered an error when attempting to write to a log container.")

    # (0x000019F1) The log service encountered an error when attempting to open a log container.
    ERROR_LOG_CONTAINER_OPEN_FAILED = WindowsError::ErrorCode.new("ERROR_LOG_CONTAINER_OPEN_FAILED",0x000019F1,"The log service encountered an error when attempting to open a log container.")

    # (0x000019F2) The log service encountered an invalid container state when attempting a requested action.
    ERROR_LOG_CONTAINER_STATE_INVALID = WindowsError::ErrorCode.new("ERROR_LOG_CONTAINER_STATE_INVALID",0x000019F2,"The log service encountered an invalid container state when attempting a requested action.")

    # (0x000019F3) The log service is not in the correct state to perform a requested action.
    ERROR_LOG_STATE_INVALID = WindowsError::ErrorCode.new("ERROR_LOG_STATE_INVALID",0x000019F3,"The log service is not in the correct state to perform a requested action.")

    # (0x000019F4) The log space cannot be reclaimed because the log is pinned.
    ERROR_LOG_PINNED = WindowsError::ErrorCode.new("ERROR_LOG_PINNED",0x000019F4,"The log space cannot be reclaimed because the log is pinned.")

    # (0x000019F5) The log metadata flush failed.
    ERROR_LOG_METADATA_FLUSH_FAILED = WindowsError::ErrorCode.new("ERROR_LOG_METADATA_FLUSH_FAILED",0x000019F5,"The log metadata flush failed.")

    # (0x000019F6) Security on the log and its containers is inconsistent.
    ERROR_LOG_INCONSISTENT_SECURITY = WindowsError::ErrorCode.new("ERROR_LOG_INCONSISTENT_SECURITY",0x000019F6,"Security on the log and its containers is inconsistent.")

    # (0x000019F7) Records were appended to the log or reservation changes were made, but the log could not be flushed.
    ERROR_LOG_APPENDED_FLUSH_FAILED = WindowsError::ErrorCode.new("ERROR_LOG_APPENDED_FLUSH_FAILED",0x000019F7,"Records were appended to the log or reservation changes were made, but the log could not be flushed.")

    # (0x000019F8) The log is pinned due to reservation consuming most of the log space. Free some reserved records to make space available.
    ERROR_LOG_PINNED_RESERVATION = WindowsError::ErrorCode.new("ERROR_LOG_PINNED_RESERVATION",0x000019F8,"The log is pinned due to reservation consuming most of the log space. Free some reserved records to make space available.")

    # (0x00001A2C) The transaction handle associated with this operation is not valid.
    ERROR_INVALID_TRANSACTION = WindowsError::ErrorCode.new("ERROR_INVALID_TRANSACTION",0x00001A2C,"The transaction handle associated with this operation is not valid.")

    # (0x00001A2D) The requested operation was made in the context of a transaction that is no longer active.
    ERROR_TRANSACTION_NOT_ACTIVE = WindowsError::ErrorCode.new("ERROR_TRANSACTION_NOT_ACTIVE",0x00001A2D,"The requested operation was made in the context of a transaction that is no longer active.")

    # (0x00001A2E) The requested operation is not valid on the transaction object in its current state.
    ERROR_TRANSACTION_REQUEST_NOT_VALID = WindowsError::ErrorCode.new("ERROR_TRANSACTION_REQUEST_NOT_VALID",0x00001A2E,"The requested operation is not valid on the transaction object in its current state.")

    # (0x00001A2F) The caller has called a response API, but the response is not expected because the transaction manager did not issue the corresponding request to the caller.
    ERROR_TRANSACTION_NOT_REQUESTED = WindowsError::ErrorCode.new("ERROR_TRANSACTION_NOT_REQUESTED",0x00001A2F,"The caller has called a response API, but the response is not expected because the transaction manager did not issue the corresponding request to the caller.")

    # (0x00001A30) It is too late to perform the requested operation because the transaction has already been aborted.
    ERROR_TRANSACTION_ALREADY_ABORTED = WindowsError::ErrorCode.new("ERROR_TRANSACTION_ALREADY_ABORTED",0x00001A30,"It is too late to perform the requested operation because the transaction has already been aborted.")

    # (0x00001A31) It is too late to perform the requested operation because the transaction has already been committed.
    ERROR_TRANSACTION_ALREADY_COMMITTED = WindowsError::ErrorCode.new("ERROR_TRANSACTION_ALREADY_COMMITTED",0x00001A31,"It is too late to perform the requested operation because the transaction has already been committed.")

    # (0x00001A32) The transaction manager was unable to be successfully initialized. Transacted operations are not supported.
    ERROR_TM_INITIALIZATION_FAILED = WindowsError::ErrorCode.new("ERROR_TM_INITIALIZATION_FAILED",0x00001A32,"The transaction manager was unable to be successfully initialized. Transacted operations are not supported.")

    # (0x00001A33) The specified resource manager made no changes or updates to the resource under this transaction.
    ERROR_RESOURCEMANAGER_READ_ONLY = WindowsError::ErrorCode.new("ERROR_RESOURCEMANAGER_READ_ONLY",0x00001A33,"The specified resource manager made no changes or updates to the resource under this transaction.")

    # (0x00001A34) The resource manager has attempted to prepare a transaction that it has not successfully joined.
    ERROR_TRANSACTION_NOT_JOINED = WindowsError::ErrorCode.new("ERROR_TRANSACTION_NOT_JOINED",0x00001A34,"The resource manager has attempted to prepare a transaction that it has not successfully joined.")

    # (0x00001A35) The transaction object already has a superior enlistment, and the caller attempted an operation that would have created a new superior. Only a single superior enlistment is allowed.
    ERROR_TRANSACTION_SUPERIOR_EXISTS = WindowsError::ErrorCode.new("ERROR_TRANSACTION_SUPERIOR_EXISTS",0x00001A35,"The transaction object already has a superior enlistment, and the caller attempted an operation that would have created a new superior. Only a single superior enlistment is allowed.")

    # (0x00001A36) The resource manager tried to register a protocol that already exists.
    ERROR_CRM_PROTOCOL_ALREADY_EXISTS = WindowsError::ErrorCode.new("ERROR_CRM_PROTOCOL_ALREADY_EXISTS",0x00001A36,"The resource manager tried to register a protocol that already exists.")

    # (0x00001A37) The attempt to propagate the transaction failed.
    ERROR_TRANSACTION_PROPAGATION_FAILED = WindowsError::ErrorCode.new("ERROR_TRANSACTION_PROPAGATION_FAILED",0x00001A37,"The attempt to propagate the transaction failed.")

    # (0x00001A38) The requested propagation protocol was not registered as a CRM.
    ERROR_CRM_PROTOCOL_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_CRM_PROTOCOL_NOT_FOUND",0x00001A38,"The requested propagation protocol was not registered as a CRM.")

    # (0x00001A39) The buffer passed in to PushTransaction or PullTransaction is not in a valid format.
    ERROR_TRANSACTION_INVALID_MARSHALL_BUFFER = WindowsError::ErrorCode.new("ERROR_TRANSACTION_INVALID_MARSHALL_BUFFER",0x00001A39,"The buffer passed in to PushTransaction or PullTransaction is not in a valid format.")

    # (0x00001A3A) The current transaction context associated with the thread is not a valid handle to a transaction object.
    ERROR_CURRENT_TRANSACTION_NOT_VALID = WindowsError::ErrorCode.new("ERROR_CURRENT_TRANSACTION_NOT_VALID",0x00001A3A,"The current transaction context associated with the thread is not a valid handle to a transaction object.")

    # (0x00001A3B) The specified transaction object could not be opened because it was not found.
    ERROR_TRANSACTION_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_TRANSACTION_NOT_FOUND",0x00001A3B,"The specified transaction object could not be opened because it was not found.")

    # (0x00001A3C) The specified resource manager object could not be opened because it was not found.
    ERROR_RESOURCEMANAGER_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_RESOURCEMANAGER_NOT_FOUND",0x00001A3C,"The specified resource manager object could not be opened because it was not found.")

    # (0x00001A3D) The specified enlistment object could not be opened because it was not found.
    ERROR_ENLISTMENT_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_ENLISTMENT_NOT_FOUND",0x00001A3D,"The specified enlistment object could not be opened because it was not found.")

    # (0x00001A3E) The specified transaction manager object could not be opened because it was not found.
    ERROR_TRANSACTIONMANAGER_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_TRANSACTIONMANAGER_NOT_FOUND",0x00001A3E,"The specified transaction manager object could not be opened because it was not found.")

    # (0x00001A3F) The specified resource manager was unable to create an enlistment because its associated transaction manager is not online.
    ERROR_TRANSACTIONMANAGER_NOT_ONLINE = WindowsError::ErrorCode.new("ERROR_TRANSACTIONMANAGER_NOT_ONLINE",0x00001A3F,"The specified resource manager was unable to create an enlistment because its associated transaction manager is not online.")

    # (0x00001A40) The specified transaction manager was unable to create the objects contained in its log file in the ObjectB namespace. Therefore, the transaction manager was unable to recover.
    ERROR_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION = WindowsError::ErrorCode.new("ERROR_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION",0x00001A40,"The specified transaction manager was unable to create the objects contained in its log file in the ObjectB namespace. Therefore, the transaction manager was unable to recover.")

    # (0x00001A90) The function attempted to use a name that is reserved for use by another transaction.
    ERROR_TRANSACTIONAL_CONFLICT = WindowsError::ErrorCode.new("ERROR_TRANSACTIONAL_CONFLICT",0x00001A90,"The function attempted to use a name that is reserved for use by another transaction.")

    # (0x00001A91) Transaction support within the specified file system resource manager is not started or was shut down due to an error.
    ERROR_RM_NOT_ACTIVE = WindowsError::ErrorCode.new("ERROR_RM_NOT_ACTIVE",0x00001A91,"Transaction support within the specified file system resource manager is not started or was shut down due to an error.")

    # (0x00001A92) The metadata of the resource manager has been corrupted. The resource manager will not function.
    ERROR_RM_METADATA_CORRUPT = WindowsError::ErrorCode.new("ERROR_RM_METADATA_CORRUPT",0x00001A92,"The metadata of the resource manager has been corrupted. The resource manager will not function.")

    # (0x00001A93) The specified directory does not contain a resource manager.
    ERROR_DIRECTORY_NOT_RM = WindowsError::ErrorCode.new("ERROR_DIRECTORY_NOT_RM",0x00001A93,"The specified directory does not contain a resource manager.")

    # (0x00001A95) The remote server or share does not support transacted file operations.
    ERROR_TRANSACTIONS_UNSUPPORTED_REMOTE = WindowsError::ErrorCode.new("ERROR_TRANSACTIONS_UNSUPPORTED_REMOTE",0x00001A95,"The remote server or share does not support transacted file operations.")

    # (0x00001A96) The requested log size is invalid.
    ERROR_LOG_RESIZE_INVALID_SIZE = WindowsError::ErrorCode.new("ERROR_LOG_RESIZE_INVALID_SIZE",0x00001A96,"The requested log size is invalid.")

    # (0x00001A97) The object (file, stream, link) corresponding to the handle has been deleted by a transaction savepoint rollback.
    ERROR_OBJECT_NO_LONGER_EXISTS = WindowsError::ErrorCode.new("ERROR_OBJECT_NO_LONGER_EXISTS",0x00001A97,"The object (file, stream, link) corresponding to the handle has been deleted by a transaction savepoint rollback.")

    # (0x00001A98) The specified file miniversion was not found for this transacted file open.
    ERROR_STREAM_MINIVERSION_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_STREAM_MINIVERSION_NOT_FOUND",0x00001A98,"The specified file miniversion was not found for this transacted file open.")

    # (0x00001A99) The specified file miniversion was found but has been invalidated. The most likely cause is a transaction savepoint rollback.
    ERROR_STREAM_MINIVERSION_NOT_VALID = WindowsError::ErrorCode.new("ERROR_STREAM_MINIVERSION_NOT_VALID",0x00001A99,"The specified file miniversion was found but has been invalidated. The most likely cause is a transaction savepoint rollback.")

    # (0x00001A9A) A miniversion may only be opened in the context of the transaction that created it.
    ERROR_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION = WindowsError::ErrorCode.new("ERROR_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION",0x00001A9A,"A miniversion may only be opened in the context of the transaction that created it.")

    # (0x00001A9B) It is not possible to open a miniversion with modify access.
    ERROR_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT = WindowsError::ErrorCode.new("ERROR_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT",0x00001A9B,"It is not possible to open a miniversion with modify access.")

    # (0x00001A9C) It is not possible to create any more miniversions for this stream.
    ERROR_CANT_CREATE_MORE_STREAM_MINIVERSIONS = WindowsError::ErrorCode.new("ERROR_CANT_CREATE_MORE_STREAM_MINIVERSIONS",0x00001A9C,"It is not possible to create any more miniversions for this stream.")

    # (0x00001A9E) The remote server sent mismatching version numbers or FID for a file opened with transactions.
    ERROR_REMOTE_FILE_VERSION_MISMATCH = WindowsError::ErrorCode.new("ERROR_REMOTE_FILE_VERSION_MISMATCH",0x00001A9E,"The remote server sent mismatching version numbers or FID for a file opened with transactions.")

    # (0x00001A9F) The handle has been invalidated by a transaction. The most likely cause is the presence of memory mapping on a file, or an open handle when the transaction ended or rolled back to savepoint.
    ERROR_HANDLE_NO_LONGER_VALID = WindowsError::ErrorCode.new("ERROR_HANDLE_NO_LONGER_VALID",0x00001A9F,"The handle has been invalidated by a transaction. The most likely cause is the presence of memory mapping on a file, or an open handle when the transaction ended or rolled back to savepoint.")

    # (0x00001AA0) There is no transaction metadata on the file.
    ERROR_NO_TXF_METADATA = WindowsError::ErrorCode.new("ERROR_NO_TXF_METADATA",0x00001AA0,"There is no transaction metadata on the file.")

    # (0x00001AA1) The log data is corrupt.
    ERROR_LOG_CORRUPTION_DETECTED = WindowsError::ErrorCode.new("ERROR_LOG_CORRUPTION_DETECTED",0x00001AA1,"The log data is corrupt.")

    # (0x00001AA2) The file cannot be recovered because a handle is still open on it.
    ERROR_CANT_RECOVER_WITH_HANDLE_OPEN = WindowsError::ErrorCode.new("ERROR_CANT_RECOVER_WITH_HANDLE_OPEN",0x00001AA2,"The file cannot be recovered because a handle is still open on it.")

    # (0x00001AA3) The transaction outcome is unavailable because the resource manager responsible for it is disconnected.
    ERROR_RM_DISCONNECTED = WindowsError::ErrorCode.new("ERROR_RM_DISCONNECTED",0x00001AA3,"The transaction outcome is unavailable because the resource manager responsible for it is disconnected.")

    # (0x00001AA4) The request was rejected because the enlistment in question is not a superior enlistment.
    ERROR_ENLISTMENT_NOT_SUPERIOR = WindowsError::ErrorCode.new("ERROR_ENLISTMENT_NOT_SUPERIOR",0x00001AA4,"The request was rejected because the enlistment in question is not a superior enlistment.")

    # (0x00001AA5) The transactional resource manager is already consistent. Recovery is not needed.
    ERROR_RECOVERY_NOT_NEEDED = WindowsError::ErrorCode.new("ERROR_RECOVERY_NOT_NEEDED",0x00001AA5,"The transactional resource manager is already consistent. Recovery is not needed.")

    # (0x00001AA6) The transactional resource manager has already been started.
    ERROR_RM_ALREADY_STARTED = WindowsError::ErrorCode.new("ERROR_RM_ALREADY_STARTED",0x00001AA6,"The transactional resource manager has already been started.")

    # (0x00001AA7) The file cannot be opened in a transaction because its identity depends on the outcome of an unresolved transaction.
    ERROR_FILE_IDENTITY_NOT_PERSISTENT = WindowsError::ErrorCode.new("ERROR_FILE_IDENTITY_NOT_PERSISTENT",0x00001AA7,"The file cannot be opened in a transaction because its identity depends on the outcome of an unresolved transaction.")

    # (0x00001AA8) The operation cannot be performed because another transaction is depending on the fact that this property will not change.
    ERROR_CANT_BREAK_TRANSACTIONAL_DEPENDENCY = WindowsError::ErrorCode.new("ERROR_CANT_BREAK_TRANSACTIONAL_DEPENDENCY",0x00001AA8,"The operation cannot be performed because another transaction is depending on the fact that this property will not change.")

    # (0x00001AA9) The operation would involve a single file with two transactional resource managers and is therefore not allowed.
    ERROR_CANT_CROSS_RM_BOUNDARY = WindowsError::ErrorCode.new("ERROR_CANT_CROSS_RM_BOUNDARY",0x00001AA9,"The operation would involve a single file with two transactional resource managers and is therefore not allowed.")

    # (0x00001AAA) The $Txf directory must be empty for this operation to succeed.
    ERROR_TXF_DIR_NOT_EMPTY = WindowsError::ErrorCode.new("ERROR_TXF_DIR_NOT_EMPTY",0x00001AAA,"The $Txf directory must be empty for this operation to succeed.")

    # (0x00001AAB) The operation would leave a transactional resource manager in an inconsistent state and is, therefore, not allowed.
    ERROR_INDOUBT_TRANSACTIONS_EXIST = WindowsError::ErrorCode.new("ERROR_INDOUBT_TRANSACTIONS_EXIST",0x00001AAB,"The operation would leave a transactional resource manager in an inconsistent state and is, therefore, not allowed.")

    # (0x00001AAC) The operation could not be completed because the transaction manager does not have a log.
    ERROR_TM_VOLATILE = WindowsError::ErrorCode.new("ERROR_TM_VOLATILE",0x00001AAC,"The operation could not be completed because the transaction manager does not have a log.")

    # (0x00001AAD) A rollback could not be scheduled because a previously scheduled rollback has already been executed or is queued for execution.
    ERROR_ROLLBACK_TIMER_EXPIRED = WindowsError::ErrorCode.new("ERROR_ROLLBACK_TIMER_EXPIRED",0x00001AAD,"A rollback could not be scheduled because a previously scheduled rollback has already been executed or is queued for execution.")

    # (0x00001AAE) The transactional metadata attribute on the file or directory is corrupt and unreadable.
    ERROR_TXF_ATTRIBUTE_CORRUPT = WindowsError::ErrorCode.new("ERROR_TXF_ATTRIBUTE_CORRUPT",0x00001AAE,"The transactional metadata attribute on the file or directory is corrupt and unreadable.")

    # (0x00001AAF) The encryption operation could not be completed because a transaction is active.
    ERROR_EFS_NOT_ALLOWED_IN_TRANSACTION = WindowsError::ErrorCode.new("ERROR_EFS_NOT_ALLOWED_IN_TRANSACTION",0x00001AAF,"The encryption operation could not be completed because a transaction is active.")

    # (0x00001AB0) This object is not allowed to be opened in a transaction.
    ERROR_TRANSACTIONAL_OPEN_NOT_ALLOWED = WindowsError::ErrorCode.new("ERROR_TRANSACTIONAL_OPEN_NOT_ALLOWED",0x00001AB0,"This object is not allowed to be opened in a transaction.")

    # (0x00001AB1) An attempt to create space in the transactional resource manager's log failed. The failure status has been recorded in the event log.
    ERROR_LOG_GROWTH_FAILED = WindowsError::ErrorCode.new("ERROR_LOG_GROWTH_FAILED",0x00001AB1,"An attempt to create space in the transactional resource manager's log failed. The failure status has been recorded in the event log.")

    # (0x00001AB2) Memory mapping (creating a mapped section) to a remote file under a transaction is not supported.
    ERROR_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE = WindowsError::ErrorCode.new("ERROR_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE",0x00001AB2,"Memory mapping (creating a mapped section) to a remote file under a transaction is not supported.")

    # (0x00001AB3) Transaction metadata is already present on this file and cannot be superseded.
    ERROR_TXF_METADATA_ALREADY_PRESENT = WindowsError::ErrorCode.new("ERROR_TXF_METADATA_ALREADY_PRESENT",0x00001AB3,"Transaction metadata is already present on this file and cannot be superseded.")

    # (0x00001AB4) A transaction scope could not be entered because the scope handler has not been initialized.
    ERROR_TRANSACTION_SCOPE_CALLBACKS_NOT_SET = WindowsError::ErrorCode.new("ERROR_TRANSACTION_SCOPE_CALLBACKS_NOT_SET",0x00001AB4,"A transaction scope could not be entered because the scope handler has not been initialized.")

    # (0x00001AB5) Promotion was required to allow the resource manager to enlist, but the transaction was set to disallow it.
    ERROR_TRANSACTION_REQUIRED_PROMOTION = WindowsError::ErrorCode.new("ERROR_TRANSACTION_REQUIRED_PROMOTION",0x00001AB5,"Promotion was required to allow the resource manager to enlist, but the transaction was set to disallow it.")

    # (0x00001AB6) This file is open for modification in an unresolved transaction and may be opened for execution only by a transacted reader.
    ERROR_CANNOT_EXECUTE_FILE_IN_TRANSACTION = WindowsError::ErrorCode.new("ERROR_CANNOT_EXECUTE_FILE_IN_TRANSACTION",0x00001AB6,"This file is open for modification in an unresolved transaction and may be opened for execution only by a transacted reader.")

    # (0x00001AB7) The request to thaw frozen transactions was ignored because transactions were not previously frozen.
    ERROR_TRANSACTIONS_NOT_FROZEN = WindowsError::ErrorCode.new("ERROR_TRANSACTIONS_NOT_FROZEN",0x00001AB7,"The request to thaw frozen transactions was ignored because transactions were not previously frozen.")

    # (0x00001AB8) Transactions cannot be frozen because a freeze is already in progress.
    ERROR_TRANSACTION_FREEZE_IN_PROGRESS = WindowsError::ErrorCode.new("ERROR_TRANSACTION_FREEZE_IN_PROGRESS",0x00001AB8,"Transactions cannot be frozen because a freeze is already in progress.")

    # (0x00001AB9) The target volume is not a snapshot volume. This operation is only valid on a volume mounted as a snapshot.
    ERROR_NOT_SNAPSHOT_VOLUME = WindowsError::ErrorCode.new("ERROR_NOT_SNAPSHOT_VOLUME",0x00001AB9,"The target volume is not a snapshot volume. This operation is only valid on a volume mounted as a snapshot.")

    # (0x00001ABA) The savepoint operation failed because files are open on the transaction. This is not permitted.
    ERROR_NO_SAVEPOINT_WITH_OPEN_FILES = WindowsError::ErrorCode.new("ERROR_NO_SAVEPOINT_WITH_OPEN_FILES",0x00001ABA,"The savepoint operation failed because files are open on the transaction. This is not permitted.")

    # (0x00001ABB) Windows has discovered corruption in a file, and that file has since been repaired. Data loss may have occurred.
    ERROR_DATA_LOST_REPAIR = WindowsError::ErrorCode.new("ERROR_DATA_LOST_REPAIR",0x00001ABB,"Windows has discovered corruption in a file, and that file has since been repaired. Data loss may have occurred.")

    # (0x00001ABC) The sparse operation could not be completed because a transaction is active on the file.
    ERROR_SPARSE_NOT_ALLOWED_IN_TRANSACTION = WindowsError::ErrorCode.new("ERROR_SPARSE_NOT_ALLOWED_IN_TRANSACTION",0x00001ABC,"The sparse operation could not be completed because a transaction is active on the file.")

    # (0x00001ABD) The call to create a transaction manager object failed because the Tm Identity stored in the logfile does not match the Tm Identity that was passed in as an argument.
    ERROR_TM_IDENTITY_MISMATCH = WindowsError::ErrorCode.new("ERROR_TM_IDENTITY_MISMATCH",0x00001ABD,"The call to create a transaction manager object failed because the Tm Identity stored in the logfile does not match the Tm Identity that was passed in as an argument.")

    # (0x00001ABE) I/O was attempted on a section object that has been floated as a result of a transaction ending. There is no valid data.
    ERROR_FLOATED_SECTION = WindowsError::ErrorCode.new("ERROR_FLOATED_SECTION",0x00001ABE,"I/O was attempted on a section object that has been floated as a result of a transaction ending. There is no valid data.")

    # (0x00001ABF) The transactional resource manager cannot currently accept transacted work due to a transient condition, such as low resources.
    ERROR_CANNOT_ACCEPT_TRANSACTED_WORK = WindowsError::ErrorCode.new("ERROR_CANNOT_ACCEPT_TRANSACTED_WORK",0x00001ABF,"The transactional resource manager cannot currently accept transacted work due to a transient condition, such as low resources.")

    # (0x00001AC0) The transactional resource manager had too many transactions outstanding that could not be aborted. The transactional resource manager has been shut down.
    ERROR_CANNOT_ABORT_TRANSACTIONS = WindowsError::ErrorCode.new("ERROR_CANNOT_ABORT_TRANSACTIONS",0x00001AC0,"The transactional resource manager had too many transactions outstanding that could not be aborted. The transactional resource manager has been shut down.")

    # (0x00001B59) The specified session name is invalid.
    ERROR_CTX_WINSTATION_NAME_INVALID = WindowsError::ErrorCode.new("ERROR_CTX_WINSTATION_NAME_INVALID",0x00001B59,"The specified session name is invalid.")

    # (0x00001B5A) The specified protocol driver is invalid.
    ERROR_CTX_INVALID_PD = WindowsError::ErrorCode.new("ERROR_CTX_INVALID_PD",0x00001B5A,"The specified protocol driver is invalid.")

    # (0x00001B5B) The specified protocol driver was not found in the system path.
    ERROR_CTX_PD_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_CTX_PD_NOT_FOUND",0x00001B5B,"The specified protocol driver was not found in the system path.")

    # (0x00001B5C) The specified terminal connection driver was not found in the system path.
    ERROR_CTX_WD_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_CTX_WD_NOT_FOUND",0x00001B5C,"The specified terminal connection driver was not found in the system path.")

    # (0x00001B5D) A registry key for event logging could not be created for this session.
    ERROR_CTX_CANNOT_MAKE_EVENTLOG_ENTRY = WindowsError::ErrorCode.new("ERROR_CTX_CANNOT_MAKE_EVENTLOG_ENTRY",0x00001B5D,"A registry key for event logging could not be created for this session.")

    # (0x00001B5E) A service with the same name already exists on the system.
    ERROR_CTX_SERVICE_NAME_COLLISION = WindowsError::ErrorCode.new("ERROR_CTX_SERVICE_NAME_COLLISION",0x00001B5E,"A service with the same name already exists on the system.")

    # (0x00001B5F) A close operation is pending on the session.
    ERROR_CTX_CLOSE_PENDING = WindowsError::ErrorCode.new("ERROR_CTX_CLOSE_PENDING",0x00001B5F,"A close operation is pending on the session.")

    # (0x00001B60) There are no free output buffers available.
    ERROR_CTX_NO_OUTBUF = WindowsError::ErrorCode.new("ERROR_CTX_NO_OUTBUF",0x00001B60,"There are no free output buffers available.")

    # (0x00001B61) The MODEM.INF file was not found.
    ERROR_CTX_MODEM_INF_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_CTX_MODEM_INF_NOT_FOUND",0x00001B61,"The MODEM.INF file was not found.")

    # (0x00001B62) The modem name was not found in the MODEM.INF file.
    ERROR_CTX_INVALID_MODEMNAME = WindowsError::ErrorCode.new("ERROR_CTX_INVALID_MODEMNAME",0x00001B62,"The modem name was not found in the MODEM.INF file.")

    # (0x00001B63) The modem did not accept the command sent to it. Verify that the configured modem name matches the attached modem.
    ERROR_CTX_MODEM_RESPONSE_ERROR = WindowsError::ErrorCode.new("ERROR_CTX_MODEM_RESPONSE_ERROR",0x00001B63,"The modem did not accept the command sent to it. Verify that the configured modem name matches the attached modem.")

    # (0x00001B64) The modem did not respond to the command sent to it. Verify that the modem is properly cabled and turned on.
    ERROR_CTX_MODEM_RESPONSE_TIMEOUT = WindowsError::ErrorCode.new("ERROR_CTX_MODEM_RESPONSE_TIMEOUT",0x00001B64,"The modem did not respond to the command sent to it. Verify that the modem is properly cabled and turned on.")

    # (0x00001B65) Carrier detect has failed or carrier has been dropped due to disconnect.
    ERROR_CTX_MODEM_RESPONSE_NO_CARRIER = WindowsError::ErrorCode.new("ERROR_CTX_MODEM_RESPONSE_NO_CARRIER",0x00001B65,"Carrier detect has failed or carrier has been dropped due to disconnect.")

    # (0x00001B66) Dial tone not detected within the required time. Verify that the phone cable is properly attached and functional.
    ERROR_CTX_MODEM_RESPONSE_NO_DIALTONE = WindowsError::ErrorCode.new("ERROR_CTX_MODEM_RESPONSE_NO_DIALTONE",0x00001B66,"Dial tone not detected within the required time. Verify that the phone cable is properly attached and functional.")

    # (0x00001B67) Busy signal detected at remote site on callback.
    ERROR_CTX_MODEM_RESPONSE_BUSY = WindowsError::ErrorCode.new("ERROR_CTX_MODEM_RESPONSE_BUSY",0x00001B67,"Busy signal detected at remote site on callback.")

    # (0x00001B68) Voice detected at remote site on callback.
    ERROR_CTX_MODEM_RESPONSE_VOICE = WindowsError::ErrorCode.new("ERROR_CTX_MODEM_RESPONSE_VOICE",0x00001B68,"Voice detected at remote site on callback.")

    # (0x00001B69) Transport driver error.
    ERROR_CTX_TD_ERROR = WindowsError::ErrorCode.new("ERROR_CTX_TD_ERROR",0x00001B69,"Transport driver error.")

    # (0x00001B6E) The specified session cannot be found.
    ERROR_CTX_WINSTATION_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_CTX_WINSTATION_NOT_FOUND",0x00001B6E,"The specified session cannot be found.")

    # (0x00001B6F) The specified session name is already in use.
    ERROR_CTX_WINSTATION_ALREADY_EXISTS = WindowsError::ErrorCode.new("ERROR_CTX_WINSTATION_ALREADY_EXISTS",0x00001B6F,"The specified session name is already in use.")

    # (0x00001B70) The requested operation cannot be completed because the terminal connection is currently busy processing a connect, disconnect, reset, or delete operation.
    ERROR_CTX_WINSTATION_BUSY = WindowsError::ErrorCode.new("ERROR_CTX_WINSTATION_BUSY",0x00001B70,"The requested operation cannot be completed because the terminal connection is currently busy processing a connect, disconnect, reset, or delete operation.")

    # (0x00001B71) An attempt has been made to connect to a session whose video mode is not supported by the current client.
    ERROR_CTX_BAD_VIDEO_MODE = WindowsError::ErrorCode.new("ERROR_CTX_BAD_VIDEO_MODE",0x00001B71,"An attempt has been made to connect to a session whose video mode is not supported by the current client.")

    # (0x00001B7B) The application attempted to enable DOS graphics mode. DOS graphics mode is not supported.
    ERROR_CTX_GRAPHICS_INVALID = WindowsError::ErrorCode.new("ERROR_CTX_GRAPHICS_INVALID",0x00001B7B,"The application attempted to enable DOS graphics mode. DOS graphics mode is not supported.")

    # (0x00001B7D) Your interactive logon privilege has been disabled. Contact your administrator.
    ERROR_CTX_LOGON_DISABLED = WindowsError::ErrorCode.new("ERROR_CTX_LOGON_DISABLED",0x00001B7D,"Your interactive logon privilege has been disabled. Contact your administrator.")

    # (0x00001B7E) The requested operation can be performed only on the system console. This is most often the result of a driver or system DLL requiring direct console access.
    ERROR_CTX_NOT_CONSOLE = WindowsError::ErrorCode.new("ERROR_CTX_NOT_CONSOLE",0x00001B7E,"The requested operation can be performed only on the system console. This is most often the result of a driver or system DLL requiring direct console access.")

    # (0x00001B80) The client failed to respond to the server connect message.
    ERROR_CTX_CLIENT_QUERY_TIMEOUT = WindowsError::ErrorCode.new("ERROR_CTX_CLIENT_QUERY_TIMEOUT",0x00001B80,"The client failed to respond to the server connect message.")

    # (0x00001B81) Disconnecting the console session is not supported.
    ERROR_CTX_CONSOLE_DISCONNECT = WindowsError::ErrorCode.new("ERROR_CTX_CONSOLE_DISCONNECT",0x00001B81,"Disconnecting the console session is not supported.")

    # (0x00001B82) Reconnecting a disconnected session to the console is not supported.
    ERROR_CTX_CONSOLE_CONNECT = WindowsError::ErrorCode.new("ERROR_CTX_CONSOLE_CONNECT",0x00001B82,"Reconnecting a disconnected session to the console is not supported.")

    # (0x00001B84) The request to control another session remotely was denied.
    ERROR_CTX_SHADOW_DENIED = WindowsError::ErrorCode.new("ERROR_CTX_SHADOW_DENIED",0x00001B84,"The request to control another session remotely was denied.")

    # (0x00001B85) The requested session access is denied.
    ERROR_CTX_WINSTATION_ACCESS_DENIED = WindowsError::ErrorCode.new("ERROR_CTX_WINSTATION_ACCESS_DENIED",0x00001B85,"The requested session access is denied.")

    # (0x00001B89) The specified terminal connection driver is invalid.
    ERROR_CTX_INVALID_WD = WindowsError::ErrorCode.new("ERROR_CTX_INVALID_WD",0x00001B89,"The specified terminal connection driver is invalid.")

    # (0x00001B8A) The requested session cannot be controlled remotely. This may be because the session is disconnected or does not currently have a user logged on.
    ERROR_CTX_SHADOW_INVALID = WindowsError::ErrorCode.new("ERROR_CTX_SHADOW_INVALID",0x00001B8A,"The requested session cannot be controlled remotely. This may be because the session is disconnected or does not currently have a user logged on.")

    # (0x00001B8B) The requested session is not configured to allow remote control.
    ERROR_CTX_SHADOW_DISABLED = WindowsError::ErrorCode.new("ERROR_CTX_SHADOW_DISABLED",0x00001B8B,"The requested session is not configured to allow remote control.")

    # (0x00001B8C) Your request to connect to this terminal server has been rejected. Your terminal server client license number is currently being used by another user. Call your system administrator to obtain a unique license number.
    ERROR_CTX_CLIENT_LICENSE_IN_USE = WindowsError::ErrorCode.new("ERROR_CTX_CLIENT_LICENSE_IN_USE",0x00001B8C,"Your request to connect to this terminal server has been rejected. Your terminal server client license number is currently being used by another user. Call your system administrator to obtain a unique license number.")

    # (0x00001B8D) Your request to connect to this terminal server has been rejected. Your terminal server client license number has not been entered for this copy of the terminal server client. Contact your system administrator.
    ERROR_CTX_CLIENT_LICENSE_NOT_SET = WindowsError::ErrorCode.new("ERROR_CTX_CLIENT_LICENSE_NOT_SET",0x00001B8D,"Your request to connect to this terminal server has been rejected. Your terminal server client license number has not been entered for this copy of the terminal server client. Contact your system administrator.")

    # (0x00001B8E) The number of connections to this computer is limited and all connections are in use right now. Try connecting later or contact your system administrator.
    ERROR_CTX_LICENSE_NOT_AVAILABLE = WindowsError::ErrorCode.new("ERROR_CTX_LICENSE_NOT_AVAILABLE",0x00001B8E,"The number of connections to this computer is limited and all connections are in use right now. Try connecting later or contact your system administrator.")

    # (0x00001B8F) The client you are using is not licensed to use this system. Your logon request is denied.
    ERROR_CTX_LICENSE_CLIENT_INVALID = WindowsError::ErrorCode.new("ERROR_CTX_LICENSE_CLIENT_INVALID",0x00001B8F,"The client you are using is not licensed to use this system. Your logon request is denied.")

    # (0x00001B90) The system license has expired. Your logon request is denied.
    ERROR_CTX_LICENSE_EXPIRED = WindowsError::ErrorCode.new("ERROR_CTX_LICENSE_EXPIRED",0x00001B90,"The system license has expired. Your logon request is denied.")

    # (0x00001B91) Remote control could not be terminated because the specified session is not currently being remotely controlled.
    ERROR_CTX_SHADOW_NOT_RUNNING = WindowsError::ErrorCode.new("ERROR_CTX_SHADOW_NOT_RUNNING",0x00001B91,"Remote control could not be terminated because the specified session is not currently being remotely controlled.")

    # (0x00001B92) The remote control of the console was terminated because the display mode was changed. Changing the display mode in a remote control session is not supported.
    ERROR_CTX_SHADOW_ENDED_BY_MODE_CHANGE = WindowsError::ErrorCode.new("ERROR_CTX_SHADOW_ENDED_BY_MODE_CHANGE",0x00001B92,"The remote control of the console was terminated because the display mode was changed. Changing the display mode in a remote control session is not supported.")

    # (0x00001B93) Activation has already been reset the maximum number of times for this installation. Your activation timer will not be cleared.
    ERROR_ACTIVATION_COUNT_EXCEEDED = WindowsError::ErrorCode.new("ERROR_ACTIVATION_COUNT_EXCEEDED",0x00001B93,"Activation has already been reset the maximum number of times for this installation. Your activation timer will not be cleared.")

    # (0x00001B94) Remote logons are currently disabled.
    ERROR_CTX_WINSTATIONS_DISABLED = WindowsError::ErrorCode.new("ERROR_CTX_WINSTATIONS_DISABLED",0x00001B94,"Remote logons are currently disabled.")

    # (0x00001B95) You do not have the proper encryption level to access this session.
    ERROR_CTX_ENCRYPTION_LEVEL_REQUIRED = WindowsError::ErrorCode.new("ERROR_CTX_ENCRYPTION_LEVEL_REQUIRED",0x00001B95,"You do not have the proper encryption level to access this session.")

    # (0x00001B96) The user %s\\%s is currently logged on to this computer. Only the current user or an administrator can log on to this computer.
    ERROR_CTX_SESSION_IN_USE = WindowsError::ErrorCode.new("ERROR_CTX_SESSION_IN_USE",0x00001B96,"The user %s\\\\%s is currently logged on to this computer. Only the current user or an administrator can log on to this computer.")

    # (0x00001B97) The user %s\\%s is already logged on to the console of this computer. You do not have permission to log in at this time. To resolve this issue, contact %s\\%s and have them log off.
    ERROR_CTX_NO_FORCE_LOGOFF = WindowsError::ErrorCode.new("ERROR_CTX_NO_FORCE_LOGOFF",0x00001B97,"The user %s\\\\%s is already logged on to the console of this computer. You do not have permission to log in at this time. To resolve this issue, contact %s\\\\%s and have them log off.")

    # (0x00001B98) Unable to log you on because of an account restriction.
    ERROR_CTX_ACCOUNT_RESTRICTION = WindowsError::ErrorCode.new("ERROR_CTX_ACCOUNT_RESTRICTION",0x00001B98,"Unable to log you on because of an account restriction.")

    # (0x00001B99) The RDP component %2 detected an error in the protocol stream and has disconnected the client.
    ERROR_RDP_PROTOCOL_ERROR = WindowsError::ErrorCode.new("ERROR_RDP_PROTOCOL_ERROR",0x00001B99,"The RDP component %2 detected an error in the protocol stream and has disconnected the client.")

    # (0x00001B9A) The Client Drive Mapping Service has connected on terminal connection.
    ERROR_CTX_CDM_CONNECT = WindowsError::ErrorCode.new("ERROR_CTX_CDM_CONNECT",0x00001B9A,"The Client Drive Mapping Service has connected on terminal connection.")

    # (0x00001B9B) The Client Drive Mapping Service has disconnected on terminal connection.
    ERROR_CTX_CDM_DISCONNECT = WindowsError::ErrorCode.new("ERROR_CTX_CDM_DISCONNECT",0x00001B9B,"The Client Drive Mapping Service has disconnected on terminal connection.")

    # (0x00001B9C) The terminal server security layer detected an error in the protocol stream and has disconnected the client.
    ERROR_CTX_SECURITY_LAYER_ERROR = WindowsError::ErrorCode.new("ERROR_CTX_SECURITY_LAYER_ERROR",0x00001B9C,"The terminal server security layer detected an error in the protocol stream and has disconnected the client.")

    # (0x00001B9D) The target session is incompatible with the current session.
    ERROR_TS_INCOMPATIBLE_SESSIONS = WindowsError::ErrorCode.new("ERROR_TS_INCOMPATIBLE_SESSIONS",0x00001B9D,"The target session is incompatible with the current session.")

    # (0x00001F41) The file replication service API was called incorrectly.
    FRS_ERR_INVALID_API_SEQUENCE = WindowsError::ErrorCode.new("FRS_ERR_INVALID_API_SEQUENCE",0x00001F41,"The file replication service API was called incorrectly.")

    # (0x00001F42) The file replication service cannot be started.
    FRS_ERR_STARTING_SERVICE = WindowsError::ErrorCode.new("FRS_ERR_STARTING_SERVICE",0x00001F42,"The file replication service cannot be started.")

    # (0x00001F43) The file replication service cannot be stopped.
    FRS_ERR_STOPPING_SERVICE = WindowsError::ErrorCode.new("FRS_ERR_STOPPING_SERVICE",0x00001F43,"The file replication service cannot be stopped.")

    # (0x00001F44) The file replication service API terminated the request. The event log may have more information.
    FRS_ERR_INTERNAL_API = WindowsError::ErrorCode.new("FRS_ERR_INTERNAL_API",0x00001F44,"The file replication service API terminated the request. The event log may have more information.")

    # (0x00001F45) The file replication service terminated the request. The event log may have more information.
    FRS_ERR_INTERNAL = WindowsError::ErrorCode.new("FRS_ERR_INTERNAL",0x00001F45,"The file replication service terminated the request. The event log may have more information.")

    # (0x00001F46) The file replication service cannot be contacted. The event log may have more information.
    FRS_ERR_SERVICE_COMM = WindowsError::ErrorCode.new("FRS_ERR_SERVICE_COMM",0x00001F46,"The file replication service cannot be contacted. The event log may have more information.")

    # (0x00001F47) The file replication service cannot satisfy the request because the user has insufficient privileges. The event log may have more information.
    FRS_ERR_INSUFFICIENT_PRIV = WindowsError::ErrorCode.new("FRS_ERR_INSUFFICIENT_PRIV",0x00001F47,"The file replication service cannot satisfy the request because the user has insufficient privileges. The event log may have more information.")

    # (0x00001F48) The file replication service cannot satisfy the request because authenticated RPC is not available. The event log may have more information.
    FRS_ERR_AUTHENTICATION = WindowsError::ErrorCode.new("FRS_ERR_AUTHENTICATION",0x00001F48,"The file replication service cannot satisfy the request because authenticated RPC is not available. The event log may have more information.")

    # (0x00001F49) The file replication service cannot satisfy the request because the user has insufficient privileges on the domain controller. The event log may have more information.
    FRS_ERR_PARENT_INSUFFICIENT_PRIV = WindowsError::ErrorCode.new("FRS_ERR_PARENT_INSUFFICIENT_PRIV",0x00001F49,"The file replication service cannot satisfy the request because the user has insufficient privileges on the domain controller. The event log may have more information.")

    # (0x00001F4A) The file replication service cannot satisfy the request because authenticated RPC is not available on the domain controller. The event log may have more information.
    FRS_ERR_PARENT_AUTHENTICATION = WindowsError::ErrorCode.new("FRS_ERR_PARENT_AUTHENTICATION",0x00001F4A,"The file replication service cannot satisfy the request because authenticated RPC is not available on the domain controller. The event log may have more information.")

    # (0x00001F4B) The file replication service cannot communicate with the file replication service on the domain controller. The event log may have more information.
    FRS_ERR_CHILD_TO_PARENT_COMM = WindowsError::ErrorCode.new("FRS_ERR_CHILD_TO_PARENT_COMM",0x00001F4B,"The file replication service cannot communicate with the file replication service on the domain controller. The event log may have more information.")

    # (0x00001F4C) The file replication service on the domain controller cannot communicate with the file replication service on this computer. The event log may have more information.
    FRS_ERR_PARENT_TO_CHILD_COMM = WindowsError::ErrorCode.new("FRS_ERR_PARENT_TO_CHILD_COMM",0x00001F4C,"The file replication service on the domain controller cannot communicate with the file replication service on this computer. The event log may have more information.")

    # (0x00001F4D) The file replication service cannot populate the system volume because of an internal error. The event log may have more information.
    FRS_ERR_SYSVOL_POPULATE = WindowsError::ErrorCode.new("FRS_ERR_SYSVOL_POPULATE",0x00001F4D,"The file replication service cannot populate the system volume because of an internal error. The event log may have more information.")

    # (0x00001F4E) The file replication service cannot populate the system volume because of an internal time-out. The event log may have more information.
    FRS_ERR_SYSVOL_POPULATE_TIMEOUT = WindowsError::ErrorCode.new("FRS_ERR_SYSVOL_POPULATE_TIMEOUT",0x00001F4E,"The file replication service cannot populate the system volume because of an internal time-out. The event log may have more information.")

    # (0x00001F4F) The file replication service cannot process the request. The system volume is busy with a previous request.
    FRS_ERR_SYSVOL_IS_BUSY = WindowsError::ErrorCode.new("FRS_ERR_SYSVOL_IS_BUSY",0x00001F4F,"The file replication service cannot process the request. The system volume is busy with a previous request.")

    # (0x00001F50) The file replication service cannot stop replicating the system volume because of an internal error. The event log may have more information.
    FRS_ERR_SYSVOL_DEMOTE = WindowsError::ErrorCode.new("FRS_ERR_SYSVOL_DEMOTE",0x00001F50,"The file replication service cannot stop replicating the system volume because of an internal error. The event log may have more information.")

    # (0x00001F51) The file replication service detected an invalid parameter.
    FRS_ERR_INVALID_SERVICE_PARAMETER = WindowsError::ErrorCode.new("FRS_ERR_INVALID_SERVICE_PARAMETER",0x00001F51,"The file replication service detected an invalid parameter.")

    # (0x00002008) An error occurred while installing the directory service. For more information, see the event log.
    ERROR_DS_NOT_INSTALLED = WindowsError::ErrorCode.new("ERROR_DS_NOT_INSTALLED",0x00002008,"An error occurred while installing the directory service. For more information, see the event log.")

    # (0x00002009) The directory service evaluated group memberships locally.
    ERROR_DS_MEMBERSHIP_EVALUATED_LOCALLY = WindowsError::ErrorCode.new("ERROR_DS_MEMBERSHIP_EVALUATED_LOCALLY",0x00002009,"The directory service evaluated group memberships locally.")

    # (0x0000200A) The specified directory service attribute or value does not exist.
    ERROR_DS_NO_ATTRIBUTE_OR_VALUE = WindowsError::ErrorCode.new("ERROR_DS_NO_ATTRIBUTE_OR_VALUE",0x0000200A,"The specified directory service attribute or value does not exist.")

    # (0x0000200B) The attribute syntax specified to the directory service is invalid.
    ERROR_DS_INVALID_ATTRIBUTE_YNTAX = WindowsError::ErrorCode.new("ERROR_DS_INVALID_ATTRIBUTE_YNTAX",0x0000200B,"The attribute syntax specified to the directory service is invalid.")

    # (0x0000200C) The attribute type specified to the directory service is not defined.
    ERROR_DS_ATTRIBUTE_TYPE_UNDEFINED = WindowsError::ErrorCode.new("ERROR_DS_ATTRIBUTE_TYPE_UNDEFINED",0x0000200C,"The attribute type specified to the directory service is not defined.")

    # (0x0000200D) The specified directory service attribute or value already exists.
    ERROR_DS_ATTRIBUTE_OR_VALUE_EXISTS = WindowsError::ErrorCode.new("ERROR_DS_ATTRIBUTE_OR_VALUE_EXISTS",0x0000200D,"The specified directory service attribute or value already exists.")

    # (0x0000200E) The directory service is busy.
    ERROR_DS_BUSY = WindowsError::ErrorCode.new("ERROR_DS_BUSY",0x0000200E,"The directory service is busy.")

    # (0x0000200F) The directory service is unavailable.
    ERROR_DS_UNAVAILABLE = WindowsError::ErrorCode.new("ERROR_DS_UNAVAILABLE",0x0000200F,"The directory service is unavailable.")

    # (0x00002010) The directory service was unable to allocate a relative identifier.
    ERROR_DS_NO_RIDS_ALLOCATED = WindowsError::ErrorCode.new("ERROR_DS_NO_RIDS_ALLOCATED",0x00002010,"The directory service was unable to allocate a relative identifier.")

    # (0x00002011) The directory service has exhausted the pool of relative identifiers.
    ERROR_DS_NO_MORE_RIDS = WindowsError::ErrorCode.new("ERROR_DS_NO_MORE_RIDS",0x00002011,"The directory service has exhausted the pool of relative identifiers.")

    # (0x00002012) The requested operation could not be performed because the directory service is not the master for that type of operation.
    ERROR_DS_INCORRECT_ROLE_OWNER = WindowsError::ErrorCode.new("ERROR_DS_INCORRECT_ROLE_OWNER",0x00002012,"The requested operation could not be performed because the directory service is not the master for that type of operation.")

    # (0x00002013) The directory service was unable to initialize the subsystem that allocates relative identifiers.
    ERROR_DS_RIDMGR_INIT_ERROR = WindowsError::ErrorCode.new("ERROR_DS_RIDMGR_INIT_ERROR",0x00002013,"The directory service was unable to initialize the subsystem that allocates relative identifiers.")

    # (0x00002014) The requested operation did not satisfy one or more constraints associated with the class of the object.
    ERROR_DS_OBJ_CLASS_VIOLATION = WindowsError::ErrorCode.new("ERROR_DS_OBJ_CLASS_VIOLATION",0x00002014,"The requested operation did not satisfy one or more constraints associated with the class of the object.")

    # (0x00002015) The directory service can perform the requested operation only on a leaf object.
    ERROR_DS_CANT_ON_NON_LEAF = WindowsError::ErrorCode.new("ERROR_DS_CANT_ON_NON_LEAF",0x00002015,"The directory service can perform the requested operation only on a leaf object.")

    # (0x00002016) The directory service cannot perform the requested operation on the relative distinguished name (RDN) attribute of an object.
    ERROR_DS_CANT_ON_RDN = WindowsError::ErrorCode.new("ERROR_DS_CANT_ON_RDN",0x00002016,"The directory service cannot perform the requested operation on the relative distinguished name (RDN) attribute of an object.")

    # (0x00002017) The directory service detected an attempt to modify the object class of an object.
    ERROR_DS_CANT_MOD_OBJ_CLASS = WindowsError::ErrorCode.new("ERROR_DS_CANT_MOD_OBJ_CLASS",0x00002017,"The directory service detected an attempt to modify the object class of an object.")

    # (0x00002018) The requested cross-domain move operation could not be performed.
    ERROR_DS_CROSS_DOM_MOVE_ERROR = WindowsError::ErrorCode.new("ERROR_DS_CROSS_DOM_MOVE_ERROR",0x00002018,"The requested cross-domain move operation could not be performed.")

    # (0x00002019) Unable to contact the global catalog (GC) server.
    ERROR_DS_GC_NOT_AVAILABLE = WindowsError::ErrorCode.new("ERROR_DS_GC_NOT_AVAILABLE",0x00002019,"Unable to contact the global catalog (GC) server.")

    # (0x0000201A) The policy object is shared and can only be modified at the root.
    ERROR_SHARED_POLICY = WindowsError::ErrorCode.new("ERROR_SHARED_POLICY",0x0000201A,"The policy object is shared and can only be modified at the root.")

    # (0x0000201B) The policy object does not exist.
    ERROR_POLICY_OBJECT_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_POLICY_OBJECT_NOT_FOUND",0x0000201B,"The policy object does not exist.")

    # (0x0000201C) The requested policy information is only in the directory service.
    ERROR_POLICY_ONLY_IN_DS = WindowsError::ErrorCode.new("ERROR_POLICY_ONLY_IN_DS",0x0000201C,"The requested policy information is only in the directory service.")

    # (0x0000201D) A domain controller promotion is currently active.
    ERROR_PROMOTION_ACTIVE = WindowsError::ErrorCode.new("ERROR_PROMOTION_ACTIVE",0x0000201D,"A domain controller promotion is currently active.")

    # (0x0000201E) A domain controller promotion is not currently active.
    ERROR_NO_PROMOTION_ACTIVE = WindowsError::ErrorCode.new("ERROR_NO_PROMOTION_ACTIVE",0x0000201E,"A domain controller promotion is not currently active.")

    # (0x00002020) An operations error occurred.
    ERROR_DS_OPERATIONS_ERROR = WindowsError::ErrorCode.new("ERROR_DS_OPERATIONS_ERROR",0x00002020,"An operations error occurred.")

    # (0x00002021) A protocol error occurred.
    ERROR_DS_PROTOCOL_ERROR = WindowsError::ErrorCode.new("ERROR_DS_PROTOCOL_ERROR",0x00002021,"A protocol error occurred.")

    # (0x00002022) The time limit for this request was exceeded.
    ERROR_DS_TIMELIMIT_EXCEEDED = WindowsError::ErrorCode.new("ERROR_DS_TIMELIMIT_EXCEEDED",0x00002022,"The time limit for this request was exceeded.")

    # (0x00002023) The size limit for this request was exceeded.
    ERROR_DS_SIZELIMIT_EXCEEDED = WindowsError::ErrorCode.new("ERROR_DS_SIZELIMIT_EXCEEDED",0x00002023,"The size limit for this request was exceeded.")

    # (0x00002024) The administrative limit for this request was exceeded.
    ERROR_DS_ADMIN_LIMIT_EXCEEDED = WindowsError::ErrorCode.new("ERROR_DS_ADMIN_LIMIT_EXCEEDED",0x00002024,"The administrative limit for this request was exceeded.")

    # (0x00002025) The compare response was false.
    ERROR_DS_COMPARE_FALSE = WindowsError::ErrorCode.new("ERROR_DS_COMPARE_FALSE",0x00002025,"The compare response was false.")

    # (0x00002026) The compare response was true.
    ERROR_DS_COMPARE_TRUE = WindowsError::ErrorCode.new("ERROR_DS_COMPARE_TRUE",0x00002026,"The compare response was true.")

    # (0x00002027) The requested authentication method is not supported by the server.
    ERROR_DS_AUTH_METHOD_NOT_SUPPORTED = WindowsError::ErrorCode.new("ERROR_DS_AUTH_METHOD_NOT_SUPPORTED",0x00002027,"The requested authentication method is not supported by the server.")

    # (0x00002028) A more secure authentication method is required for this server.
    ERROR_DS_STRONG_AUTH_REQUIRED = WindowsError::ErrorCode.new("ERROR_DS_STRONG_AUTH_REQUIRED",0x00002028,"A more secure authentication method is required for this server.")

    # (0x00002029) Inappropriate authentication.
    ERROR_DS_INAPPROPRIATE_AUTH = WindowsError::ErrorCode.new("ERROR_DS_INAPPROPRIATE_AUTH",0x00002029,"Inappropriate authentication.")

    # (0x0000202A) The authentication mechanism is unknown.
    ERROR_DS_AUTH_UNKNOWN = WindowsError::ErrorCode.new("ERROR_DS_AUTH_UNKNOWN",0x0000202A,"The authentication mechanism is unknown.")

    # (0x0000202B) A referral was returned from the server.
    ERROR_DS_REFERRAL = WindowsError::ErrorCode.new("ERROR_DS_REFERRAL",0x0000202B,"A referral was returned from the server.")

    # (0x0000202C) The server does not support the requested critical extension.
    ERROR_DS_UNAVAILABLE_CRIT_EXTENSION = WindowsError::ErrorCode.new("ERROR_DS_UNAVAILABLE_CRIT_EXTENSION",0x0000202C,"The server does not support the requested critical extension.")

    # (0x0000202D) This request requires a secure connection.
    ERROR_DS_CONFIDENTIALITY_REQUIRED = WindowsError::ErrorCode.new("ERROR_DS_CONFIDENTIALITY_REQUIRED",0x0000202D,"This request requires a secure connection.")

    # (0x0000202E) Inappropriate matching.
    ERROR_DS_INAPPROPRIATE_MATCHING = WindowsError::ErrorCode.new("ERROR_DS_INAPPROPRIATE_MATCHING",0x0000202E,"Inappropriate matching.")

    # (0x0000202F) A constraint violation occurred.
    ERROR_DS_CONSTRAINT_VIOLATION = WindowsError::ErrorCode.new("ERROR_DS_CONSTRAINT_VIOLATION",0x0000202F,"A constraint violation occurred.")

    # (0x00002030) There is no such object on the server.
    ERROR_DS_NO_SUCH_OBJECT = WindowsError::ErrorCode.new("ERROR_DS_NO_SUCH_OBJECT",0x00002030,"There is no such object on the server.")

    # (0x00002031) There is an alias problem.
    ERROR_DS_ALIAS_PROBLEM = WindowsError::ErrorCode.new("ERROR_DS_ALIAS_PROBLEM",0x00002031,"There is an alias problem.")

    # (0x00002032) An invalid dn syntax has been specified.
    ERROR_DS_INVALID_DN_SYNTAX = WindowsError::ErrorCode.new("ERROR_DS_INVALID_DN_SYNTAX",0x00002032,"An invalid dn syntax has been specified.")

    # (0x00002033) The object is a leaf object.
    ERROR_DS_IS_LEAF = WindowsError::ErrorCode.new("ERROR_DS_IS_LEAF",0x00002033,"The object is a leaf object.")

    # (0x00002034) There is an alias dereferencing problem.
    ERROR_DS_ALIAS_DEREF_PROBLEM = WindowsError::ErrorCode.new("ERROR_DS_ALIAS_DEREF_PROBLEM",0x00002034,"There is an alias dereferencing problem.")

    # (0x00002035) The server is unwilling to process the request.
    ERROR_DS_UNWILLING_TO_PERFORM = WindowsError::ErrorCode.new("ERROR_DS_UNWILLING_TO_PERFORM",0x00002035,"The server is unwilling to process the request.")

    # (0x00002036) A loop has been detected.
    ERROR_DS_LOOP_DETECT = WindowsError::ErrorCode.new("ERROR_DS_LOOP_DETECT",0x00002036,"A loop has been detected.")

    # (0x00002037) There is a naming violation.
    ERROR_DS_NAMING_VIOLATION = WindowsError::ErrorCode.new("ERROR_DS_NAMING_VIOLATION",0x00002037,"There is a naming violation.")

    # (0x00002038) The result set is too large.
    ERROR_DS_OBJECT_RESULTS_TOO_LARGE = WindowsError::ErrorCode.new("ERROR_DS_OBJECT_RESULTS_TOO_LARGE",0x00002038,"The result set is too large.")

    # (0x00002039) The operation affects multiple DSAs.
    ERROR_DS_AFFECTS_MULTIPLE_DSAS = WindowsError::ErrorCode.new("ERROR_DS_AFFECTS_MULTIPLE_DSAS",0x00002039,"The operation affects multiple DSAs.")

    # (0x0000203A) The server is not operational.
    ERROR_DS_SERVER_DOWN = WindowsError::ErrorCode.new("ERROR_DS_SERVER_DOWN",0x0000203A,"The server is not operational.")

    # (0x0000203B) A local error has occurred.
    ERROR_DS_LOCAL_ERROR = WindowsError::ErrorCode.new("ERROR_DS_LOCAL_ERROR",0x0000203B,"A local error has occurred.")

    # (0x0000203C) An encoding error has occurred.
    ERROR_DS_ENCODING_ERROR = WindowsError::ErrorCode.new("ERROR_DS_ENCODING_ERROR",0x0000203C,"An encoding error has occurred.")

    # (0x0000203D) A decoding error has occurred.
    ERROR_DS_DECODING_ERROR = WindowsError::ErrorCode.new("ERROR_DS_DECODING_ERROR",0x0000203D,"A decoding error has occurred.")

    # (0x0000203E) The search filter cannot be recognized.
    ERROR_DS_FILTER_UNKNOWN = WindowsError::ErrorCode.new("ERROR_DS_FILTER_UNKNOWN",0x0000203E,"The search filter cannot be recognized.")

    # (0x0000203F) One or more parameters are illegal.
    ERROR_DS_PARAM_ERROR = WindowsError::ErrorCode.new("ERROR_DS_PARAM_ERROR",0x0000203F,"One or more parameters are illegal.")

    # (0x00002040) The specified method is not supported.
    ERROR_DS_NOT_SUPPORTED = WindowsError::ErrorCode.new("ERROR_DS_NOT_SUPPORTED",0x00002040,"The specified method is not supported.")

    # (0x00002041) No results were returned.
    ERROR_DS_NO_RESULTS_RETURNED = WindowsError::ErrorCode.new("ERROR_DS_NO_RESULTS_RETURNED",0x00002041,"No results were returned.")

    # (0x00002042) The specified control is not supported by the server.
    ERROR_DS_CONTROL_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_DS_CONTROL_NOT_FOUND",0x00002042,"The specified control is not supported by the server.")

    # (0x00002043) A referral loop was detected by the client.
    ERROR_DS_CLIENT_LOOP = WindowsError::ErrorCode.new("ERROR_DS_CLIENT_LOOP",0x00002043,"A referral loop was detected by the client.")

    # (0x00002044) The preset referral limit was exceeded.
    ERROR_DS_REFERRAL_LIMIT_EXCEEDED = WindowsError::ErrorCode.new("ERROR_DS_REFERRAL_LIMIT_EXCEEDED",0x00002044,"The preset referral limit was exceeded.")

    # (0x00002045) The search requires a SORT control.
    ERROR_DS_SORT_CONTROL_MISSING = WindowsError::ErrorCode.new("ERROR_DS_SORT_CONTROL_MISSING",0x00002045,"The search requires a SORT control.")

    # (0x00002046) The search results exceed the offset range specified.
    ERROR_DS_OFFSET_RANGE_ERROR = WindowsError::ErrorCode.new("ERROR_DS_OFFSET_RANGE_ERROR",0x00002046,"The search results exceed the offset range specified.")

    # (0x0000206D) The root object must be the head of a naming context. The root object cannot have an instantiated parent.
    ERROR_DS_ROOT_MUST_BE_NC = WindowsError::ErrorCode.new("ERROR_DS_ROOT_MUST_BE_NC",0x0000206D,"The root object must be the head of a naming context. The root object cannot have an instantiated parent.")

    # (0x0000206E) The add replica operation cannot be performed. The naming context must be writable to create the replica.
    ERROR_DS_ADD_REPLICA_INHIBITED = WindowsError::ErrorCode.new("ERROR_DS_ADD_REPLICA_INHIBITED",0x0000206E,"The add replica operation cannot be performed. The naming context must be writable to create the replica.")

    # (0x0000206F) A reference to an attribute that is not defined in the schema occurred.
    ERROR_DS_ATT_NOT_DEF_IN_SCHEMA = WindowsError::ErrorCode.new("ERROR_DS_ATT_NOT_DEF_IN_SCHEMA",0x0000206F,"A reference to an attribute that is not defined in the schema occurred.")

    # (0x00002070) The maximum size of an object has been exceeded.
    ERROR_DS_MAX_OBJ_SIZE_EXCEEDED = WindowsError::ErrorCode.new("ERROR_DS_MAX_OBJ_SIZE_EXCEEDED",0x00002070,"The maximum size of an object has been exceeded.")

    # (0x00002071) An attempt was made to add an object to the directory with a name that is already in use.
    ERROR_DS_OBJ_STRING_NAME_EXISTS = WindowsError::ErrorCode.new("ERROR_DS_OBJ_STRING_NAME_EXISTS",0x00002071,"An attempt was made to add an object to the directory with a name that is already in use.")

    # (0x00002072) An attempt was made to add an object of a class that does not have an RDN defined in the schema.
    ERROR_DS_NO_RDN_DEFINED_IN_SCHEMA = WindowsError::ErrorCode.new("ERROR_DS_NO_RDN_DEFINED_IN_SCHEMA",0x00002072,"An attempt was made to add an object of a class that does not have an RDN defined in the schema.")

    # (0x00002073) An attempt was made to add an object using an RDN that is not the RDN defined in the schema.
    ERROR_DS_RDN_DOESNT_MATCH_SCHEMA = WindowsError::ErrorCode.new("ERROR_DS_RDN_DOESNT_MATCH_SCHEMA",0x00002073,"An attempt was made to add an object using an RDN that is not the RDN defined in the schema.")

    # (0x00002074) None of the requested attributes were found on the objects.
    ERROR_DS_NO_REQUESTED_ATTS_FOUND = WindowsError::ErrorCode.new("ERROR_DS_NO_REQUESTED_ATTS_FOUND",0x00002074,"None of the requested attributes were found on the objects.")

    # (0x00002075) The user buffer is too small.
    ERROR_DS_USER_BUFFER_TO_SMALL = WindowsError::ErrorCode.new("ERROR_DS_USER_BUFFER_TO_SMALL",0x00002075,"The user buffer is too small.")

    # (0x00002076) The attribute specified in the operation is not present on the object.
    ERROR_DS_ATT_IS_NOT_ON_OBJ = WindowsError::ErrorCode.new("ERROR_DS_ATT_IS_NOT_ON_OBJ",0x00002076,"The attribute specified in the operation is not present on the object.")

    # (0x00002077) Illegal modify operation. Some aspect of the modification is not permitted.
    ERROR_DS_ILLEGAL_MOD_OPERATION = WindowsError::ErrorCode.new("ERROR_DS_ILLEGAL_MOD_OPERATION",0x00002077,"Illegal modify operation. Some aspect of the modification is not permitted.")

    # (0x00002078) The specified object is too large.
    ERROR_DS_OBJ_TOO_LARGE = WindowsError::ErrorCode.new("ERROR_DS_OBJ_TOO_LARGE",0x00002078,"The specified object is too large.")

    # (0x00002079) The specified instance type is not valid.
    ERROR_DS_BAD_INSTANCE_TYPE = WindowsError::ErrorCode.new("ERROR_DS_BAD_INSTANCE_TYPE",0x00002079,"The specified instance type is not valid.")

    # (0x0000207A) The operation must be performed at a master DSA.
    ERROR_DS_MASTERDSA_REQUIRED = WindowsError::ErrorCode.new("ERROR_DS_MASTERDSA_REQUIRED",0x0000207A,"The operation must be performed at a master DSA.")

    # (0x0000207B) The object class attribute must be specified.
    ERROR_DS_OBJECT_CLASS_REQUIRED = WindowsError::ErrorCode.new("ERROR_DS_OBJECT_CLASS_REQUIRED",0x0000207B,"The object class attribute must be specified.")

    # (0x0000207C) A required attribute is missing.
    ERROR_DS_MISSING_REQUIRED_ATT = WindowsError::ErrorCode.new("ERROR_DS_MISSING_REQUIRED_ATT",0x0000207C,"A required attribute is missing.")

    # (0x0000207D) An attempt was made to modify an object to include an attribute that is not legal for its class.
    ERROR_DS_ATT_NOT_DEF_FOR_CLASS = WindowsError::ErrorCode.new("ERROR_DS_ATT_NOT_DEF_FOR_CLASS",0x0000207D,"An attempt was made to modify an object to include an attribute that is not legal for its class.")

    # (0x0000207E) The specified attribute is already present on the object.
    ERROR_DS_ATT_ALREADY_EXISTS = WindowsError::ErrorCode.new("ERROR_DS_ATT_ALREADY_EXISTS",0x0000207E,"The specified attribute is already present on the object.")

    # (0x00002080) The specified attribute is not present, or has no values.
    ERROR_DS_CANT_ADD_ATT_VALUES = WindowsError::ErrorCode.new("ERROR_DS_CANT_ADD_ATT_VALUES",0x00002080,"The specified attribute is not present, or has no values.")

    # (0x00002081) Multiple values were specified for an attribute that can have only one value.
    ERROR_DS_SINGLE_VALUE_CONSTRAINT = WindowsError::ErrorCode.new("ERROR_DS_SINGLE_VALUE_CONSTRAINT",0x00002081,"Multiple values were specified for an attribute that can have only one value.")

    # (0x00002082) A value for the attribute was not in the acceptable range of values.
    ERROR_DS_RANGE_CONSTRAINT = WindowsError::ErrorCode.new("ERROR_DS_RANGE_CONSTRAINT",0x00002082,"A value for the attribute was not in the acceptable range of values.")

    # (0x00002083) The specified value already exists.
    ERROR_DS_ATT_VAL_ALREADY_EXISTS = WindowsError::ErrorCode.new("ERROR_DS_ATT_VAL_ALREADY_EXISTS",0x00002083,"The specified value already exists.")

    # (0x00002084) The attribute cannot be removed because it is not present on the object.
    ERROR_DS_CANT_REM_MISSING_ATT = WindowsError::ErrorCode.new("ERROR_DS_CANT_REM_MISSING_ATT",0x00002084,"The attribute cannot be removed because it is not present on the object.")

    # (0x00002085) The attribute value cannot be removed because it is not present on the object.
    ERROR_DS_CANT_REM_MISSING_ATT_VAL = WindowsError::ErrorCode.new("ERROR_DS_CANT_REM_MISSING_ATT_VAL",0x00002085,"The attribute value cannot be removed because it is not present on the object.")

    # (0x00002086) The specified root object cannot be a subreference.
    ERROR_DS_ROOT_CANT_BE_SUBREF = WindowsError::ErrorCode.new("ERROR_DS_ROOT_CANT_BE_SUBREF",0x00002086,"The specified root object cannot be a subreference.")

    # (0x00002087) Chaining is not permitted.
    ERROR_DS_NO_CHAINING = WindowsError::ErrorCode.new("ERROR_DS_NO_CHAINING",0x00002087,"Chaining is not permitted.")

    # (0x00002088) Chained evaluation is not permitted.
    ERROR_DS_NO_CHAINED_EVAL = WindowsError::ErrorCode.new("ERROR_DS_NO_CHAINED_EVAL",0x00002088,"Chained evaluation is not permitted.")

    # (0x00002089) The operation could not be performed because the object's parent is either uninstantiated or deleted.
    ERROR_DS_NO_PARENT_OBJECT = WindowsError::ErrorCode.new("ERROR_DS_NO_PARENT_OBJECT",0x00002089,"The operation could not be performed because the object's parent is either uninstantiated or deleted.")

    # (0x0000208A) Having a parent that is an alias is not permitted. Aliases are leaf objects.
    ERROR_DS_PARENT_IS_AN_ALIAS = WindowsError::ErrorCode.new("ERROR_DS_PARENT_IS_AN_ALIAS",0x0000208A,"Having a parent that is an alias is not permitted. Aliases are leaf objects.")

    # (0x0000208B) The object and parent must be of the same type, either both masters or both replicas.
    ERROR_DS_CANT_MIX_MASTER_AND_REPS = WindowsError::ErrorCode.new("ERROR_DS_CANT_MIX_MASTER_AND_REPS",0x0000208B,"The object and parent must be of the same type, either both masters or both replicas.")

    # (0x0000208C) The operation cannot be performed because child objects exist. This operation can only be performed on a leaf object.
    ERROR_DS_CHILDREN_EXIST = WindowsError::ErrorCode.new("ERROR_DS_CHILDREN_EXIST",0x0000208C,"The operation cannot be performed because child objects exist. This operation can only be performed on a leaf object.")

    # (0x0000208D) Directory object not found.
    ERROR_DS_OBJ_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_DS_OBJ_NOT_FOUND",0x0000208D,"Directory object not found.")

    # (0x0000208E) The aliased object is missing.
    ERROR_DS_ALIASED_OBJ_MISSING = WindowsError::ErrorCode.new("ERROR_DS_ALIASED_OBJ_MISSING",0x0000208E,"The aliased object is missing.")

    # (0x0000208F) The object name has bad syntax.
    ERROR_DS_BAD_NAME_SYNTAX = WindowsError::ErrorCode.new("ERROR_DS_BAD_NAME_SYNTAX",0x0000208F,"The object name has bad syntax.")

    # (0x00002090) An alias is not permitted to refer to another alias.
    ERROR_DS_ALIAS_POINTS_TO_ALIAS = WindowsError::ErrorCode.new("ERROR_DS_ALIAS_POINTS_TO_ALIAS",0x00002090,"An alias is not permitted to refer to another alias.")

    # (0x00002091) The alias cannot be dereferenced.
    ERROR_DS_CANT_DEREF_ALIAS = WindowsError::ErrorCode.new("ERROR_DS_CANT_DEREF_ALIAS",0x00002091,"The alias cannot be dereferenced.")

    # (0x00002092) The operation is out of scope.
    ERROR_DS_OUT_OF_SCOPE = WindowsError::ErrorCode.new("ERROR_DS_OUT_OF_SCOPE",0x00002092,"The operation is out of scope.")

    # (0x00002093) The operation cannot continue because the object is in the process of being removed.
    ERROR_DS_OBJECT_BEING_REMOVED = WindowsError::ErrorCode.new("ERROR_DS_OBJECT_BEING_REMOVED",0x00002093,"The operation cannot continue because the object is in the process of being removed.")

    # (0x00002094) The DSA object cannot be deleted.
    ERROR_DS_CANT_DELETE_DSA_OBJ = WindowsError::ErrorCode.new("ERROR_DS_CANT_DELETE_DSA_OBJ",0x00002094,"The DSA object cannot be deleted.")

    # (0x00002095) A directory service error has occurred.
    ERROR_DS_GENERIC_ERROR = WindowsError::ErrorCode.new("ERROR_DS_GENERIC_ERROR",0x00002095,"A directory service error has occurred.")

    # (0x00002096) The operation can only be performed on an internal master DSA object.
    ERROR_DS_DSA_MUST_BE_INT_MASTER = WindowsError::ErrorCode.new("ERROR_DS_DSA_MUST_BE_INT_MASTER",0x00002096,"The operation can only be performed on an internal master DSA object.")

    # (0x00002097) The object must be of class DSA.
    ERROR_DS_CLASS_NOT_DSA = WindowsError::ErrorCode.new("ERROR_DS_CLASS_NOT_DSA",0x00002097,"The object must be of class DSA.")

    # (0x00002098) Insufficient access rights to perform the operation.
    ERROR_DS_INSUFF_ACCESS_RIGHTS = WindowsError::ErrorCode.new("ERROR_DS_INSUFF_ACCESS_RIGHTS",0x00002098,"Insufficient access rights to perform the operation.")

    # (0x00002099) The object cannot be added because the parent is not on the list of possible superiors.
    ERROR_DS_ILLEGAL_SUPERIOR = WindowsError::ErrorCode.new("ERROR_DS_ILLEGAL_SUPERIOR",0x00002099,"The object cannot be added because the parent is not on the list of possible superiors.")

    # (0x0000209A) Access to the attribute is not permitted because the attribute is owned by the SAM.
    ERROR_DS_ATTRIBUTE_OWNED_BY_SAM = WindowsError::ErrorCode.new("ERROR_DS_ATTRIBUTE_OWNED_BY_SAM",0x0000209A,"Access to the attribute is not permitted because the attribute is owned by the SAM.")

    # (0x0000209B) The name has too many parts.
    ERROR_DS_NAME_TOO_MANY_PARTS = WindowsError::ErrorCode.new("ERROR_DS_NAME_TOO_MANY_PARTS",0x0000209B,"The name has too many parts.")

    # (0x0000209C) The name is too long.
    ERROR_DS_NAME_TOO_LONG = WindowsError::ErrorCode.new("ERROR_DS_NAME_TOO_LONG",0x0000209C,"The name is too long.")

    # (0x0000209D) The name value is too long.
    ERROR_DS_NAME_VALUE_TOO_LONG = WindowsError::ErrorCode.new("ERROR_DS_NAME_VALUE_TOO_LONG",0x0000209D,"The name value is too long.")

    # (0x0000209E) The directory service encountered an error parsing a name.
    ERROR_DS_NAME_UNPARSEABLE = WindowsError::ErrorCode.new("ERROR_DS_NAME_UNPARSEABLE",0x0000209E,"The directory service encountered an error parsing a name.")

    # (0x0000209F) The directory service cannot get the attribute type for a name.
    ERROR_DS_NAME_TYPE_UNKNOWN = WindowsError::ErrorCode.new("ERROR_DS_NAME_TYPE_UNKNOWN",0x0000209F,"The directory service cannot get the attribute type for a name.")

    # (0x000020A0) The name does not identify an object; the name identifies a phantom.
    ERROR_DS_NOT_AN_OBJECT = WindowsError::ErrorCode.new("ERROR_DS_NOT_AN_OBJECT",0x000020A0,"The name does not identify an object; the name identifies a phantom.")

    # (0x000020A1) The security descriptor is too short.
    ERROR_DS_SEC_DESC_TOO_SHORT = WindowsError::ErrorCode.new("ERROR_DS_SEC_DESC_TOO_SHORT",0x000020A1,"The security descriptor is too short.")

    # (0x000020A2) The security descriptor is invalid.
    ERROR_DS_SEC_DESC_INVALID = WindowsError::ErrorCode.new("ERROR_DS_SEC_DESC_INVALID",0x000020A2,"The security descriptor is invalid.")

    # (0x000020A3) Failed to create name for deleted object.
    ERROR_DS_NO_DELETED_NAME = WindowsError::ErrorCode.new("ERROR_DS_NO_DELETED_NAME",0x000020A3,"Failed to create name for deleted object.")

    # (0x000020A4) The parent of a new subreference must exist.
    ERROR_DS_SUBREF_MUST_HAVE_PARENT = WindowsError::ErrorCode.new("ERROR_DS_SUBREF_MUST_HAVE_PARENT",0x000020A4,"The parent of a new subreference must exist.")

    # (0x000020A5) The object must be a naming context.
    ERROR_DS_NCNAME_MUST_BE_NC = WindowsError::ErrorCode.new("ERROR_DS_NCNAME_MUST_BE_NC",0x000020A5,"The object must be a naming context.")

    # (0x000020A6) It is not permitted to add an attribute that is owned by the system.
    ERROR_DS_CANT_ADD_SYSTEM_ONLY = WindowsError::ErrorCode.new("ERROR_DS_CANT_ADD_SYSTEM_ONLY",0x000020A6,"It is not permitted to add an attribute that is owned by the system.")

    # (0x000020A7) The class of the object must be structural; you cannot instantiate an abstract class.
    ERROR_DS_CLASS_MUST_BE_CONCRETE = WindowsError::ErrorCode.new("ERROR_DS_CLASS_MUST_BE_CONCRETE",0x000020A7,"The class of the object must be structural; you cannot instantiate an abstract class.")

    # (0x000020A8) The schema object could not be found.
    ERROR_DS_INVALID_DMD = WindowsError::ErrorCode.new("ERROR_DS_INVALID_DMD",0x000020A8,"The schema object could not be found.")

    # (0x000020A9) A local object with this GUID (dead or alive) already exists.
    ERROR_DS_OBJ_GUID_EXISTS = WindowsError::ErrorCode.new("ERROR_DS_OBJ_GUID_EXISTS",0x000020A9,"A local object with this GUID (dead or alive) already exists.")

    # (0x000020AA) The operation cannot be performed on a back link.
    ERROR_DS_NOT_ON_BACKLINK = WindowsError::ErrorCode.new("ERROR_DS_NOT_ON_BACKLINK",0x000020AA,"The operation cannot be performed on a back link.")

    # (0x000020AB) The cross-reference for the specified naming context could not be found.
    ERROR_DS_NO_CROSSREF_FOR_NC = WindowsError::ErrorCode.new("ERROR_DS_NO_CROSSREF_FOR_NC",0x000020AB,"The cross-reference for the specified naming context could not be found.")

    # (0x000020AC) The operation could not be performed because the directory service is shutting down.
    ERROR_DS_SHUTTING_DOWN = WindowsError::ErrorCode.new("ERROR_DS_SHUTTING_DOWN",0x000020AC,"The operation could not be performed because the directory service is shutting down.")

    # (0x000020AD) The directory service request is invalid.
    ERROR_DS_UNKNOWN_OPERATION = WindowsError::ErrorCode.new("ERROR_DS_UNKNOWN_OPERATION",0x000020AD,"The directory service request is invalid.")

    # (0x000020AE) The role owner attribute could not be read.
    ERROR_DS_INVALID_ROLE_OWNER = WindowsError::ErrorCode.new("ERROR_DS_INVALID_ROLE_OWNER",0x000020AE,"The role owner attribute could not be read.")

    # (0x000020AF) The requested Flexible Single Master Operations (FSMO) operation failed. The current FSMO holder could not be contacted.
    ERROR_DS_COULDNT_CONTACT_FSMO = WindowsError::ErrorCode.new("ERROR_DS_COULDNT_CONTACT_FSMO",0x000020AF,"The requested Flexible Single Master Operations (FSMO) operation failed. The current FSMO holder could not be contacted.")

    # (0x000020B0) Modification of a distinguished name across a naming context is not permitted.
    ERROR_DS_CROSS_NC_DN_RENAME = WindowsError::ErrorCode.new("ERROR_DS_CROSS_NC_DN_RENAME",0x000020B0,"Modification of a distinguished name across a naming context is not permitted.")

    # (0x000020B1) The attribute cannot be modified because it is owned by the system.
    ERROR_DS_CANT_MOD_SYSTEM_ONLY = WindowsError::ErrorCode.new("ERROR_DS_CANT_MOD_SYSTEM_ONLY",0x000020B1,"The attribute cannot be modified because it is owned by the system.")

    # (0x000020B2) Only the replicator can perform this function.
    ERROR_DS_REPLICATOR_ONLY = WindowsError::ErrorCode.new("ERROR_DS_REPLICATOR_ONLY",0x000020B2,"Only the replicator can perform this function.")

    # (0x000020B3) The specified class is not defined.
    ERROR_DS_OBJ_CLASS_NOT_DEFINED = WindowsError::ErrorCode.new("ERROR_DS_OBJ_CLASS_NOT_DEFINED",0x000020B3,"The specified class is not defined.")

    # (0x000020B4) The specified class is not a subclass.
    ERROR_DS_OBJ_CLASS_NOT_SUBCLASS = WindowsError::ErrorCode.new("ERROR_DS_OBJ_CLASS_NOT_SUBCLASS",0x000020B4,"The specified class is not a subclass.")

    # (0x000020B5) The name reference is invalid.
    ERROR_DS_NAME_REFERENCE_INVALID = WindowsError::ErrorCode.new("ERROR_DS_NAME_REFERENCE_INVALID",0x000020B5,"The name reference is invalid.")

    # (0x000020B6) A cross-reference already exists.
    ERROR_DS_CROSS_REF_EXISTS = WindowsError::ErrorCode.new("ERROR_DS_CROSS_REF_EXISTS",0x000020B6,"A cross-reference already exists.")

    # (0x000020B7) It is not permitted to delete a master cross-reference.
    ERROR_DS_CANT_DEL_MASTER_CROSSREF = WindowsError::ErrorCode.new("ERROR_DS_CANT_DEL_MASTER_CROSSREF",0x000020B7,"It is not permitted to delete a master cross-reference.")

    # (0x000020B8) Subtree notifications are only supported on naming context (NC) heads.
    ERROR_DS_SUBTREE_NOTIFY_NOT_NC_HEAD = WindowsError::ErrorCode.new("ERROR_DS_SUBTREE_NOTIFY_NOT_NC_HEAD",0x000020B8,"Subtree notifications are only supported on naming context (NC) heads.")

    # (0x000020B9) Notification filter is too complex.
    ERROR_DS_NOTIFY_FILTER_TOO_COMPLEX = WindowsError::ErrorCode.new("ERROR_DS_NOTIFY_FILTER_TOO_COMPLEX",0x000020B9,"Notification filter is too complex.")

    # (0x000020BA) Schema update failed: Duplicate RDN.
    ERROR_DS_DUP_RDN = WindowsError::ErrorCode.new("ERROR_DS_DUP_RDN",0x000020BA,"Schema update failed: Duplicate RDN.")

    # (0x000020BB) Schema update failed: Duplicate OID.
    ERROR_DS_DUP_OID = WindowsError::ErrorCode.new("ERROR_DS_DUP_OID",0x000020BB,"Schema update failed: Duplicate OID.")

    # (0x000020BC) Schema update failed: Duplicate Message Application Programming Interface (MAPI) identifier.
    ERROR_DS_DUP_MAPI_ID = WindowsError::ErrorCode.new("ERROR_DS_DUP_MAPI_ID",0x000020BC,"Schema update failed: Duplicate Message Application Programming Interface (MAPI) identifier.")

    # (0x000020BD) Schema update failed: Duplicate schema ID GUID.
    ERROR_DS_DUP_SCHEMA_ID_GUID = WindowsError::ErrorCode.new("ERROR_DS_DUP_SCHEMA_ID_GUID",0x000020BD,"Schema update failed: Duplicate schema ID GUID.")

    # (0x000020BE) Schema update failed: Duplicate LDAP display name.
    ERROR_DS_DUP_LDAP_DISPLAY_NAME = WindowsError::ErrorCode.new("ERROR_DS_DUP_LDAP_DISPLAY_NAME",0x000020BE,"Schema update failed: Duplicate LDAP display name.")

    # (0x000020BF) Schema update failed: Range-Lower less than Range-Upper.
    ERROR_DS_SEMANTIC_ATT_TEST = WindowsError::ErrorCode.new("ERROR_DS_SEMANTIC_ATT_TEST",0x000020BF,"Schema update failed: Range-Lower less than Range-Upper.")

    # (0x000020C0) Schema update failed: Syntax mismatch.
    ERROR_DS_SYNTAX_MISMATCH = WindowsError::ErrorCode.new("ERROR_DS_SYNTAX_MISMATCH",0x000020C0,"Schema update failed: Syntax mismatch.")

    # (0x000020C1) Schema deletion failed: Attribute is used in the Must-Contain list.
    ERROR_DS_EXISTS_IN_MUST_HAVE = WindowsError::ErrorCode.new("ERROR_DS_EXISTS_IN_MUST_HAVE",0x000020C1,"Schema deletion failed: Attribute is used in the Must-Contain list.")

    # (0x000020C2) Schema deletion failed: Attribute is used in the May-Contain list.
    ERROR_DS_EXISTS_IN_MAY_HAVE = WindowsError::ErrorCode.new("ERROR_DS_EXISTS_IN_MAY_HAVE",0x000020C2,"Schema deletion failed: Attribute is used in the May-Contain list.")

    # (0x000020C3) Schema update failed: Attribute in May-Contain list does not exist.
    ERROR_DS_NONEXISTENT_MAY_HAVE = WindowsError::ErrorCode.new("ERROR_DS_NONEXISTENT_MAY_HAVE",0x000020C3,"Schema update failed: Attribute in May-Contain list does not exist.")

    # (0x000020C4) Schema update failed: Attribute in the Must-Contain list does not exist.
    ERROR_DS_NONEXISTENT_MUST_HAVE = WindowsError::ErrorCode.new("ERROR_DS_NONEXISTENT_MUST_HAVE",0x000020C4,"Schema update failed: Attribute in the Must-Contain list does not exist.")

    # (0x000020C5) Schema update failed: Class in the Aux Class list does not exist or is not an auxiliary class.
    ERROR_DS_AUX_CLS_TEST_FAIL = WindowsError::ErrorCode.new("ERROR_DS_AUX_CLS_TEST_FAIL",0x000020C5,"Schema update failed: Class in the Aux Class list does not exist or is not an auxiliary class.")

    # (0x000020C6) Schema update failed: Class in the Poss-Superiors list does not exist.
    ERROR_DS_NONEXISTENT_POSS_SUP = WindowsError::ErrorCode.new("ERROR_DS_NONEXISTENT_POSS_SUP",0x000020C6,"Schema update failed: Class in the Poss-Superiors list does not exist.")

    # (0x000020C7) Schema update failed: Class in the subclass of the list does not exist or does not satisfy hierarchy rules.
    ERROR_DS_SUB_CLS_TEST_FAIL = WindowsError::ErrorCode.new("ERROR_DS_SUB_CLS_TEST_FAIL",0x000020C7,"Schema update failed: Class in the subclass of the list does not exist or does not satisfy hierarchy rules.")

    # (0x000020C8) Schema update failed: Rdn-Att-Id has wrong syntax.
    ERROR_DS_BAD_RDN_ATT_ID_SYNTAX = WindowsError::ErrorCode.new("ERROR_DS_BAD_RDN_ATT_ID_SYNTAX",0x000020C8,"Schema update failed: Rdn-Att-Id has wrong syntax.")

    # (0x000020C9) Schema deletion failed: Class is used as an auxiliary class.
    ERROR_DS_EXISTS_IN_AUX_CLS = WindowsError::ErrorCode.new("ERROR_DS_EXISTS_IN_AUX_CLS",0x000020C9,"Schema deletion failed: Class is used as an auxiliary class.")

    # (0x000020CA) Schema deletion failed: Class is used as a subclass.
    ERROR_DS_EXISTS_IN_SUB_CLS = WindowsError::ErrorCode.new("ERROR_DS_EXISTS_IN_SUB_CLS",0x000020CA,"Schema deletion failed: Class is used as a subclass.")

    # (0x000020CB) Schema deletion failed: Class is used as a Poss-Superior.
    ERROR_DS_EXISTS_IN_POSS_SUP = WindowsError::ErrorCode.new("ERROR_DS_EXISTS_IN_POSS_SUP",0x000020CB,"Schema deletion failed: Class is used as a Poss-Superior.")

    # (0x000020CC) Schema update failed in recalculating validation cache.
    ERROR_DS_RECALCSCHEMA_FAILED = WindowsError::ErrorCode.new("ERROR_DS_RECALCSCHEMA_FAILED",0x000020CC,"Schema update failed in recalculating validation cache.")

    # (0x000020CD) The tree deletion is not finished. The request must be made again to continue deleting the tree.
    ERROR_DS_TREE_DELETE_NOT_FINISHED = WindowsError::ErrorCode.new("ERROR_DS_TREE_DELETE_NOT_FINISHED",0x000020CD,"The tree deletion is not finished. The request must be made again to continue deleting the tree.")

    # (0x000020CE) The requested delete operation could not be performed.
    ERROR_DS_CANT_DELETE = WindowsError::ErrorCode.new("ERROR_DS_CANT_DELETE",0x000020CE,"The requested delete operation could not be performed.")

    # (0x000020CF) Cannot read the governs class identifier for the schema record.
    ERROR_DS_ATT_SCHEMA_REQ_ID = WindowsError::ErrorCode.new("ERROR_DS_ATT_SCHEMA_REQ_ID",0x000020CF,"Cannot read the governs class identifier for the schema record.")

    # (0x000020D0) The attribute schema has bad syntax.
    ERROR_DS_BAD_ATT_SCHEMA_SYNTAX = WindowsError::ErrorCode.new("ERROR_DS_BAD_ATT_SCHEMA_SYNTAX",0x000020D0,"The attribute schema has bad syntax.")

    # (0x000020D1) The attribute could not be cached.
    ERROR_DS_CANT_CACHE_ATT = WindowsError::ErrorCode.new("ERROR_DS_CANT_CACHE_ATT",0x000020D1,"The attribute could not be cached.")

    # (0x000020D2) The class could not be cached.
    ERROR_DS_CANT_CACHE_CLASS = WindowsError::ErrorCode.new("ERROR_DS_CANT_CACHE_CLASS",0x000020D2,"The class could not be cached.")

    # (0x000020D3) The attribute could not be removed from the cache.
    ERROR_DS_CANT_REMOVE_ATT_CACHE = WindowsError::ErrorCode.new("ERROR_DS_CANT_REMOVE_ATT_CACHE",0x000020D3,"The attribute could not be removed from the cache.")

    # (0x000020D4) The class could not be removed from the cache.
    ERROR_DS_CANT_REMOVE_CLASS_CACHE = WindowsError::ErrorCode.new("ERROR_DS_CANT_REMOVE_CLASS_CACHE",0x000020D4,"The class could not be removed from the cache.")

    # (0x000020D5) The distinguished name attribute could not be read.
    ERROR_DS_CANT_RETRIEVE_DN = WindowsError::ErrorCode.new("ERROR_DS_CANT_RETRIEVE_DN",0x000020D5,"The distinguished name attribute could not be read.")

    # (0x000020D6) No superior reference has been configured for the directory service. The directory service is, therefore, unable to issue referrals to objects outside this forest.
    ERROR_DS_MISSING_SUPREF = WindowsError::ErrorCode.new("ERROR_DS_MISSING_SUPREF",0x000020D6,"No superior reference has been configured for the directory service. The directory service is, therefore, unable to issue referrals to objects outside this forest.")

    # (0x000020D7) The instance type attribute could not be retrieved.
    ERROR_DS_CANT_RETRIEVE_INSTANCE = WindowsError::ErrorCode.new("ERROR_DS_CANT_RETRIEVE_INSTANCE",0x000020D7,"The instance type attribute could not be retrieved.")

    # (0x000020D8) An internal error has occurred.
    ERROR_DS_CODE_INCONSISTENCY = WindowsError::ErrorCode.new("ERROR_DS_CODE_INCONSISTENCY",0x000020D8,"An internal error has occurred.")

    # (0x000020D9) A database error has occurred.
    ERROR_DS_DATABASE_ERROR = WindowsError::ErrorCode.new("ERROR_DS_DATABASE_ERROR",0x000020D9,"A database error has occurred.")

    # (0x000020DA) The governsID attribute is missing.
    ERROR_DS_GOVERNSID_MISSING = WindowsError::ErrorCode.new("ERROR_DS_GOVERNSID_MISSING",0x000020DA,"The governsID attribute is missing.")

    # (0x000020DB) An expected attribute is missing.
    ERROR_DS_MISSING_EXPECTED_ATT = WindowsError::ErrorCode.new("ERROR_DS_MISSING_EXPECTED_ATT",0x000020DB,"An expected attribute is missing.")

    # (0x000020DC) The specified naming context is missing a cross-reference.
    ERROR_DS_NCNAME_MISSING_CR_REF = WindowsError::ErrorCode.new("ERROR_DS_NCNAME_MISSING_CR_REF",0x000020DC,"The specified naming context is missing a cross-reference.")

    # (0x000020DD) A security checking error has occurred.
    ERROR_DS_SECURITY_CHECKING_ERROR = WindowsError::ErrorCode.new("ERROR_DS_SECURITY_CHECKING_ERROR",0x000020DD,"A security checking error has occurred.")

    # (0x000020DE) The schema is not loaded.
    ERROR_DS_SCHEMA_NOT_LOADED = WindowsError::ErrorCode.new("ERROR_DS_SCHEMA_NOT_LOADED",0x000020DE,"The schema is not loaded.")

    # (0x000020DF) Schema allocation failed. Check if the machine is running low on memory.
    ERROR_DS_SCHEMA_ALLOC_FAILED = WindowsError::ErrorCode.new("ERROR_DS_SCHEMA_ALLOC_FAILED",0x000020DF,"Schema allocation failed. Check if the machine is running low on memory.")

    # (0x000020E0) Failed to obtain the required syntax for the attribute schema.
    ERROR_DS_ATT_SCHEMA_REQ_SYNTAX = WindowsError::ErrorCode.new("ERROR_DS_ATT_SCHEMA_REQ_SYNTAX",0x000020E0,"Failed to obtain the required syntax for the attribute schema.")

    # (0x000020E1) The GC verification failed. The GC is not available or does not support the operation. Some part of the directory is currently not available.
    ERROR_DS_GCVERIFY_ERROR = WindowsError::ErrorCode.new("ERROR_DS_GCVERIFY_ERROR",0x000020E1,"The GC verification failed. The GC is not available or does not support the operation. Some part of the directory is currently not available.")

    # (0x000020E2) The replication operation failed because of a schema mismatch between the servers involved.
    ERROR_DS_DRA_SCHEMA_MISMATCH = WindowsError::ErrorCode.new("ERROR_DS_DRA_SCHEMA_MISMATCH",0x000020E2,"The replication operation failed because of a schema mismatch between the servers involved.")

    # (0x000020E3) The DSA object could not be found.
    ERROR_DS_CANT_FIND_DSA_OBJ = WindowsError::ErrorCode.new("ERROR_DS_CANT_FIND_DSA_OBJ",0x000020E3,"The DSA object could not be found.")

    # (0x000020E4) The naming context could not be found.
    ERROR_DS_CANT_FIND_EXPECTED_NC = WindowsError::ErrorCode.new("ERROR_DS_CANT_FIND_EXPECTED_NC",0x000020E4,"The naming context could not be found.")

    # (0x000020E5) The naming context could not be found in the cache.
    ERROR_DS_CANT_FIND_NC_IN_CACHE = WindowsError::ErrorCode.new("ERROR_DS_CANT_FIND_NC_IN_CACHE",0x000020E5,"The naming context could not be found in the cache.")

    # (0x000020E6) The child object could not be retrieved.
    ERROR_DS_CANT_RETRIEVE_CHILD = WindowsError::ErrorCode.new("ERROR_DS_CANT_RETRIEVE_CHILD",0x000020E6,"The child object could not be retrieved.")

    # (0x000020E7) The modification was not permitted for security reasons.
    ERROR_DS_SECURITY_ILLEGAL_MODIFY = WindowsError::ErrorCode.new("ERROR_DS_SECURITY_ILLEGAL_MODIFY",0x000020E7,"The modification was not permitted for security reasons.")

    # (0x000020E8) The operation cannot replace the hidden record.
    ERROR_DS_CANT_REPLACE_HIDDEN_REC = WindowsError::ErrorCode.new("ERROR_DS_CANT_REPLACE_HIDDEN_REC",0x000020E8,"The operation cannot replace the hidden record.")

    # (0x000020E9) The hierarchy file is invalid.
    ERROR_DS_BAD_HIERARCHY_FILE = WindowsError::ErrorCode.new("ERROR_DS_BAD_HIERARCHY_FILE",0x000020E9,"The hierarchy file is invalid.")

    # (0x000020EA) The attempt to build the hierarchy table failed.
    ERROR_DS_BUILD_HIERARCHY_TABLE_FAILED = WindowsError::ErrorCode.new("ERROR_DS_BUILD_HIERARCHY_TABLE_FAILED",0x000020EA,"The attempt to build the hierarchy table failed.")

    # (0x000020EB) The directory configuration parameter is missing from the registry.
    ERROR_DS_CONFIG_PARAM_MISSING = WindowsError::ErrorCode.new("ERROR_DS_CONFIG_PARAM_MISSING",0x000020EB,"The directory configuration parameter is missing from the registry.")

    # (0x000020EC) The attempt to count the address book indices failed.
    ERROR_DS_COUNTING_AB_INDICES_FAILED = WindowsError::ErrorCode.new("ERROR_DS_COUNTING_AB_INDICES_FAILED",0x000020EC,"The attempt to count the address book indices failed.")

    # (0x000020ED) The allocation of the hierarchy table failed.
    ERROR_DS_HIERARCHY_TABLE_MALLOC_FAILED = WindowsError::ErrorCode.new("ERROR_DS_HIERARCHY_TABLE_MALLOC_FAILED",0x000020ED,"The allocation of the hierarchy table failed.")

    # (0x000020EE) The directory service encountered an internal failure.
    ERROR_DS_INTERNAL_FAILURE = WindowsError::ErrorCode.new("ERROR_DS_INTERNAL_FAILURE",0x000020EE,"The directory service encountered an internal failure.")

    # (0x000020EF) The directory service encountered an unknown failure.
    ERROR_DS_UNKNOWN_ERROR = WindowsError::ErrorCode.new("ERROR_DS_UNKNOWN_ERROR",0x000020EF,"The directory service encountered an unknown failure.")

    # (0x000020F0) A root object requires a class of "top".
    ERROR_DS_ROOT_REQUIRES_CLASS_TOP = WindowsError::ErrorCode.new("ERROR_DS_ROOT_REQUIRES_CLASS_TOP",0x000020F0,"A root object requires a class of \"top\".")

    # (0x000020F1) This directory server is shutting down, and cannot take ownership of new floating single-master operation roles.
    ERROR_DS_REFUSING_FSMO_ROLES = WindowsError::ErrorCode.new("ERROR_DS_REFUSING_FSMO_ROLES",0x000020F1,"This directory server is shutting down, and cannot take ownership of new floating single-master operation roles.")

    # (0x000020F2) The directory service is missing mandatory configuration information and is unable to determine the ownership of floating single-master operation roles.
    ERROR_DS_MISSING_FSMO_SETTINGS = WindowsError::ErrorCode.new("ERROR_DS_MISSING_FSMO_SETTINGS",0x000020F2,"The directory service is missing mandatory configuration information and is unable to determine the ownership of floating single-master operation roles.")

    # (0x000020F3) The directory service was unable to transfer ownership of one or more floating single-master operation roles to other servers.
    ERROR_DS_UNABLE_TO_SURRENDER_ROLES = WindowsError::ErrorCode.new("ERROR_DS_UNABLE_TO_SURRENDER_ROLES",0x000020F3,"The directory service was unable to transfer ownership of one or more floating single-master operation roles to other servers.")

    # (0x000020F4) The replication operation failed.
    ERROR_DS_DRA_GENERIC = WindowsError::ErrorCode.new("ERROR_DS_DRA_GENERIC",0x000020F4,"The replication operation failed.")

    # (0x000020F5) An invalid parameter was specified for this replication operation.
    ERROR_DS_DRA_INVALID_PARAMETER = WindowsError::ErrorCode.new("ERROR_DS_DRA_INVALID_PARAMETER",0x000020F5,"An invalid parameter was specified for this replication operation.")

    # (0x000020F6) The directory service is too busy to complete the replication operation at this time.
    ERROR_DS_DRA_BUSY = WindowsError::ErrorCode.new("ERROR_DS_DRA_BUSY",0x000020F6,"The directory service is too busy to complete the replication operation at this time.")

    # (0x000020F7) The DN specified for this replication operation is invalid.
    ERROR_DS_DRA_BAD_DN = WindowsError::ErrorCode.new("ERROR_DS_DRA_BAD_DN",0x000020F7,"The DN specified for this replication operation is invalid.")

    # (0x000020F8) The naming context specified for this replication operation is invalid.
    ERROR_DS_DRA_BAD_NC = WindowsError::ErrorCode.new("ERROR_DS_DRA_BAD_NC",0x000020F8,"The naming context specified for this replication operation is invalid.")

    # (0x000020F9) The DN specified for this replication operation already exists.
    ERROR_DS_DRA_DN_EXISTS = WindowsError::ErrorCode.new("ERROR_DS_DRA_DN_EXISTS",0x000020F9,"The DN specified for this replication operation already exists.")

    # (0x000020FA) The replication system encountered an internal error.
    ERROR_DS_DRA_INTERNAL_ERROR = WindowsError::ErrorCode.new("ERROR_DS_DRA_INTERNAL_ERROR",0x000020FA,"The replication system encountered an internal error.")

    # (0x000020FB) The replication operation encountered a database inconsistency.
    ERROR_DS_DRA_INCONSISTENT_DIT = WindowsError::ErrorCode.new("ERROR_DS_DRA_INCONSISTENT_DIT",0x000020FB,"The replication operation encountered a database inconsistency.")

    # (0x000020FC) The server specified for this replication operation could not be contacted.
    ERROR_DS_DRA_CONNECTION_FAILED = WindowsError::ErrorCode.new("ERROR_DS_DRA_CONNECTION_FAILED",0x000020FC,"The server specified for this replication operation could not be contacted.")

    # (0x000020FD) The replication operation encountered an object with an invalid instance type.
    ERROR_DS_DRA_BAD_INSTANCE_TYPE = WindowsError::ErrorCode.new("ERROR_DS_DRA_BAD_INSTANCE_TYPE",0x000020FD,"The replication operation encountered an object with an invalid instance type.")

    # (0x000020FE) The replication operation failed to allocate memory.
    ERROR_DS_DRA_OUT_OF_MEM = WindowsError::ErrorCode.new("ERROR_DS_DRA_OUT_OF_MEM",0x000020FE,"The replication operation failed to allocate memory.")

    # (0x000020FF) The replication operation encountered an error with the mail system.
    ERROR_DS_DRA_MAIL_PROBLEM = WindowsError::ErrorCode.new("ERROR_DS_DRA_MAIL_PROBLEM",0x000020FF,"The replication operation encountered an error with the mail system.")

    # (0x00002100) The replication reference information for the target server already exists.
    ERROR_DS_DRA_REF_ALREADY_EXISTS = WindowsError::ErrorCode.new("ERROR_DS_DRA_REF_ALREADY_EXISTS",0x00002100,"The replication reference information for the target server already exists.")

    # (0x00002101) The replication reference information for the target server does not exist.
    ERROR_DS_DRA_REF_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_DS_DRA_REF_NOT_FOUND",0x00002101,"The replication reference information for the target server does not exist.")

    # (0x00002102) The naming context cannot be removed because it is replicated to another server.
    ERROR_DS_DRA_OBJ_IS_REP_SOURCE = WindowsError::ErrorCode.new("ERROR_DS_DRA_OBJ_IS_REP_SOURCE",0x00002102,"The naming context cannot be removed because it is replicated to another server.")

    # (0x00002103) The replication operation encountered a database error.
    ERROR_DS_DRA_DB_ERROR = WindowsError::ErrorCode.new("ERROR_DS_DRA_DB_ERROR",0x00002103,"The replication operation encountered a database error.")

    # (0x00002104) The naming context is in the process of being removed or is not replicated from the specified server.
    ERROR_DS_DRA_NO_REPLICA = WindowsError::ErrorCode.new("ERROR_DS_DRA_NO_REPLICA",0x00002104,"The naming context is in the process of being removed or is not replicated from the specified server.")

    # (0x00002105) Replication access was denied.
    ERROR_DS_DRA_ACCESS_DENIED = WindowsError::ErrorCode.new("ERROR_DS_DRA_ACCESS_DENIED",0x00002105,"Replication access was denied.")

    # (0x00002106) The requested operation is not supported by this version of the directory service.
    ERROR_DS_DRA_NOT_SUPPORTED = WindowsError::ErrorCode.new("ERROR_DS_DRA_NOT_SUPPORTED",0x00002106,"The requested operation is not supported by this version of the directory service.")

    # (0x00002107) The replication RPC was canceled.
    ERROR_DS_DRA_RPC_CANCELLED = WindowsError::ErrorCode.new("ERROR_DS_DRA_RPC_CANCELLED",0x00002107,"The replication RPC was canceled.")

    # (0x00002108) The source server is currently rejecting replication requests.
    ERROR_DS_DRA_SOURCE_DISABLED = WindowsError::ErrorCode.new("ERROR_DS_DRA_SOURCE_DISABLED",0x00002108,"The source server is currently rejecting replication requests.")

    # (0x00002109) The destination server is currently rejecting replication requests.
    ERROR_DS_DRA_SINK_DISABLED = WindowsError::ErrorCode.new("ERROR_DS_DRA_SINK_DISABLED",0x00002109,"The destination server is currently rejecting replication requests.")

    # (0x0000210A) The replication operation failed due to a collision of object names.
    ERROR_DS_DRA_NAME_COLLISION = WindowsError::ErrorCode.new("ERROR_DS_DRA_NAME_COLLISION",0x0000210A,"The replication operation failed due to a collision of object names.")

    # (0x0000210B) The replication source has been reinstalled.
    ERROR_DS_DRA_SOURCE_REINSTALLED = WindowsError::ErrorCode.new("ERROR_DS_DRA_SOURCE_REINSTALLED",0x0000210B,"The replication source has been reinstalled.")

    # (0x0000210C) The replication operation failed because a required parent object is missing.
    ERROR_DS_DRA_MISSING_PARENT = WindowsError::ErrorCode.new("ERROR_DS_DRA_MISSING_PARENT",0x0000210C,"The replication operation failed because a required parent object is missing.")

    # (0x0000210D) The replication operation was preempted.
    ERROR_DS_DRA_PREEMPTED = WindowsError::ErrorCode.new("ERROR_DS_DRA_PREEMPTED",0x0000210D,"The replication operation was preempted.")

    # (0x0000210E) The replication synchronization attempt was abandoned because of a lack of updates.
    ERROR_DS_DRA_ABANDON_SYNC = WindowsError::ErrorCode.new("ERROR_DS_DRA_ABANDON_SYNC",0x0000210E,"The replication synchronization attempt was abandoned because of a lack of updates.")

    # (0x0000210F) The replication operation was terminated because the system is shutting down.
    ERROR_DS_DRA_SHUTDOWN = WindowsError::ErrorCode.new("ERROR_DS_DRA_SHUTDOWN",0x0000210F,"The replication operation was terminated because the system is shutting down.")

    # (0x00002110) A synchronization attempt failed because the destination DC is currently waiting to synchronize new partial attributes from the source. This condition is normal if a recent schema change modified the partial attribute set. The destination partial attribute set is not a subset of the source partial attribute set.
    ERROR_DS_DRA_INCOMPATIBLE_PARTIAL_SET = WindowsError::ErrorCode.new("ERROR_DS_DRA_INCOMPATIBLE_PARTIAL_SET",0x00002110,"A synchronization attempt failed because the destination DC is currently waiting to synchronize new partial attributes from the source. This condition is normal if a recent schema change modified the partial attribute set. The destination partial attribute set is not a subset of the source partial attribute set.")

    # (0x00002111) The replication synchronization attempt failed because a master replica attempted to sync from a partial replica.
    ERROR_DS_DRA_SOURCE_IS_PARTIAL_REPLICA = WindowsError::ErrorCode.new("ERROR_DS_DRA_SOURCE_IS_PARTIAL_REPLICA",0x00002111,"The replication synchronization attempt failed because a master replica attempted to sync from a partial replica.")

    # (0x00002112) The server specified for this replication operation was contacted, but that server was unable to contact an additional server needed to complete the operation.
    ERROR_DS_DRA_EXTN_CONNECTION_FAILED = WindowsError::ErrorCode.new("ERROR_DS_DRA_EXTN_CONNECTION_FAILED",0x00002112,"The server specified for this replication operation was contacted, but that server was unable to contact an additional server needed to complete the operation.")

    # (0x00002113) The version of the directory service schema of the source forest is not compatible with the version of the directory service on this computer.
    ERROR_DS_INSTALL_SCHEMA_MISMATCH = WindowsError::ErrorCode.new("ERROR_DS_INSTALL_SCHEMA_MISMATCH",0x00002113,"The version of the directory service schema of the source forest is not compatible with the version of the directory service on this computer.")

    # (0x00002114) Schema update failed: An attribute with the same link identifier already exists.
    ERROR_DS_DUP_LINK_ID = WindowsError::ErrorCode.new("ERROR_DS_DUP_LINK_ID",0x00002114,"Schema update failed: An attribute with the same link identifier already exists.")

    # (0x00002115) Name translation: Generic processing error.
    ERROR_DS_NAME_ERROR_RESOLVING = WindowsError::ErrorCode.new("ERROR_DS_NAME_ERROR_RESOLVING",0x00002115,"Name translation: Generic processing error.")

    # (0x00002116) Name translation: Could not find the name or insufficient right to see name.
    ERROR_DS_NAME_ERROR_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_DS_NAME_ERROR_NOT_FOUND",0x00002116,"Name translation: Could not find the name or insufficient right to see name.")

    # (0x00002117) Name translation: Input name mapped to more than one output name.
    ERROR_DS_NAME_ERROR_NOT_UNIQUE = WindowsError::ErrorCode.new("ERROR_DS_NAME_ERROR_NOT_UNIQUE",0x00002117,"Name translation: Input name mapped to more than one output name.")

    # (0x00002118) Name translation: The input name was found but not the associated output format.
    ERROR_DS_NAME_ERROR_NO_MAPPING = WindowsError::ErrorCode.new("ERROR_DS_NAME_ERROR_NO_MAPPING",0x00002118,"Name translation: The input name was found but not the associated output format.")

    # (0x00002119) Name translation: Unable to resolve completely, only the domain was found.
    ERROR_DS_NAME_ERROR_DOMAIN_ONLY = WindowsError::ErrorCode.new("ERROR_DS_NAME_ERROR_DOMAIN_ONLY",0x00002119,"Name translation: Unable to resolve completely, only the domain was found.")

    # (0x0000211A) Name translation: Unable to perform purely syntactical mapping at the client without going out to the wire.
    ERROR_DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING = WindowsError::ErrorCode.new("ERROR_DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING",0x0000211A,"Name translation: Unable to perform purely syntactical mapping at the client without going out to the wire.")

    # (0x0000211B) Modification of a constructed attribute is not allowed.
    ERROR_DS_CONSTRUCTED_ATT_MOD = WindowsError::ErrorCode.new("ERROR_DS_CONSTRUCTED_ATT_MOD",0x0000211B,"Modification of a constructed attribute is not allowed.")

    # (0x0000211C) The OM-Object-Class specified is incorrect for an attribute with the specified syntax.
    ERROR_DS_WRONG_OM_OBJ_CLASS = WindowsError::ErrorCode.new("ERROR_DS_WRONG_OM_OBJ_CLASS",0x0000211C,"The OM-Object-Class specified is incorrect for an attribute with the specified syntax.")

    # (0x0000211D) The replication request has been posted; waiting for a reply.
    ERROR_DS_DRA_REPL_PENDING = WindowsError::ErrorCode.new("ERROR_DS_DRA_REPL_PENDING",0x0000211D,"The replication request has been posted; waiting for a reply.")

    # (0x0000211E) The requested operation requires a directory service, and none was available.
    ERROR_DS_DS_REQUIRED = WindowsError::ErrorCode.new("ERROR_DS_DS_REQUIRED",0x0000211E,"The requested operation requires a directory service, and none was available.")

    # (0x0000211F) The LDAP display name of the class or attribute contains non-ASCII characters.
    ERROR_DS_INVALID_LDAP_DISPLAY_NAME = WindowsError::ErrorCode.new("ERROR_DS_INVALID_LDAP_DISPLAY_NAME",0x0000211F,"The LDAP display name of the class or attribute contains non-ASCII characters.")

    # (0x00002120) The requested search operation is only supported for base searches.
    ERROR_DS_NON_BASE_SEARCH = WindowsError::ErrorCode.new("ERROR_DS_NON_BASE_SEARCH",0x00002120,"The requested search operation is only supported for base searches.")

    # (0x00002121) The search failed to retrieve attributes from the database.
    ERROR_DS_CANT_RETRIEVE_ATTS = WindowsError::ErrorCode.new("ERROR_DS_CANT_RETRIEVE_ATTS",0x00002121,"The search failed to retrieve attributes from the database.")

    # (0x00002122) The schema update operation tried to add a backward link attribute that has no corresponding forward link.
    ERROR_DS_BACKLINK_WITHOUT_LINK = WindowsError::ErrorCode.new("ERROR_DS_BACKLINK_WITHOUT_LINK",0x00002122,"The schema update operation tried to add a backward link attribute that has no corresponding forward link.")

    # (0x00002123) The source and destination of a cross-domain move do not agree on the object's epoch number. Either the source or the destination does not have the latest version of the object.
    ERROR_DS_EPOCH_MISMATCH = WindowsError::ErrorCode.new("ERROR_DS_EPOCH_MISMATCH",0x00002123,"The source and destination of a cross-domain move do not agree on the object's epoch number. Either the source or the destination does not have the latest version of the object.")

    # (0x00002124) The source and destination of a cross-domain move do not agree on the object's current name. Either the source or the destination does not have the latest version of the object.
    ERROR_DS_SRC_NAME_MISMATCH = WindowsError::ErrorCode.new("ERROR_DS_SRC_NAME_MISMATCH",0x00002124,"The source and destination of a cross-domain move do not agree on the object's current name. Either the source or the destination does not have the latest version of the object.")

    # (0x00002125) The source and destination for the cross-domain move operation are identical. The caller should use a local move operation instead of a cross-domain move operation.
    ERROR_DS_SRC_AND_DST_NC_IDENTICAL = WindowsError::ErrorCode.new("ERROR_DS_SRC_AND_DST_NC_IDENTICAL",0x00002125,"The source and destination for the cross-domain move operation are identical. The caller should use a local move operation instead of a cross-domain move operation.")

    # (0x00002126) The source and destination for a cross-domain move do not agree on the naming contexts in the forest. Either the source or the destination does not have the latest version of the Partitions container.
    ERROR_DS_DST_NC_MISMATCH = WindowsError::ErrorCode.new("ERROR_DS_DST_NC_MISMATCH",0x00002126,"The source and destination for a cross-domain move do not agree on the naming contexts in the forest. Either the source or the destination does not have the latest version of the Partitions container.")

    # (0x00002127) The destination of a cross-domain move is not authoritative for the destination naming context.
    ERROR_DS_NOT_AUTHORITIVE_FOR_DST_NC = WindowsError::ErrorCode.new("ERROR_DS_NOT_AUTHORITIVE_FOR_DST_NC",0x00002127,"The destination of a cross-domain move is not authoritative for the destination naming context.")

    # (0x00002128) The source and destination of a cross-domain move do not agree on the identity of the source object. Either the source or the destination does not have the latest version of the source object.
    ERROR_DS_SRC_GUID_MISMATCH = WindowsError::ErrorCode.new("ERROR_DS_SRC_GUID_MISMATCH",0x00002128,"The source and destination of a cross-domain move do not agree on the identity of the source object. Either the source or the destination does not have the latest version of the source object.")

    # (0x00002129) The object being moved across domains is already known to be deleted by the destination server. The source server does not have the latest version of the source object.
    ERROR_DS_CANT_MOVE_DELETED_OBJECT = WindowsError::ErrorCode.new("ERROR_DS_CANT_MOVE_DELETED_OBJECT",0x00002129,"The object being moved across domains is already known to be deleted by the destination server. The source server does not have the latest version of the source object.")

    # (0x0000212A) Another operation that requires exclusive access to the PDC FSMO is already in progress.
    ERROR_DS_PDC_OPERATION_IN_PROGRESS = WindowsError::ErrorCode.new("ERROR_DS_PDC_OPERATION_IN_PROGRESS",0x0000212A,"Another operation that requires exclusive access to the PDC FSMO is already in progress.")

    # (0x0000212B) A cross-domain move operation failed because two versions of the moved object exist—one each in the source and destination domains. The destination object needs to be removed to restore the system to a consistent state.
    ERROR_DS_CROSS_DOMAIN_CLEANUP_REQD = WindowsError::ErrorCode.new("ERROR_DS_CROSS_DOMAIN_CLEANUP_REQD",0x0000212B,"A cross-domain move operation failed because two versions of the moved object exist\u{2014}one each in the source and destination domains. The destination object needs to be removed to restore the system to a consistent state.")

    # (0x0000212C) This object may not be moved across domain boundaries either because cross-domain moves for this class are not allowed, or the object has some special characteristics, for example, a trust account or a restricted relative identifier (RID), that prevent its move.
    ERROR_DS_ILLEGAL_XDOM_MOVE_OPERATION = WindowsError::ErrorCode.new("ERROR_DS_ILLEGAL_XDOM_MOVE_OPERATION",0x0000212C,"This object may not be moved across domain boundaries either because cross-domain moves for this class are not allowed, or the object has some special characteristics, for example, a trust account or a restricted relative identifier (RID), that prevent its move.")

    # (0x0000212D) Cannot move objects with memberships across domain boundaries because, once moved, this violates the membership conditions of the account group. Remove the object from any account group memberships and retry.
    ERROR_DS_CANT_WITH_ACCT_GROUP_MEMBERSHPS = WindowsError::ErrorCode.new("ERROR_DS_CANT_WITH_ACCT_GROUP_MEMBERSHPS",0x0000212D,"Cannot move objects with memberships across domain boundaries because, once moved, this violates the membership conditions of the account group. Remove the object from any account group memberships and retry.")

    # (0x0000212E) A naming context head must be the immediate child of another naming context head, not of an interior node.
    ERROR_DS_NC_MUST_HAVE_NC_PARENT = WindowsError::ErrorCode.new("ERROR_DS_NC_MUST_HAVE_NC_PARENT",0x0000212E,"A naming context head must be the immediate child of another naming context head, not of an interior node.")

    # (0x0000212F) The directory cannot validate the proposed naming context name because it does not hold a replica of the naming context above the proposed naming context. Ensure that the domain naming master role is held by a server that is configured as a GC server, and that the server is up-to-date with its replication partners. (Applies only to Windows 2000 domain naming masters.)
    ERROR_DS_CR_IMPOSSIBLE_TO_VALIDATE = WindowsError::ErrorCode.new("ERROR_DS_CR_IMPOSSIBLE_TO_VALIDATE",0x0000212F,"The directory cannot validate the proposed naming context name because it does not hold a replica of the naming context above the proposed naming context. Ensure that the domain naming master role is held by a server that is configured as a GC server, and that the server is up-to-date with its replication partners. (Applies only to Windows 2000 domain naming masters.)")

    # (0x00002130) Destination domain must be in native mode.
    ERROR_DS_DST_DOMAIN_NOT_NATIVE = WindowsError::ErrorCode.new("ERROR_DS_DST_DOMAIN_NOT_NATIVE",0x00002130,"Destination domain must be in native mode.")

    # (0x00002131) The operation cannot be performed because the server does not have an infrastructure container in the domain of interest.
    ERROR_DS_MISSING_INFRASTRUCTURE_CONTAINER = WindowsError::ErrorCode.new("ERROR_DS_MISSING_INFRASTRUCTURE_CONTAINER",0x00002131,"The operation cannot be performed because the server does not have an infrastructure container in the domain of interest.")

    # (0x00002132) Cross-domain moves of nonempty account groups is not allowed.
    ERROR_DS_CANT_MOVE_ACCOUNT_GROUP = WindowsError::ErrorCode.new("ERROR_DS_CANT_MOVE_ACCOUNT_GROUP",0x00002132,"Cross-domain moves of nonempty account groups is not allowed.")

    # (0x00002133) Cross-domain moves of nonempty resource groups is not allowed.
    ERROR_DS_CANT_MOVE_RESOURCE_GROUP = WindowsError::ErrorCode.new("ERROR_DS_CANT_MOVE_RESOURCE_GROUP",0x00002133,"Cross-domain moves of nonempty resource groups is not allowed.")

    # (0x00002134) The search flags for the attribute are invalid. The ambiguous name resolution (ANR) bit is valid only on attributes of Unicode or Teletex strings.
    ERROR_DS_INVALID_SEARCH_FLAG = WindowsError::ErrorCode.new("ERROR_DS_INVALID_SEARCH_FLAG",0x00002134,"The search flags for the attribute are invalid. The ambiguous name resolution (ANR) bit is valid only on attributes of Unicode or Teletex strings.")

    # (0x00002135) Tree deletions starting at an object that has an NC head as a descendant are not allowed.
    ERROR_DS_NO_TREE_DELETE_ABOVE_NC = WindowsError::ErrorCode.new("ERROR_DS_NO_TREE_DELETE_ABOVE_NC",0x00002135,"Tree deletions starting at an object that has an NC head as a descendant are not allowed.")

    # (0x00002136) The directory service failed to lock a tree in preparation for a tree deletion because the tree was in use.
    ERROR_DS_COULDNT_LOCK_TREE_FOR_DELETE = WindowsError::ErrorCode.new("ERROR_DS_COULDNT_LOCK_TREE_FOR_DELETE",0x00002136,"The directory service failed to lock a tree in preparation for a tree deletion because the tree was in use.")

    # (0x00002137) The directory service failed to identify the list of objects to delete while attempting a tree deletion.
    ERROR_DS_COULDNT_IDENTIFY_OBJECTS_FOR_TREE_DELETE = WindowsError::ErrorCode.new("ERROR_DS_COULDNT_IDENTIFY_OBJECTS_FOR_TREE_DELETE",0x00002137,"The directory service failed to identify the list of objects to delete while attempting a tree deletion.")

    # (0x00002138) SAM initialization failed because of the following error: %1. Error Status: 0x%2. Click OK to shut down the system and reboot into Directory Services Restore Mode. Check the event log for detailed information.
    ERROR_DS_SAM_INIT_FAILURE = WindowsError::ErrorCode.new("ERROR_DS_SAM_INIT_FAILURE",0x00002138,"SAM initialization failed because of the following error: %1. Error Status: 0x%2. Click OK to shut down the system and reboot into Directory Services Restore Mode. Check the event log for detailed information.")

    # (0x00002139) Only an administrator can modify the membership list of an administrative group.
    ERROR_DS_SENSITIVE_GROUP_VIOLATION = WindowsError::ErrorCode.new("ERROR_DS_SENSITIVE_GROUP_VIOLATION",0x00002139,"Only an administrator can modify the membership list of an administrative group.")

    # (0x0000213A) Cannot change the primary group ID of a domain controller account.
    ERROR_DS_CANT_MOD_PRIMARYGROUPID = WindowsError::ErrorCode.new("ERROR_DS_CANT_MOD_PRIMARYGROUPID",0x0000213A,"Cannot change the primary group ID of a domain controller account.")

    # (0x0000213B) An attempt was made to modify the base schema.
    ERROR_DS_ILLEGAL_BASE_SCHEMA_MOD = WindowsError::ErrorCode.new("ERROR_DS_ILLEGAL_BASE_SCHEMA_MOD",0x0000213B,"An attempt was made to modify the base schema.")

    # (0x0000213C) Adding a new mandatory attribute to an existing class, deleting a mandatory attribute from an existing class, or adding an optional attribute to the special class Top that is not a backlink attribute (directly or through inheritance, for example, by adding or deleting an auxiliary class) is not allowed.
    ERROR_DS_NONSAFE_SCHEMA_CHANGE = WindowsError::ErrorCode.new("ERROR_DS_NONSAFE_SCHEMA_CHANGE",0x0000213C,"Adding a new mandatory attribute to an existing class, deleting a mandatory attribute from an existing class, or adding an optional attribute to the special class Top that is not a backlink attribute (directly or through inheritance, for example, by adding or deleting an auxiliary class) is not allowed.")

    # (0x0000213D) Schema update is not allowed on this DC because the DC is not the schema FSMO role owner.
    ERROR_DS_SCHEMA_UPDATE_DISALLOWED = WindowsError::ErrorCode.new("ERROR_DS_SCHEMA_UPDATE_DISALLOWED",0x0000213D,"Schema update is not allowed on this DC because the DC is not the schema FSMO role owner.")

    # (0x0000213E) An object of this class cannot be created under the schema container. You can only create Attribute-Schema and Class-Schema objects under the schema container.
    ERROR_DS_CANT_CREATE_UNDER_SCHEMA = WindowsError::ErrorCode.new("ERROR_DS_CANT_CREATE_UNDER_SCHEMA",0x0000213E,"An object of this class cannot be created under the schema container. You can only create Attribute-Schema and Class-Schema objects under the schema container.")

    # (0x0000213F) The replica or child install failed to get the objectVersion attribute on the schema container on the source DC. Either the attribute is missing on the schema container or the credentials supplied do not have permission to read it.
    ERROR_DS_INSTALL_NO_SRC_SCH_VERSION = WindowsError::ErrorCode.new("ERROR_DS_INSTALL_NO_SRC_SCH_VERSION",0x0000213F,"The replica or child install failed to get the objectVersion attribute on the schema container on the source DC. Either the attribute is missing on the schema container or the credentials supplied do not have permission to read it.")

    # (0x00002140) The replica or child install failed to read the objectVersion attribute in the SCHEMA section of the file schema.ini in the System32 directory.
    ERROR_DS_INSTALL_NO_SCH_VERSION_IN_INIFILE = WindowsError::ErrorCode.new("ERROR_DS_INSTALL_NO_SCH_VERSION_IN_INIFILE",0x00002140,"The replica or child install failed to read the objectVersion attribute in the SCHEMA section of the file schema.ini in the System32 directory.")

    # (0x00002141) The specified group type is invalid.
    ERROR_DS_INVALID_GROUP_TYPE = WindowsError::ErrorCode.new("ERROR_DS_INVALID_GROUP_TYPE",0x00002141,"The specified group type is invalid.")

    # (0x00002142) You cannot nest global groups in a mixed domain if the group is security-enabled.
    ERROR_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN = WindowsError::ErrorCode.new("ERROR_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN",0x00002142,"You cannot nest global groups in a mixed domain if the group is security-enabled.")

    # (0x00002143) You cannot nest local groups in a mixed domain if the group is security-enabled.
    ERROR_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN = WindowsError::ErrorCode.new("ERROR_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN",0x00002143,"You cannot nest local groups in a mixed domain if the group is security-enabled.")

    # (0x00002144) A global group cannot have a local group as a member.
    ERROR_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER = WindowsError::ErrorCode.new("ERROR_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER",0x00002144,"A global group cannot have a local group as a member.")

    # (0x00002145) A global group cannot have a universal group as a member.
    ERROR_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER = WindowsError::ErrorCode.new("ERROR_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER",0x00002145,"A global group cannot have a universal group as a member.")

    # (0x00002146) A universal group cannot have a local group as a member.
    ERROR_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER = WindowsError::ErrorCode.new("ERROR_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER",0x00002146,"A universal group cannot have a local group as a member.")

    # (0x00002147) A global group cannot have a cross-domain member.
    ERROR_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER = WindowsError::ErrorCode.new("ERROR_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER",0x00002147,"A global group cannot have a cross-domain member.")

    # (0x00002148) A local group cannot have another cross domain local group as a member.
    ERROR_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER = WindowsError::ErrorCode.new("ERROR_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER",0x00002148,"A local group cannot have another cross domain local group as a member.")

    # (0x00002149) A group with primary members cannot change to a security-disabled group.
    ERROR_DS_HAVE_PRIMARY_MEMBERS = WindowsError::ErrorCode.new("ERROR_DS_HAVE_PRIMARY_MEMBERS",0x00002149,"A group with primary members cannot change to a security-disabled group.")

    # (0x0000214A) The schema cache load failed to convert the string default security descriptor (SD) on a class-schema object.
    ERROR_DS_STRING_SD_CONVERSION_FAILED = WindowsError::ErrorCode.new("ERROR_DS_STRING_SD_CONVERSION_FAILED",0x0000214A,"The schema cache load failed to convert the string default security descriptor (SD) on a class-schema object.")

    # (0x0000214B) Only DSAs configured to be GC servers should be allowed to hold the domain naming master FSMO role. (Applies only to Windows 2000 servers.)
    ERROR_DS_NAMING_MASTER_GC = WindowsError::ErrorCode.new("ERROR_DS_NAMING_MASTER_GC",0x0000214B,"Only DSAs configured to be GC servers should be allowed to hold the domain naming master FSMO role. (Applies only to Windows 2000 servers.)")

    # (0x0000214C) The DSA operation is unable to proceed because of a DNS lookup failure.
    ERROR_DS_DNS_LOOKUP_FAILURE = WindowsError::ErrorCode.new("ERROR_DS_DNS_LOOKUP_FAILURE",0x0000214C,"The DSA operation is unable to proceed because of a DNS lookup failure.")

    # (0x0000214D) While processing a change to the DNS host name for an object, the SPN values could not be kept in sync.
    ERROR_DS_COULDNT_UPDATE_SPNS = WindowsError::ErrorCode.new("ERROR_DS_COULDNT_UPDATE_SPNS",0x0000214D,"While processing a change to the DNS host name for an object, the SPN values could not be kept in sync.")

    # (0x0000214E) The Security Descriptor attribute could not be read.
    ERROR_DS_CANT_RETRIEVE_SD = WindowsError::ErrorCode.new("ERROR_DS_CANT_RETRIEVE_SD",0x0000214E,"The Security Descriptor attribute could not be read.")

    # (0x0000214F) The object requested was not found, but an object with that key was found.
    ERROR_DS_KEY_NOT_UNIQUE = WindowsError::ErrorCode.new("ERROR_DS_KEY_NOT_UNIQUE",0x0000214F,"The object requested was not found, but an object with that key was found.")

    # (0x00002150) The syntax of the linked attribute being added is incorrect. Forward links can only have syntax 2.5.5.1, 2.5.5.7, and 2.5.5.14, and backlinks can only have syntax 2.5.5.1.
    ERROR_DS_WRONG_LINKED_ATT_SYNTAX = WindowsError::ErrorCode.new("ERROR_DS_WRONG_LINKED_ATT_SYNTAX",0x00002150,"The syntax of the linked attribute being added is incorrect. Forward links can only have syntax 2.5.5.1, 2.5.5.7, and 2.5.5.14, and backlinks can only have syntax 2.5.5.1.")

    # (0x00002151) SAM needs to get the boot password.
    ERROR_DS_SAM_NEED_BOOTKEY_PASSWORD = WindowsError::ErrorCode.new("ERROR_DS_SAM_NEED_BOOTKEY_PASSWORD",0x00002151,"SAM needs to get the boot password.")

    # (0x00002152) SAM needs to get the boot key from the floppy disk.
    ERROR_DS_SAM_NEED_BOOTKEY_FLOPPY = WindowsError::ErrorCode.new("ERROR_DS_SAM_NEED_BOOTKEY_FLOPPY",0x00002152,"SAM needs to get the boot key from the floppy disk.")

    # (0x00002153) Directory Service cannot start.
    ERROR_DS_CANT_START = WindowsError::ErrorCode.new("ERROR_DS_CANT_START",0x00002153,"Directory Service cannot start.")

    # (0x00002154) Directory Services could not start.
    ERROR_DS_INIT_FAILURE = WindowsError::ErrorCode.new("ERROR_DS_INIT_FAILURE",0x00002154,"Directory Services could not start.")

    # (0x00002155) The connection between client and server requires packet privacy or better.
    ERROR_DS_NO_PKT_PRIVACY_ON_CONNECTION = WindowsError::ErrorCode.new("ERROR_DS_NO_PKT_PRIVACY_ON_CONNECTION",0x00002155,"The connection between client and server requires packet privacy or better.")

    # (0x00002156) The source domain may not be in the same forest as the destination.
    ERROR_DS_SOURCE_DOMAIN_IN_FOREST = WindowsError::ErrorCode.new("ERROR_DS_SOURCE_DOMAIN_IN_FOREST",0x00002156,"The source domain may not be in the same forest as the destination.")

    # (0x00002157) The destination domain must be in the forest.
    ERROR_DS_DESTINATION_DOMAIN_NOT_IN_FOREST = WindowsError::ErrorCode.new("ERROR_DS_DESTINATION_DOMAIN_NOT_IN_FOREST",0x00002157,"The destination domain must be in the forest.")

    # (0x00002158) The operation requires that destination domain auditing be enabled.
    ERROR_DS_DESTINATION_AUDITING_NOT_ENABLED = WindowsError::ErrorCode.new("ERROR_DS_DESTINATION_AUDITING_NOT_ENABLED",0x00002158,"The operation requires that destination domain auditing be enabled.")

    # (0x00002159) The operation could not locate a DC for the source domain.
    ERROR_DS_CANT_FIND_DC_FOR_SRC_DOMAIN = WindowsError::ErrorCode.new("ERROR_DS_CANT_FIND_DC_FOR_SRC_DOMAIN",0x00002159,"The operation could not locate a DC for the source domain.")

    # (0x0000215A) The source object must be a group or user.
    ERROR_DS_SRC_OBJ_NOT_GROUP_OR_USER = WindowsError::ErrorCode.new("ERROR_DS_SRC_OBJ_NOT_GROUP_OR_USER",0x0000215A,"The source object must be a group or user.")

    # (0x0000215B) The source object's SID already exists in the destination forest.
    ERROR_DS_SRC_SID_EXISTS_IN_FOREST = WindowsError::ErrorCode.new("ERROR_DS_SRC_SID_EXISTS_IN_FOREST",0x0000215B,"The source object's SID already exists in the destination forest.")

    # (0x0000215C) The source and destination object must be of the same type.
    ERROR_DS_SRC_AND_DST_OBJECT_CLASS_MISMATCH = WindowsError::ErrorCode.new("ERROR_DS_SRC_AND_DST_OBJECT_CLASS_MISMATCH",0x0000215C,"The source and destination object must be of the same type.")

    # (0x0000215D) SAM initialization failed because of the following error: %1. Error Status: 0x%2. Click OK to shut down the system and reboot into Safe Mode. Check the event log for detailed information.
    ERROR_SAM_INIT_FAILURE = WindowsError::ErrorCode.new("ERROR_SAM_INIT_FAILURE",0x0000215D,"SAM initialization failed because of the following error: %1. Error Status: 0x%2. Click OK to shut down the system and reboot into Safe Mode. Check the event log for detailed information.")

    # (0x0000215E) Schema information could not be included in the replication request.
    ERROR_DS_DRA_SCHEMA_INFO_SHIP = WindowsError::ErrorCode.new("ERROR_DS_DRA_SCHEMA_INFO_SHIP",0x0000215E,"Schema information could not be included in the replication request.")

    # (0x0000215F) The replication operation could not be completed due to a schema incompatibility.
    ERROR_DS_DRA_SCHEMA_CONFLICT = WindowsError::ErrorCode.new("ERROR_DS_DRA_SCHEMA_CONFLICT",0x0000215F,"The replication operation could not be completed due to a schema incompatibility.")

    # (0x00002160) The replication operation could not be completed due to a previous schema incompatibility.
    ERROR_DS_DRA_EARLIER_SCHEMA_CONFLICT = WindowsError::ErrorCode.new("ERROR_DS_DRA_EARLIER_SCHEMA_CONFLICT",0x00002160,"The replication operation could not be completed due to a previous schema incompatibility.")

    # (0x00002161) The replication update could not be applied because either the source or the destination has not yet received information regarding a recent cross-domain move operation.
    ERROR_DS_DRA_OBJ_NC_MISMATCH = WindowsError::ErrorCode.new("ERROR_DS_DRA_OBJ_NC_MISMATCH",0x00002161,"The replication update could not be applied because either the source or the destination has not yet received information regarding a recent cross-domain move operation.")

    # (0x00002162) The requested domain could not be deleted because there exist domain controllers that still host this domain.
    ERROR_DS_NC_STILL_HAS_DSAS = WindowsError::ErrorCode.new("ERROR_DS_NC_STILL_HAS_DSAS",0x00002162,"The requested domain could not be deleted because there exist domain controllers that still host this domain.")

    # (0x00002163) The requested operation can be performed only on a GC server.
    ERROR_DS_GC_REQUIRED = WindowsError::ErrorCode.new("ERROR_DS_GC_REQUIRED",0x00002163,"The requested operation can be performed only on a GC server.")

    # (0x00002164) A local group can only be a member of other local groups in the same domain.
    ERROR_DS_LOCAL_MEMBER_OF_LOCAL_ONLY = WindowsError::ErrorCode.new("ERROR_DS_LOCAL_MEMBER_OF_LOCAL_ONLY",0x00002164,"A local group can only be a member of other local groups in the same domain.")

    # (0x00002165) Foreign security principals cannot be members of universal groups.
    ERROR_DS_NO_FPO_IN_UNIVERSAL_GROUPS = WindowsError::ErrorCode.new("ERROR_DS_NO_FPO_IN_UNIVERSAL_GROUPS",0x00002165,"Foreign security principals cannot be members of universal groups.")

    # (0x00002166) The attribute is not allowed to be replicated to the GC because of security reasons.
    ERROR_DS_CANT_ADD_TO_GC = WindowsError::ErrorCode.new("ERROR_DS_CANT_ADD_TO_GC",0x00002166,"The attribute is not allowed to be replicated to the GC because of security reasons.")

    # (0x00002167) The checkpoint with the PDC could not be taken because too many modifications are currently being processed.
    ERROR_DS_NO_CHECKPOINT_WITH_PDC = WindowsError::ErrorCode.new("ERROR_DS_NO_CHECKPOINT_WITH_PDC",0x00002167,"The checkpoint with the PDC could not be taken because too many modifications are currently being processed.")

    # (0x00002168) The operation requires that source domain auditing be enabled.
    ERROR_DS_SOURCE_AUDITING_NOT_ENABLED = WindowsError::ErrorCode.new("ERROR_DS_SOURCE_AUDITING_NOT_ENABLED",0x00002168,"The operation requires that source domain auditing be enabled.")

    # (0x00002169) Security principal objects can only be created inside domain naming contexts.
    ERROR_DS_CANT_CREATE_IN_NONDOMAIN_NC = WindowsError::ErrorCode.new("ERROR_DS_CANT_CREATE_IN_NONDOMAIN_NC",0x00002169,"Security principal objects can only be created inside domain naming contexts.")

    # (0x0000216A) An SPN could not be constructed because the provided host name is not in the necessary format.
    ERROR_DS_INVALID_NAME_FOR_SPN = WindowsError::ErrorCode.new("ERROR_DS_INVALID_NAME_FOR_SPN",0x0000216A,"An SPN could not be constructed because the provided host name is not in the necessary format.")

    # (0x0000216B) A filter was passed that uses constructed attributes.
    ERROR_DS_FILTER_USES_CONTRUCTED_ATTRS = WindowsError::ErrorCode.new("ERROR_DS_FILTER_USES_CONTRUCTED_ATTRS",0x0000216B,"A filter was passed that uses constructed attributes.")

    # (0x0000216C) The unicodePwd attribute value must be enclosed in quotation marks.
    ERROR_DS_UNICODEPWD_NOT_IN_QUOTES = WindowsError::ErrorCode.new("ERROR_DS_UNICODEPWD_NOT_IN_QUOTES",0x0000216C,"The unicodePwd attribute value must be enclosed in quotation marks.")

    # (0x0000216D) Your computer could not be joined to the domain. You have exceeded the maximum number of computer accounts you are allowed to create in this domain. Contact your system administrator to have this limit reset or increased.
    ERROR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED = WindowsError::ErrorCode.new("ERROR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED",0x0000216D,"Your computer could not be joined to the domain. You have exceeded the maximum number of computer accounts you are allowed to create in this domain. Contact your system administrator to have this limit reset or increased.")

    # (0x0000216E) For security reasons, the operation must be run on the destination DC.
    ERROR_DS_MUST_BE_RUN_ON_DST_DC = WindowsError::ErrorCode.new("ERROR_DS_MUST_BE_RUN_ON_DST_DC",0x0000216E,"For security reasons, the operation must be run on the destination DC.")

    # (0x0000216F) For security reasons, the source DC must be NT4SP4 or greater.
    ERROR_DS_SRC_DC_MUST_BE_SP4_OR_GREATER = WindowsError::ErrorCode.new("ERROR_DS_SRC_DC_MUST_BE_SP4_OR_GREATER",0x0000216F,"For security reasons, the source DC must be NT4SP4 or greater.")

    # (0x00002170) Critical directory service system objects cannot be deleted during tree deletion operations. The tree deletion may have been partially performed.
    ERROR_DS_CANT_TREE_DELETE_CRITICAL_OBJ = WindowsError::ErrorCode.new("ERROR_DS_CANT_TREE_DELETE_CRITICAL_OBJ",0x00002170,"Critical directory service system objects cannot be deleted during tree deletion operations. The tree deletion may have been partially performed.")

    # (0x00002171) Directory Services could not start because of the following error: %1. Error Status: 0x%2. Click OK to shut down the system. You can use the Recovery Console to further diagnose the system.
    ERROR_DS_INIT_FAILURE_CONSOLE = WindowsError::ErrorCode.new("ERROR_DS_INIT_FAILURE_CONSOLE",0x00002171,"Directory Services could not start because of the following error: %1. Error Status: 0x%2. Click OK to shut down the system. You can use the Recovery Console to further diagnose the system.")

    # (0x00002172) SAM initialization failed because of the following error: %1. Error Status: 0x%2. Click OK to shut down the system. You can use the Recovery Console to further diagnose the system.
    ERROR_DS_SAM_INIT_FAILURE_CONSOLE = WindowsError::ErrorCode.new("ERROR_DS_SAM_INIT_FAILURE_CONSOLE",0x00002172,"SAM initialization failed because of the following error: %1. Error Status: 0x%2. Click OK to shut down the system. You can use the Recovery Console to further diagnose the system.")

    # (0x00002173) The version of the operating system installed is incompatible with the current forest functional level. You must upgrade to a new version of the operating system before this server can become a domain controller in this forest.
    ERROR_DS_FOREST_VERSION_TOO_HIGH = WindowsError::ErrorCode.new("ERROR_DS_FOREST_VERSION_TOO_HIGH",0x00002173,"The version of the operating system installed is incompatible with the current forest functional level. You must upgrade to a new version of the operating system before this server can become a domain controller in this forest.")

    # (0x00002174) The version of the operating system installed is incompatible with the current domain functional level. You must upgrade to a new version of the operating system before this server can become a domain controller in this domain.
    ERROR_DS_DOMAIN_VERSION_TOO_HIGH = WindowsError::ErrorCode.new("ERROR_DS_DOMAIN_VERSION_TOO_HIGH",0x00002174,"The version of the operating system installed is incompatible with the current domain functional level. You must upgrade to a new version of the operating system before this server can become a domain controller in this domain.")

    # (0x00002175) The version of the operating system installed on this server no longer supports the current forest functional level. You must raise the forest functional level before this server can become a domain controller in this forest.
    ERROR_DS_FOREST_VERSION_TOO_LOW = WindowsError::ErrorCode.new("ERROR_DS_FOREST_VERSION_TOO_LOW",0x00002175,"The version of the operating system installed on this server no longer supports the current forest functional level. You must raise the forest functional level before this server can become a domain controller in this forest.")

    # (0x00002176) The version of the operating system installed on this server no longer supports the current domain functional level. You must raise the domain functional level before this server can become a domain controller in this domain.
    ERROR_DS_DOMAIN_VERSION_TOO_LOW = WindowsError::ErrorCode.new("ERROR_DS_DOMAIN_VERSION_TOO_LOW",0x00002176,"The version of the operating system installed on this server no longer supports the current domain functional level. You must raise the domain functional level before this server can become a domain controller in this domain.")

    # (0x00002177) The version of the operating system installed on this server is incompatible with the functional level of the domain or forest.
    ERROR_DS_INCOMPATIBLE_VERSION = WindowsError::ErrorCode.new("ERROR_DS_INCOMPATIBLE_VERSION",0x00002177,"The version of the operating system installed on this server is incompatible with the functional level of the domain or forest.")

    # (0x00002178) The functional level of the domain (or forest) cannot be raised to the requested value because one or more domain controllers in the domain (or forest) are at a lower, incompatible functional level.
    ERROR_DS_LOW_DSA_VERSION = WindowsError::ErrorCode.new("ERROR_DS_LOW_DSA_VERSION",0x00002178,"The functional level of the domain (or forest) cannot be raised to the requested value because one or more domain controllers in the domain (or forest) are at a lower, incompatible functional level.")

    # (0x00002179) The forest functional level cannot be raised to the requested value because one or more domains are still in mixed-domain mode. All domains in the forest must be in native mode for you to raise the forest functional level.
    ERROR_DS_NO_BEHAVIOR_VERSION_IN_MIXEDDOMAIN = WindowsError::ErrorCode.new("ERROR_DS_NO_BEHAVIOR_VERSION_IN_MIXEDDOMAIN",0x00002179,"The forest functional level cannot be raised to the requested value because one or more domains are still in mixed-domain mode. All domains in the forest must be in native mode for you to raise the forest functional level.")

    # (0x0000217A) The sort order requested is not supported.
    ERROR_DS_NOT_SUPPORTED_SORT_ORDER = WindowsError::ErrorCode.new("ERROR_DS_NOT_SUPPORTED_SORT_ORDER",0x0000217A,"The sort order requested is not supported.")

    # (0x0000217B) The requested name already exists as a unique identifier.
    ERROR_DS_NAME_NOT_UNIQUE = WindowsError::ErrorCode.new("ERROR_DS_NAME_NOT_UNIQUE",0x0000217B,"The requested name already exists as a unique identifier.")

    # (0x0000217C) The machine account was created before Windows NT 4.0. The account needs to be re-created.
    ERROR_DS_MACHINE_ACCOUNT_CREATED_PRENT4 = WindowsError::ErrorCode.new("ERROR_DS_MACHINE_ACCOUNT_CREATED_PRENT4",0x0000217C,"The machine account was created before Windows NT 4.0. The account needs to be re-created.")

    # (0x0000217D) The database is out of version store.
    ERROR_DS_OUT_OF_VERSION_STORE = WindowsError::ErrorCode.new("ERROR_DS_OUT_OF_VERSION_STORE",0x0000217D,"The database is out of version store.")

    # (0x0000217E) Unable to continue operation because multiple conflicting controls were used.
    ERROR_DS_INCOMPATIBLE_CONTROLS_USED = WindowsError::ErrorCode.new("ERROR_DS_INCOMPATIBLE_CONTROLS_USED",0x0000217E,"Unable to continue operation because multiple conflicting controls were used.")

    # (0x0000217F) Unable to find a valid security descriptor reference domain for this partition.
    ERROR_DS_NO_REF_DOMAIN = WindowsError::ErrorCode.new("ERROR_DS_NO_REF_DOMAIN",0x0000217F,"Unable to find a valid security descriptor reference domain for this partition.")

    # (0x00002180) Schema update failed: The link identifier is reserved.
    ERROR_DS_RESERVED_LINK_ID = WindowsError::ErrorCode.new("ERROR_DS_RESERVED_LINK_ID",0x00002180,"Schema update failed: The link identifier is reserved.")

    # (0x00002181) Schema update failed: There are no link identifiers available.
    ERROR_DS_LINK_ID_NOT_AVAILABLE = WindowsError::ErrorCode.new("ERROR_DS_LINK_ID_NOT_AVAILABLE",0x00002181,"Schema update failed: There are no link identifiers available.")

    # (0x00002182) An account group cannot have a universal group as a member.
    ERROR_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER = WindowsError::ErrorCode.new("ERROR_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER",0x00002182,"An account group cannot have a universal group as a member.")

    # (0x00002183) Rename or move operations on naming context heads or read-only objects are not allowed.
    ERROR_DS_MODIFYDN_DISALLOWED_BY_INSTANCE_TYPE = WindowsError::ErrorCode.new("ERROR_DS_MODIFYDN_DISALLOWED_BY_INSTANCE_TYPE",0x00002183,"Rename or move operations on naming context heads or read-only objects are not allowed.")

    # (0x00002184) Move operations on objects in the schema naming context are not allowed.
    ERROR_DS_NO_OBJECT_MOVE_IN_SCHEMA_NC = WindowsError::ErrorCode.new("ERROR_DS_NO_OBJECT_MOVE_IN_SCHEMA_NC",0x00002184,"Move operations on objects in the schema naming context are not allowed.")

    # (0x00002185) A system flag has been set on the object that does not allow the object to be moved or renamed.
    ERROR_DS_MODIFYDN_DISALLOWED_BY_FLAG = WindowsError::ErrorCode.new("ERROR_DS_MODIFYDN_DISALLOWED_BY_FLAG",0x00002185,"A system flag has been set on the object that does not allow the object to be moved or renamed.")

    # (0x00002186) This object is not allowed to change its grandparent container. Moves are not forbidden on this object, but are restricted to sibling containers.
    ERROR_DS_MODIFYDN_WRONG_GRANDPARENT = WindowsError::ErrorCode.new("ERROR_DS_MODIFYDN_WRONG_GRANDPARENT",0x00002186,"This object is not allowed to change its grandparent container. Moves are not forbidden on this object, but are restricted to sibling containers.")

    # (0x00002187) Unable to resolve completely; a referral to another forest was generated.
    ERROR_DS_NAME_ERROR_TRUST_REFERRAL = WindowsError::ErrorCode.new("ERROR_DS_NAME_ERROR_TRUST_REFERRAL",0x00002187,"Unable to resolve completely; a referral to another forest was generated.")

    # (0x00002188) The requested action is not supported on a standard server.
    ERROR_NOT_SUPPORTED_ON_STANDARD_SERVER = WindowsError::ErrorCode.new("ERROR_NOT_SUPPORTED_ON_STANDARD_SERVER",0x00002188,"The requested action is not supported on a standard server.")

    # (0x00002189) Could not access a partition of the directory service located on a remote server. Make sure at least one server is running for the partition in question.
    ERROR_DS_CANT_ACCESS_REMOTE_PART_OF_AD = WindowsError::ErrorCode.new("ERROR_DS_CANT_ACCESS_REMOTE_PART_OF_AD",0x00002189,"Could not access a partition of the directory service located on a remote server. Make sure at least one server is running for the partition in question.")

    # (0x0000218A) The directory cannot validate the proposed naming context (or partition) name because it does not hold a replica, nor can it contact a replica of the naming context above the proposed naming context. Ensure that the parent naming context is properly registered in the DNS, and at least one replica of this naming context is reachable by the domain naming master.
    ERROR_DS_CR_IMPOSSIBLE_TO_VALIDATE_V2 = WindowsError::ErrorCode.new("ERROR_DS_CR_IMPOSSIBLE_TO_VALIDATE_V2",0x0000218A,"The directory cannot validate the proposed naming context (or partition) name because it does not hold a replica, nor can it contact a replica of the naming context above the proposed naming context. Ensure that the parent naming context is properly registered in the DNS, and at least one replica of this naming context is reachable by the domain naming master.")

    # (0x0000218B) The thread limit for this request was exceeded.
    ERROR_DS_THREAD_LIMIT_EXCEEDED = WindowsError::ErrorCode.new("ERROR_DS_THREAD_LIMIT_EXCEEDED",0x0000218B,"The thread limit for this request was exceeded.")

    # (0x0000218C) The GC server is not in the closest site.
    ERROR_DS_NOT_CLOSEST = WindowsError::ErrorCode.new("ERROR_DS_NOT_CLOSEST",0x0000218C,"The GC server is not in the closest site.")

    # (0x0000218D) The directory service cannot derive an SPN with which to mutually authenticate the target server because the corresponding server object in the local DS database has no serverReference attribute.
    ERROR_DS_CANT_DERIVE_SPN_WITHOUT_SERVER_REF = WindowsError::ErrorCode.new("ERROR_DS_CANT_DERIVE_SPN_WITHOUT_SERVER_REF",0x0000218D,"The directory service cannot derive an SPN with which to mutually authenticate the target server because the corresponding server object in the local DS database has no serverReference attribute.")

    # (0x0000218E) The directory service failed to enter single-user mode.
    ERROR_DS_SINGLE_USER_MODE_FAILED = WindowsError::ErrorCode.new("ERROR_DS_SINGLE_USER_MODE_FAILED",0x0000218E,"The directory service failed to enter single-user mode.")

    # (0x0000218F) The directory service cannot parse the script because of a syntax error.
    ERROR_DS_NTDSCRIPT_SYNTAX_ERROR = WindowsError::ErrorCode.new("ERROR_DS_NTDSCRIPT_SYNTAX_ERROR",0x0000218F,"The directory service cannot parse the script because of a syntax error.")

    # (0x00002190) The directory service cannot process the script because of an error.
    ERROR_DS_NTDSCRIPT_PROCESS_ERROR = WindowsError::ErrorCode.new("ERROR_DS_NTDSCRIPT_PROCESS_ERROR",0x00002190,"The directory service cannot process the script because of an error.")

    # (0x00002191) The directory service cannot perform the requested operation because the servers involved are of different replication epochs (which is usually related to a domain rename that is in progress).
    ERROR_DS_DIFFERENT_REPL_EPOCHS = WindowsError::ErrorCode.new("ERROR_DS_DIFFERENT_REPL_EPOCHS",0x00002191,"The directory service cannot perform the requested operation because the servers involved are of different replication epochs (which is usually related to a domain rename that is in progress).")

    # (0x00002192) The directory service binding must be renegotiated due to a change in the server extensions information.
    ERROR_DS_DRS_EXTENSIONS_CHANGED = WindowsError::ErrorCode.new("ERROR_DS_DRS_EXTENSIONS_CHANGED",0x00002192,"The directory service binding must be renegotiated due to a change in the server extensions information.")

    # (0x00002193) The operation is not allowed on a disabled cross-reference.
    ERROR_DS_REPLICA_SET_CHANGE_NOT_ALLOWED_ON_DISABLED_CR = WindowsError::ErrorCode.new("ERROR_DS_REPLICA_SET_CHANGE_NOT_ALLOWED_ON_DISABLED_CR",0x00002193,"The operation is not allowed on a disabled cross-reference.")

    # (0x00002194) Schema update failed: No values for msDS-IntId are available.
    ERROR_DS_NO_MSDS_INTID = WindowsError::ErrorCode.new("ERROR_DS_NO_MSDS_INTID",0x00002194,"Schema update failed: No values for msDS-IntId are available.")

    # (0x00002195) Schema update failed: Duplicate msDS-IntId. Retry the operation.
    ERROR_DS_DUP_MSDS_INTID = WindowsError::ErrorCode.new("ERROR_DS_DUP_MSDS_INTID",0x00002195,"Schema update failed: Duplicate msDS-IntId. Retry the operation.")

    # (0x00002196) Schema deletion failed: Attribute is used in rDNAttID.
    ERROR_DS_EXISTS_IN_RDNATTID = WindowsError::ErrorCode.new("ERROR_DS_EXISTS_IN_RDNATTID",0x00002196,"Schema deletion failed: Attribute is used in rDNAttID.")

    # (0x00002197) The directory service failed to authorize the request.
    ERROR_DS_AUTHORIZATION_FAILED = WindowsError::ErrorCode.new("ERROR_DS_AUTHORIZATION_FAILED",0x00002197,"The directory service failed to authorize the request.")

    # (0x00002198) The directory service cannot process the script because it is invalid.
    ERROR_DS_INVALID_SCRIPT = WindowsError::ErrorCode.new("ERROR_DS_INVALID_SCRIPT",0x00002198,"The directory service cannot process the script because it is invalid.")

    # (0x00002199) The remote create cross-reference operation failed on the domain naming master FSMO. The operation's error is in the extended data.
    ERROR_DS_REMOTE_CROSSREF_OP_FAILED = WindowsError::ErrorCode.new("ERROR_DS_REMOTE_CROSSREF_OP_FAILED",0x00002199,"The remote create cross-reference operation failed on the domain naming master FSMO. The operation's error is in the extended data.")

    # (0x0000219A) A cross-reference is in use locally with the same name.
    ERROR_DS_CROSS_REF_BUSY = WindowsError::ErrorCode.new("ERROR_DS_CROSS_REF_BUSY",0x0000219A,"A cross-reference is in use locally with the same name.")

    # (0x0000219B) The directory service cannot derive an SPN with which to mutually authenticate the target server because the server's domain has been deleted from the forest.
    ERROR_DS_CANT_DERIVE_SPN_FOR_DELETED_DOMAIN = WindowsError::ErrorCode.new("ERROR_DS_CANT_DERIVE_SPN_FOR_DELETED_DOMAIN",0x0000219B,"The directory service cannot derive an SPN with which to mutually authenticate the target server because the server's domain has been deleted from the forest.")

    # (0x0000219C) Writable NCs prevent this DC from demoting.
    ERROR_DS_CANT_DEMOTE_WITH_WRITEABLE_NC = WindowsError::ErrorCode.new("ERROR_DS_CANT_DEMOTE_WITH_WRITEABLE_NC",0x0000219C,"Writable NCs prevent this DC from demoting.")

    # (0x0000219D) The requested object has a nonunique identifier and cannot be retrieved.
    ERROR_DS_DUPLICATE_ID_FOUND = WindowsError::ErrorCode.new("ERROR_DS_DUPLICATE_ID_FOUND",0x0000219D,"The requested object has a nonunique identifier and cannot be retrieved.")

    # (0x0000219E) Insufficient attributes were given to create an object. This object may not exist because it may have been deleted and the garbage already collected.
    ERROR_DS_INSUFFICIENT_ATTR_TO_CREATE_OBJECT = WindowsError::ErrorCode.new("ERROR_DS_INSUFFICIENT_ATTR_TO_CREATE_OBJECT",0x0000219E,"Insufficient attributes were given to create an object. This object may not exist because it may have been deleted and the garbage already collected.")

    # (0x0000219F) The group cannot be converted due to attribute restrictions on the requested group type.
    ERROR_DS_GROUP_CONVERSION_ERROR = WindowsError::ErrorCode.new("ERROR_DS_GROUP_CONVERSION_ERROR",0x0000219F,"The group cannot be converted due to attribute restrictions on the requested group type.")

    # (0x000021A0) Cross-domain moves of nonempty basic application groups is not allowed.
    ERROR_DS_CANT_MOVE_APP_BASIC_GROUP = WindowsError::ErrorCode.new("ERROR_DS_CANT_MOVE_APP_BASIC_GROUP",0x000021A0,"Cross-domain moves of nonempty basic application groups is not allowed.")

    # (0x000021A1) Cross-domain moves of nonempty query-based application groups is not allowed.
    ERROR_DS_CANT_MOVE_APP_QUERY_GROUP = WindowsError::ErrorCode.new("ERROR_DS_CANT_MOVE_APP_QUERY_GROUP",0x000021A1,"Cross-domain moves of nonempty query-based application groups is not allowed.")

    # (0x000021A2) The FSMO role ownership could not be verified because its directory partition did not replicate successfully with at least one replication partner.
    ERROR_DS_ROLE_NOT_VERIFIED = WindowsError::ErrorCode.new("ERROR_DS_ROLE_NOT_VERIFIED",0x000021A2,"The FSMO role ownership could not be verified because its directory partition did not replicate successfully with at least one replication partner.")

    # (0x000021A3) The target container for a redirection of a well-known object container cannot already be a special container.
    ERROR_DS_WKO_CONTAINER_CANNOT_BE_SPECIAL = WindowsError::ErrorCode.new("ERROR_DS_WKO_CONTAINER_CANNOT_BE_SPECIAL",0x000021A3,"The target container for a redirection of a well-known object container cannot already be a special container.")

    # (0x000021A4) The directory service cannot perform the requested operation because a domain rename operation is in progress.
    ERROR_DS_DOMAIN_RENAME_IN_PROGRESS = WindowsError::ErrorCode.new("ERROR_DS_DOMAIN_RENAME_IN_PROGRESS",0x000021A4,"The directory service cannot perform the requested operation because a domain rename operation is in progress.")

    # (0x000021A5) The directory service detected a child partition below the requested partition name. The partition hierarchy must be created in a top down method.
    ERROR_DS_EXISTING_AD_CHILD_NC = WindowsError::ErrorCode.new("ERROR_DS_EXISTING_AD_CHILD_NC",0x000021A5,"The directory service detected a child partition below the requested partition name. The partition hierarchy must be created in a top down method.")

    # (0x000021A6) The directory service cannot replicate with this server because the time since the last replication with this server has exceeded the tombstone lifetime.
    ERROR_DS_REPL_LIFETIME_EXCEEDED = WindowsError::ErrorCode.new("ERROR_DS_REPL_LIFETIME_EXCEEDED",0x000021A6,"The directory service cannot replicate with this server because the time since the last replication with this server has exceeded the tombstone lifetime.")

    # (0x000021A7) The requested operation is not allowed on an object under the system container.
    ERROR_DS_DISALLOWED_IN_SYSTEM_CONTAINER = WindowsError::ErrorCode.new("ERROR_DS_DISALLOWED_IN_SYSTEM_CONTAINER",0x000021A7,"The requested operation is not allowed on an object under the system container.")

    # (0x000021A8) The LDAP server's network send queue has filled up because the client is not processing the results of its requests fast enough. No more requests will be processed until the client catches up. If the client does not catch up then it will be disconnected.
    ERROR_DS_LDAP_SEND_QUEUE_FULL = WindowsError::ErrorCode.new("ERROR_DS_LDAP_SEND_QUEUE_FULL",0x000021A8,"The LDAP server's network send queue has filled up because the client is not processing the results of its requests fast enough. No more requests will be processed until the client catches up. If the client does not catch up then it will be disconnected.")

    # (0x000021A9) The scheduled replication did not take place because the system was too busy to execute the request within the schedule window. The replication queue is overloaded. Consider reducing the number of partners or decreasing the scheduled replication frequency.
    ERROR_DS_DRA_OUT_SCHEDULE_WINDOW = WindowsError::ErrorCode.new("ERROR_DS_DRA_OUT_SCHEDULE_WINDOW",0x000021A9,"The scheduled replication did not take place because the system was too busy to execute the request within the schedule window. The replication queue is overloaded. Consider reducing the number of partners or decreasing the scheduled replication frequency.")

    # (0x000021AA) At this time, it cannot be determined if the branch replication policy is available on the hub domain controller. Retry at a later time to account for replication latencies.
    ERROR_DS_POLICY_NOT_KNOWN = WindowsError::ErrorCode.new("ERROR_DS_POLICY_NOT_KNOWN",0x000021AA,"At this time, it cannot be determined if the branch replication policy is available on the hub domain controller. Retry at a later time to account for replication latencies.")

    # (0x000021AB) The site settings object for the specified site does not exist.
    ERROR_NO_SITE_SETTINGS_OBJECT = WindowsError::ErrorCode.new("ERROR_NO_SITE_SETTINGS_OBJECT",0x000021AB,"The site settings object for the specified site does not exist.")

    # (0x000021AC) The local account store does not contain secret material for the specified account.
    ERROR_NO_SECRETS = WindowsError::ErrorCode.new("ERROR_NO_SECRETS",0x000021AC,"The local account store does not contain secret material for the specified account.")

    # (0x000021AD) Could not find a writable domain controller in the domain.
    ERROR_NO_WRITABLE_DC_FOUND = WindowsError::ErrorCode.new("ERROR_NO_WRITABLE_DC_FOUND",0x000021AD,"Could not find a writable domain controller in the domain.")

    # (0x000021AE) The server object for the domain controller does not exist.
    ERROR_DS_NO_SERVER_OBJECT = WindowsError::ErrorCode.new("ERROR_DS_NO_SERVER_OBJECT",0x000021AE,"The server object for the domain controller does not exist.")

    # (0x000021AF) The NTDS Settings object for the domain controller does not exist.
    ERROR_DS_NO_NTDSA_OBJECT = WindowsError::ErrorCode.new("ERROR_DS_NO_NTDSA_OBJECT",0x000021AF,"The NTDS Settings object for the domain controller does not exist.")

    # (0x000021B0) The requested search operation is not supported for attribute scoped query (ASQ) searches.
    ERROR_DS_NON_ASQ_SEARCH = WindowsError::ErrorCode.new("ERROR_DS_NON_ASQ_SEARCH",0x000021B0,"The requested search operation is not supported for attribute scoped query (ASQ) searches.")

    # (0x000021B1) A required audit event could not be generated for the operation.
    ERROR_DS_AUDIT_FAILURE = WindowsError::ErrorCode.new("ERROR_DS_AUDIT_FAILURE",0x000021B1,"A required audit event could not be generated for the operation.")

    # (0x000021B2) The search flags for the attribute are invalid. The subtree index bit is valid only on single-valued attributes.
    ERROR_DS_INVALID_SEARCH_FLAG_SUBTREE = WindowsError::ErrorCode.new("ERROR_DS_INVALID_SEARCH_FLAG_SUBTREE",0x000021B2,"The search flags for the attribute are invalid. The subtree index bit is valid only on single-valued attributes.")

    # (0x000021B3) The search flags for the attribute are invalid. The tuple index bit is valid only on attributes of Unicode strings.
    ERROR_DS_INVALID_SEARCH_FLAG_TUPLE = WindowsError::ErrorCode.new("ERROR_DS_INVALID_SEARCH_FLAG_TUPLE",0x000021B3,"The search flags for the attribute are invalid. The tuple index bit is valid only on attributes of Unicode strings.")

    # (0x000021C2) The functional level of the domain (or forest) cannot be lowered to the requested value.
    ERROR_DS_HIGH_DSA_VERSION = WindowsError::ErrorCode.new("ERROR_DS_HIGH_DSA_VERSION",0x000021C2,"The functional level of the domain (or forest) cannot be lowered to the requested value.")

    # (0x000021C7) The operation failed because the SPN value provided for addition/modification is not unique forest-wide.
    ERROR_DS_SPN_VALUE_NOT_UNIQUE_IN_FOREST = WindowsError::ErrorCode.new("ERROR_DS_SPN_VALUE_NOT_UNIQUE_IN_FOREST",0x000021C7,"The operation failed because the SPN value provided for addition/modification is not unique forest-wide.")

    # (0x000021C8) The operation failed because the UPN value provided for addition/modification is not unique forest-wide.
    ERROR_DS_UPN_VALUE_NOT_UNIQUE_IN_FOREST = WindowsError::ErrorCode.new("ERROR_DS_UPN_VALUE_NOT_UNIQUE_IN_FOREST",0x000021C8,"The operation failed because the UPN value provided for addition/modification is not unique forest-wide.")

    # (0x00002329) DNS server unable to interpret format.
    DNS_ERROR_RCODE_FORMAT_ERROR = WindowsError::ErrorCode.new("DNS_ERROR_RCODE_FORMAT_ERROR",0x00002329,"DNS server unable to interpret format.")

    # (0x0000232A) DNS server failure.
    DNS_ERROR_RCODE_SERVER_FAILURE = WindowsError::ErrorCode.new("DNS_ERROR_RCODE_SERVER_FAILURE",0x0000232A,"DNS server failure.")

    # (0x0000232B) DNS name does not exist.
    DNS_ERROR_RCODE_NAME_ERROR = WindowsError::ErrorCode.new("DNS_ERROR_RCODE_NAME_ERROR",0x0000232B,"DNS name does not exist.")

    # (0x0000232C) DNS request not supported by name server.
    DNS_ERROR_RCODE_NOT_IMPLEMENTED = WindowsError::ErrorCode.new("DNS_ERROR_RCODE_NOT_IMPLEMENTED",0x0000232C,"DNS request not supported by name server.")

    # (0x0000232D) DNS operation refused.
    DNS_ERROR_RCODE_REFUSED = WindowsError::ErrorCode.new("DNS_ERROR_RCODE_REFUSED",0x0000232D,"DNS operation refused.")

    # (0x0000232E) DNS name that should not exist, does exist.
    DNS_ERROR_RCODE_YXDOMAIN = WindowsError::ErrorCode.new("DNS_ERROR_RCODE_YXDOMAIN",0x0000232E,"DNS name that should not exist, does exist.")

    # (0x0000232F) DNS resource record (RR) set that should not exist, does exist.
    DNS_ERROR_RCODE_YXRRSET = WindowsError::ErrorCode.new("DNS_ERROR_RCODE_YXRRSET",0x0000232F,"DNS resource record (RR) set that should not exist, does exist.")

    # (0x00002330) DNS RR set that should to exist, does not exist.
    DNS_ERROR_RCODE_NXRRSET = WindowsError::ErrorCode.new("DNS_ERROR_RCODE_NXRRSET",0x00002330,"DNS RR set that should to exist, does not exist.")

    # (0x00002331) DNS server not authoritative for zone.
    DNS_ERROR_RCODE_NOTAUTH = WindowsError::ErrorCode.new("DNS_ERROR_RCODE_NOTAUTH",0x00002331,"DNS server not authoritative for zone.")

    # (0x00002332) DNS name in update or prereq is not in zone.
    DNS_ERROR_RCODE_NOTZONE = WindowsError::ErrorCode.new("DNS_ERROR_RCODE_NOTZONE",0x00002332,"DNS name in update or prereq is not in zone.")

    # (0x00002338) DNS signature failed to verify.
    DNS_ERROR_RCODE_BADSIG = WindowsError::ErrorCode.new("DNS_ERROR_RCODE_BADSIG",0x00002338,"DNS signature failed to verify.")

    # (0x00002339) DNS bad key.
    DNS_ERROR_RCODE_BADKEY = WindowsError::ErrorCode.new("DNS_ERROR_RCODE_BADKEY",0x00002339,"DNS bad key.")

    # (0x0000233A) DNS signature validity expired.
    DNS_ERROR_RCODE_BADTIME = WindowsError::ErrorCode.new("DNS_ERROR_RCODE_BADTIME",0x0000233A,"DNS signature validity expired.")

    # (0x0000251D) No records found for given DNS query.
    DNS_INFO_NO_RECORDS = WindowsError::ErrorCode.new("DNS_INFO_NO_RECORDS",0x0000251D,"No records found for given DNS query.")

    # (0x0000251E) Bad DNS packet.
    DNS_ERROR_BAD_PACKET = WindowsError::ErrorCode.new("DNS_ERROR_BAD_PACKET",0x0000251E,"Bad DNS packet.")

    # (0x0000251F) No DNS packet.
    DNS_ERROR_NO_PACKET = WindowsError::ErrorCode.new("DNS_ERROR_NO_PACKET",0x0000251F,"No DNS packet.")

    # (0x00002520) DNS error, check rcode.
    DNS_ERROR_RCODE = WindowsError::ErrorCode.new("DNS_ERROR_RCODE",0x00002520,"DNS error, check rcode.")

    # (0x00002521) Unsecured DNS packet.
    DNS_ERROR_UNSECURE_PACKET = WindowsError::ErrorCode.new("DNS_ERROR_UNSECURE_PACKET",0x00002521,"Unsecured DNS packet.")

    # (0x0000254F) Invalid DNS type.
    DNS_ERROR_INVALID_TYPE = WindowsError::ErrorCode.new("DNS_ERROR_INVALID_TYPE",0x0000254F,"Invalid DNS type.")

    # (0x00002550) Invalid IP address.
    DNS_ERROR_INVALID_IP_ADDRESS = WindowsError::ErrorCode.new("DNS_ERROR_INVALID_IP_ADDRESS",0x00002550,"Invalid IP address.")

    # (0x00002551) Invalid property.
    DNS_ERROR_INVALID_PROPERTY = WindowsError::ErrorCode.new("DNS_ERROR_INVALID_PROPERTY",0x00002551,"Invalid property.")

    # (0x00002552) Try DNS operation again later.
    DNS_ERROR_TRY_AGAIN_LATER = WindowsError::ErrorCode.new("DNS_ERROR_TRY_AGAIN_LATER",0x00002552,"Try DNS operation again later.")

    # (0x00002553) Record for given name and type is not unique.
    DNS_ERROR_NOT_UNIQUE = WindowsError::ErrorCode.new("DNS_ERROR_NOT_UNIQUE",0x00002553,"Record for given name and type is not unique.")

    # (0x00002554) DNS name does not comply with RFC specifications.
    DNS_ERROR_NON_RFC_NAME = WindowsError::ErrorCode.new("DNS_ERROR_NON_RFC_NAME",0x00002554,"DNS name does not comply with RFC specifications.")

    # (0x00002555) DNS name is a fully qualified DNS name.
    DNS_STATUS_FQDN = WindowsError::ErrorCode.new("DNS_STATUS_FQDN",0x00002555,"DNS name is a fully qualified DNS name.")

    # (0x00002556) DNS name is dotted (multilabel).
    DNS_STATUS_DOTTED_NAME = WindowsError::ErrorCode.new("DNS_STATUS_DOTTED_NAME",0x00002556,"DNS name is dotted (multilabel).")

    # (0x00002557) DNS name is a single-part name.
    DNS_STATUS_SINGLE_PART_NAME = WindowsError::ErrorCode.new("DNS_STATUS_SINGLE_PART_NAME",0x00002557,"DNS name is a single-part name.")

    # (0x00002558) DNS name contains an invalid character.
    DNS_ERROR_INVALID_NAME_CHAR = WindowsError::ErrorCode.new("DNS_ERROR_INVALID_NAME_CHAR",0x00002558,"DNS name contains an invalid character.")

    # (0x00002559) DNS name is entirely numeric.
    DNS_ERROR_NUMERIC_NAME = WindowsError::ErrorCode.new("DNS_ERROR_NUMERIC_NAME",0x00002559,"DNS name is entirely numeric.")

    # (0x0000255A) The operation requested is not permitted on a DNS root server.
    DNS_ERROR_NOT_ALLOWED_ON_ROOT_SERVER = WindowsError::ErrorCode.new("DNS_ERROR_NOT_ALLOWED_ON_ROOT_SERVER",0x0000255A,"The operation requested is not permitted on a DNS root server.")

    # (0x0000255B) The record could not be created because this part of the DNS namespace has been delegated to another server.
    DNS_ERROR_NOT_ALLOWED_UNDER_DELEGATION = WindowsError::ErrorCode.new("DNS_ERROR_NOT_ALLOWED_UNDER_DELEGATION",0x0000255B,"The record could not be created because this part of the DNS namespace has been delegated to another server.")

    # (0x0000255C) The DNS server could not find a set of root hints.
    DNS_ERROR_CANNOT_FIND_ROOT_HINTS = WindowsError::ErrorCode.new("DNS_ERROR_CANNOT_FIND_ROOT_HINTS",0x0000255C,"The DNS server could not find a set of root hints.")

    # (0x0000255D) The DNS server found root hints but they were not consistent across all adapters.
    DNS_ERROR_INCONSISTENT_ROOT_HINTS = WindowsError::ErrorCode.new("DNS_ERROR_INCONSISTENT_ROOT_HINTS",0x0000255D,"The DNS server found root hints but they were not consistent across all adapters.")

    # (0x0000255E) The specified value is too small for this parameter.
    DNS_ERROR_DWORD_VALUE_TOO_SMALL = WindowsError::ErrorCode.new("DNS_ERROR_DWORD_VALUE_TOO_SMALL",0x0000255E,"The specified value is too small for this parameter.")

    # (0x0000255F) The specified value is too large for this parameter.
    DNS_ERROR_DWORD_VALUE_TOO_LARGE = WindowsError::ErrorCode.new("DNS_ERROR_DWORD_VALUE_TOO_LARGE",0x0000255F,"The specified value is too large for this parameter.")

    # (0x00002560) This operation is not allowed while the DNS server is loading zones in the background. Try again later.
    DNS_ERROR_BACKGROUND_LOADING = WindowsError::ErrorCode.new("DNS_ERROR_BACKGROUND_LOADING",0x00002560,"This operation is not allowed while the DNS server is loading zones in the background. Try again later.")

    # (0x00002561) The operation requested is not permitted on against a DNS server running on a read-only DC.
    DNS_ERROR_NOT_ALLOWED_ON_RODC = WindowsError::ErrorCode.new("DNS_ERROR_NOT_ALLOWED_ON_RODC",0x00002561,"The operation requested is not permitted on against a DNS server running on a read-only DC.")

    # (0x00002581) DNS zone does not exist.
    DNS_ERROR_ZONE_DOES_NOT_EXIST = WindowsError::ErrorCode.new("DNS_ERROR_ZONE_DOES_NOT_EXIST",0x00002581,"DNS zone does not exist.")

    # (0x00002582) DNS zone information not available.
    DNS_ERROR_NO_ZONE_INFO = WindowsError::ErrorCode.new("DNS_ERROR_NO_ZONE_INFO",0x00002582,"DNS zone information not available.")

    # (0x00002583) Invalid operation for DNS zone.
    DNS_ERROR_INVALID_ZONE_OPERATION = WindowsError::ErrorCode.new("DNS_ERROR_INVALID_ZONE_OPERATION",0x00002583,"Invalid operation for DNS zone.")

    # (0x00002584) Invalid DNS zone configuration.
    DNS_ERROR_ZONE_CONFIGURATION_ERROR = WindowsError::ErrorCode.new("DNS_ERROR_ZONE_CONFIGURATION_ERROR",0x00002584,"Invalid DNS zone configuration.")

    # (0x00002585) DNS zone has no start of authority (SOA) record.
    DNS_ERROR_ZONE_HAS_NO_SOA_RECORD = WindowsError::ErrorCode.new("DNS_ERROR_ZONE_HAS_NO_SOA_RECORD",0x00002585,"DNS zone has no start of authority (SOA) record.")

    # (0x00002586) DNS zone has no Name Server (NS) record.
    DNS_ERROR_ZONE_HAS_NO_NS_RECORDS = WindowsError::ErrorCode.new("DNS_ERROR_ZONE_HAS_NO_NS_RECORDS",0x00002586,"DNS zone has no Name Server (NS) record.")

    # (0x00002587) DNS zone is locked.
    DNS_ERROR_ZONE_LOCKED = WindowsError::ErrorCode.new("DNS_ERROR_ZONE_LOCKED",0x00002587,"DNS zone is locked.")

    # (0x00002588) DNS zone creation failed.
    DNS_ERROR_ZONE_CREATION_FAILED = WindowsError::ErrorCode.new("DNS_ERROR_ZONE_CREATION_FAILED",0x00002588,"DNS zone creation failed.")

    # (0x00002589) DNS zone already exists.
    DNS_ERROR_ZONE_ALREADY_EXISTS = WindowsError::ErrorCode.new("DNS_ERROR_ZONE_ALREADY_EXISTS",0x00002589,"DNS zone already exists.")

    # (0x0000258A) DNS automatic zone already exists.
    DNS_ERROR_AUTOZONE_ALREADY_EXISTS = WindowsError::ErrorCode.new("DNS_ERROR_AUTOZONE_ALREADY_EXISTS",0x0000258A,"DNS automatic zone already exists.")

    # (0x0000258B) Invalid DNS zone type.
    DNS_ERROR_INVALID_ZONE_TYPE = WindowsError::ErrorCode.new("DNS_ERROR_INVALID_ZONE_TYPE",0x0000258B,"Invalid DNS zone type.")

    # (0x0000258C) Secondary DNS zone requires master IP address.
    DNS_ERROR_SECONDARY_REQUIRES_MASTER_IP = WindowsError::ErrorCode.new("DNS_ERROR_SECONDARY_REQUIRES_MASTER_IP",0x0000258C,"Secondary DNS zone requires master IP address.")

    # (0x0000258D) DNS zone not secondary.
    DNS_ERROR_ZONE_NOT_SECONDARY = WindowsError::ErrorCode.new("DNS_ERROR_ZONE_NOT_SECONDARY",0x0000258D,"DNS zone not secondary.")

    # (0x0000258E) Need secondary IP address.
    DNS_ERROR_NEED_SECONDARY_ADDRESSES = WindowsError::ErrorCode.new("DNS_ERROR_NEED_SECONDARY_ADDRESSES",0x0000258E,"Need secondary IP address.")

    # (0x0000258F) WINS initialization failed.
    DNS_ERROR_WINS_INIT_FAILED = WindowsError::ErrorCode.new("DNS_ERROR_WINS_INIT_FAILED",0x0000258F,"WINS initialization failed.")

    # (0x00002590) Need WINS servers.
    DNS_ERROR_NEED_WINS_SERVERS = WindowsError::ErrorCode.new("DNS_ERROR_NEED_WINS_SERVERS",0x00002590,"Need WINS servers.")

    # (0x00002591) NBTSTAT initialization call failed.
    DNS_ERROR_NBSTAT_INIT_FAILED = WindowsError::ErrorCode.new("DNS_ERROR_NBSTAT_INIT_FAILED",0x00002591,"NBTSTAT initialization call failed.")

    # (0x00002592) Invalid delete of SOA.
    DNS_ERROR_SOA_DELETE_INVALID = WindowsError::ErrorCode.new("DNS_ERROR_SOA_DELETE_INVALID",0x00002592,"Invalid delete of SOA.")

    # (0x00002593) A conditional forwarding zone already exists for that name.
    DNS_ERROR_FORWARDER_ALREADY_EXISTS = WindowsError::ErrorCode.new("DNS_ERROR_FORWARDER_ALREADY_EXISTS",0x00002593,"A conditional forwarding zone already exists for that name.")

    # (0x00002594) This zone must be configured with one or more master DNS server IP addresses.
    DNS_ERROR_ZONE_REQUIRES_MASTER_IP = WindowsError::ErrorCode.new("DNS_ERROR_ZONE_REQUIRES_MASTER_IP",0x00002594,"This zone must be configured with one or more master DNS server IP addresses.")

    # (0x00002595) The operation cannot be performed because this zone is shut down.
    DNS_ERROR_ZONE_IS_SHUTDOWN = WindowsError::ErrorCode.new("DNS_ERROR_ZONE_IS_SHUTDOWN",0x00002595,"The operation cannot be performed because this zone is shut down.")

    # (0x000025B3) The primary DNS zone requires a data file.
    DNS_ERROR_PRIMARY_REQUIRES_DATAFILE = WindowsError::ErrorCode.new("DNS_ERROR_PRIMARY_REQUIRES_DATAFILE",0x000025B3,"The primary DNS zone requires a data file.")

    # (0x000025B4) Invalid data file name for the DNS zone.
    DNS_ERROR_INVALID_DATAFILE_NAME = WindowsError::ErrorCode.new("DNS_ERROR_INVALID_DATAFILE_NAME",0x000025B4,"Invalid data file name for the DNS zone.")

    # (0x000025B5) Failed to open the data file for the DNS zone.
    DNS_ERROR_DATAFILE_OPEN_FAILURE = WindowsError::ErrorCode.new("DNS_ERROR_DATAFILE_OPEN_FAILURE",0x000025B5,"Failed to open the data file for the DNS zone.")

    # (0x000025B6) Failed to write the data file for the DNS zone.
    DNS_ERROR_FILE_WRITEBACK_FAILED = WindowsError::ErrorCode.new("DNS_ERROR_FILE_WRITEBACK_FAILED",0x000025B6,"Failed to write the data file for the DNS zone.")

    # (0x000025B7) Failure while reading datafile for DNS zone.
    DNS_ERROR_DATAFILE_PARSING = WindowsError::ErrorCode.new("DNS_ERROR_DATAFILE_PARSING",0x000025B7,"Failure while reading datafile for DNS zone.")

    # (0x000025E5) DNS record does not exist.
    DNS_ERROR_RECORD_DOES_NOT_EXIST = WindowsError::ErrorCode.new("DNS_ERROR_RECORD_DOES_NOT_EXIST",0x000025E5,"DNS record does not exist.")

    # (0x000025E6) DNS record format error.
    DNS_ERROR_RECORD_FORMAT = WindowsError::ErrorCode.new("DNS_ERROR_RECORD_FORMAT",0x000025E6,"DNS record format error.")

    # (0x000025E7) Node creation failure in DNS.
    DNS_ERROR_NODE_CREATION_FAILED = WindowsError::ErrorCode.new("DNS_ERROR_NODE_CREATION_FAILED",0x000025E7,"Node creation failure in DNS.")

    # (0x000025E8) Unknown DNS record type.
    DNS_ERROR_UNKNOWN_RECORD_TYPE = WindowsError::ErrorCode.new("DNS_ERROR_UNKNOWN_RECORD_TYPE",0x000025E8,"Unknown DNS record type.")

    # (0x000025E9) DNS record timed out.
    DNS_ERROR_RECORD_TIMED_OUT = WindowsError::ErrorCode.new("DNS_ERROR_RECORD_TIMED_OUT",0x000025E9,"DNS record timed out.")

    # (0x000025EA) Name not in DNS zone.
    DNS_ERROR_NAME_NOT_IN_ZONE = WindowsError::ErrorCode.new("DNS_ERROR_NAME_NOT_IN_ZONE",0x000025EA,"Name not in DNS zone.")

    # (0x000025EB) CNAME loop detected.
    DNS_ERROR_CNAME_LOOP = WindowsError::ErrorCode.new("DNS_ERROR_CNAME_LOOP",0x000025EB,"CNAME loop detected.")

    # (0x000025EC) Node is a CNAME DNS record.
    DNS_ERROR_NODE_IS_CNAME = WindowsError::ErrorCode.new("DNS_ERROR_NODE_IS_CNAME",0x000025EC,"Node is a CNAME DNS record.")

    # (0x000025ED) A CNAME record already exists for the given name.
    DNS_ERROR_CNAME_COLLISION = WindowsError::ErrorCode.new("DNS_ERROR_CNAME_COLLISION",0x000025ED,"A CNAME record already exists for the given name.")

    # (0x000025EE) Record is only at DNS zone root.
    DNS_ERROR_RECORD_ONLY_AT_ZONE_ROOT = WindowsError::ErrorCode.new("DNS_ERROR_RECORD_ONLY_AT_ZONE_ROOT",0x000025EE,"Record is only at DNS zone root.")

    # (0x000025EF) DNS record already exists.
    DNS_ERROR_RECORD_ALREADY_EXISTS = WindowsError::ErrorCode.new("DNS_ERROR_RECORD_ALREADY_EXISTS",0x000025EF,"DNS record already exists.")

    # (0x000025F0) Secondary DNS zone data error.
    DNS_ERROR_SECONDARY_DATA = WindowsError::ErrorCode.new("DNS_ERROR_SECONDARY_DATA",0x000025F0,"Secondary DNS zone data error.")

    # (0x000025F1) Could not create DNS cache data.
    DNS_ERROR_NO_CREATE_CACHE_DATA = WindowsError::ErrorCode.new("DNS_ERROR_NO_CREATE_CACHE_DATA",0x000025F1,"Could not create DNS cache data.")

    # (0x000025F2) DNS name does not exist.
    DNS_ERROR_NAME_DOES_NOT_EXIST = WindowsError::ErrorCode.new("DNS_ERROR_NAME_DOES_NOT_EXIST",0x000025F2,"DNS name does not exist.")

    # (0x000025F3) Could not create pointer (PTR) record.
    DNS_WARNING_PTR_CREATE_FAILED = WindowsError::ErrorCode.new("DNS_WARNING_PTR_CREATE_FAILED",0x000025F3,"Could not create pointer (PTR) record.")

    # (0x000025F4) DNS domain was undeleted.
    DNS_WARNING_DOMAIN_UNDELETED = WindowsError::ErrorCode.new("DNS_WARNING_DOMAIN_UNDELETED",0x000025F4,"DNS domain was undeleted.")

    # (0x000025F5) The directory service is unavailable.
    DNS_ERROR_DS_UNAVAILABLE = WindowsError::ErrorCode.new("DNS_ERROR_DS_UNAVAILABLE",0x000025F5,"The directory service is unavailable.")

    # (0x000025F6) DNS zone already exists in the directory service.
    DNS_ERROR_DS_ZONE_ALREADY_EXISTS = WindowsError::ErrorCode.new("DNS_ERROR_DS_ZONE_ALREADY_EXISTS",0x000025F6,"DNS zone already exists in the directory service.")

    # (0x000025F7) DNS server not creating or reading the boot file for the directory service integrated DNS zone.
    DNS_ERROR_NO_BOOTFILE_IF_DS_ZONE = WindowsError::ErrorCode.new("DNS_ERROR_NO_BOOTFILE_IF_DS_ZONE",0x000025F7,"DNS server not creating or reading the boot file for the directory service integrated DNS zone.")

    # (0x00002617) DNS AXFR (zone transfer) complete.
    DNS_INFO_AXFR_COMPLETE = WindowsError::ErrorCode.new("DNS_INFO_AXFR_COMPLETE",0x00002617,"DNS AXFR (zone transfer) complete.")

    # (0x00002618) DNS zone transfer failed.
    DNS_ERROR_AXFR = WindowsError::ErrorCode.new("DNS_ERROR_AXFR",0x00002618,"DNS zone transfer failed.")

    # (0x00002619) Added local WINS server.
    DNS_INFO_ADDED_LOCAL_WINS = WindowsError::ErrorCode.new("DNS_INFO_ADDED_LOCAL_WINS",0x00002619,"Added local WINS server.")

    # (0x00002649) Secure update call needs to continue update request.
    DNS_STATUS_CONTINUE_NEEDED = WindowsError::ErrorCode.new("DNS_STATUS_CONTINUE_NEEDED",0x00002649,"Secure update call needs to continue update request.")

    # (0x0000267B) TCP/IP network protocol not installed.
    DNS_ERROR_NO_TCPIP = WindowsError::ErrorCode.new("DNS_ERROR_NO_TCPIP",0x0000267B,"TCP/IP network protocol not installed.")

    # (0x0000267C) No DNS servers configured for local system.
    DNS_ERROR_NO_DNS_SERVERS = WindowsError::ErrorCode.new("DNS_ERROR_NO_DNS_SERVERS",0x0000267C,"No DNS servers configured for local system.")

    # (0x000026AD) The specified directory partition does not exist.
    DNS_ERROR_DP_DOES_NOT_EXIST = WindowsError::ErrorCode.new("DNS_ERROR_DP_DOES_NOT_EXIST",0x000026AD,"The specified directory partition does not exist.")

    # (0x000026AE) The specified directory partition already exists.
    DNS_ERROR_DP_ALREADY_EXISTS = WindowsError::ErrorCode.new("DNS_ERROR_DP_ALREADY_EXISTS",0x000026AE,"The specified directory partition already exists.")

    # (0x000026AF) This DNS server is not enlisted in the specified directory partition.
    DNS_ERROR_DP_NOT_ENLISTED = WindowsError::ErrorCode.new("DNS_ERROR_DP_NOT_ENLISTED",0x000026AF,"This DNS server is not enlisted in the specified directory partition.")

    # (0x000026B0) This DNS server is already enlisted in the specified directory partition.
    DNS_ERROR_DP_ALREADY_ENLISTED = WindowsError::ErrorCode.new("DNS_ERROR_DP_ALREADY_ENLISTED",0x000026B0,"This DNS server is already enlisted in the specified directory partition.")

    # (0x000026B1) The directory partition is not available at this time. Wait a few minutes and try again.
    DNS_ERROR_DP_NOT_AVAILABLE = WindowsError::ErrorCode.new("DNS_ERROR_DP_NOT_AVAILABLE",0x000026B1,"The directory partition is not available at this time. Wait a few minutes and try again.")

    # (0x000026B2) The application directory partition operation failed. The domain controller holding the domain naming master role is down or unable to service the request or is not running Windows Server 2003.
    DNS_ERROR_DP_FSMO_ERROR = WindowsError::ErrorCode.new("DNS_ERROR_DP_FSMO_ERROR",0x000026B2,"The application directory partition operation failed. The domain controller holding the domain naming master role is down or unable to service the request or is not running Windows Server 2003.")

    # (0x00002714) A blocking operation was interrupted by a call to WSACancelBlockingCall.
    WSAEINTR = WindowsError::ErrorCode.new("WSAEINTR",0x00002714,"A blocking operation was interrupted by a call to WSACancelBlockingCall.")

    # (0x00002719) The file handle supplied is not valid.
    WSAEBADF = WindowsError::ErrorCode.new("WSAEBADF",0x00002719,"The file handle supplied is not valid.")

    # (0x0000271D) An attempt was made to access a socket in a way forbidden by its access permissions.
    WSAEACCES = WindowsError::ErrorCode.new("WSAEACCES",0x0000271D,"An attempt was made to access a socket in a way forbidden by its access permissions.")

    # (0x0000271E) The system detected an invalid pointer address in attempting to use a pointer argument in a call.
    WSAEFAULT = WindowsError::ErrorCode.new("WSAEFAULT",0x0000271E,"The system detected an invalid pointer address in attempting to use a pointer argument in a call.")

    # (0x00002726) An invalid argument was supplied.
    WSAEINVAL = WindowsError::ErrorCode.new("WSAEINVAL",0x00002726,"An invalid argument was supplied.")

    # (0x00002728) Too many open sockets.
    WSAEMFILE = WindowsError::ErrorCode.new("WSAEMFILE",0x00002728,"Too many open sockets.")

    # (0x00002733) A nonblocking socket operation could not be completed immediately.
    WSAEWOULDBLOCK = WindowsError::ErrorCode.new("WSAEWOULDBLOCK",0x00002733,"A nonblocking socket operation could not be completed immediately.")

    # (0x00002734) A blocking operation is currently executing.
    WSAEINPROGRESS = WindowsError::ErrorCode.new("WSAEINPROGRESS",0x00002734,"A blocking operation is currently executing.")

    # (0x00002735) An operation was attempted on a nonblocking socket that already had an operation in progress.
    WSAEALREADY = WindowsError::ErrorCode.new("WSAEALREADY",0x00002735,"An operation was attempted on a nonblocking socket that already had an operation in progress.")

    # (0x00002736) An operation was attempted on something that is not a socket.
    WSAENOTSOCK = WindowsError::ErrorCode.new("WSAENOTSOCK",0x00002736,"An operation was attempted on something that is not a socket.")

    # (0x00002737) A required address was omitted from an operation on a socket.
    WSAEDESTADDRREQ = WindowsError::ErrorCode.new("WSAEDESTADDRREQ",0x00002737,"A required address was omitted from an operation on a socket.")

    # (0x00002738) A message sent on a datagram socket was larger than the internal message buffer or some other network limit, or the buffer used to receive a datagram into was smaller than the datagram itself.
    WSAEMSGSIZE = WindowsError::ErrorCode.new("WSAEMSGSIZE",0x00002738,"A message sent on a datagram socket was larger than the internal message buffer or some other network limit, or the buffer used to receive a datagram into was smaller than the datagram itself.")

    # (0x00002739) A protocol was specified in the socket function call that does not support the semantics of the socket type requested.
    WSAEPROTOTYPE = WindowsError::ErrorCode.new("WSAEPROTOTYPE",0x00002739,"A protocol was specified in the socket function call that does not support the semantics of the socket type requested.")

    # (0x0000273A) An unknown, invalid, or unsupported option or level was specified in a getsockopt or setsockopt call.
    WSAENOPROTOOPT = WindowsError::ErrorCode.new("WSAENOPROTOOPT",0x0000273A,"An unknown, invalid, or unsupported option or level was specified in a getsockopt or setsockopt call.")

    # (0x0000273B) The requested protocol has not been configured into the system, or no implementation for it exists.
    WSAEPROTONOSUPPORT = WindowsError::ErrorCode.new("WSAEPROTONOSUPPORT",0x0000273B,"The requested protocol has not been configured into the system, or no implementation for it exists.")

    # (0x0000273C) The support for the specified socket type does not exist in this address family.
    WSAESOCKTNOSUPPORT = WindowsError::ErrorCode.new("WSAESOCKTNOSUPPORT",0x0000273C,"The support for the specified socket type does not exist in this address family.")

    # (0x0000273D) The attempted operation is not supported for the type of object referenced.
    WSAEOPNOTSUPP = WindowsError::ErrorCode.new("WSAEOPNOTSUPP",0x0000273D,"The attempted operation is not supported for the type of object referenced.")

    # (0x0000273E) The protocol family has not been configured into the system or no implementation for it exists.
    WSAEPFNOSUPPORT = WindowsError::ErrorCode.new("WSAEPFNOSUPPORT",0x0000273E,"The protocol family has not been configured into the system or no implementation for it exists.")

    # (0x0000273F) An address incompatible with the requested protocol was used.
    WSAEAFNOSUPPORT = WindowsError::ErrorCode.new("WSAEAFNOSUPPORT",0x0000273F,"An address incompatible with the requested protocol was used.")

    # (0x00002740) Only one usage of each socket address (protocol/network address/port) is normally permitted.
    WSAEADDRINUSE = WindowsError::ErrorCode.new("WSAEADDRINUSE",0x00002740,"Only one usage of each socket address (protocol/network address/port) is normally permitted.")

    # (0x00002741) The requested address is not valid in its context.
    WSAEADDRNOTAVAIL = WindowsError::ErrorCode.new("WSAEADDRNOTAVAIL",0x00002741,"The requested address is not valid in its context.")

    # (0x00002742) A socket operation encountered a dead network.
    WSAENETDOWN = WindowsError::ErrorCode.new("WSAENETDOWN",0x00002742,"A socket operation encountered a dead network.")

    # (0x00002743) A socket operation was attempted to an unreachable network.
    WSAENETUNREACH = WindowsError::ErrorCode.new("WSAENETUNREACH",0x00002743,"A socket operation was attempted to an unreachable network.")

    # (0x00002744) The connection has been broken due to keep-alive activity detecting a failure while the operation was in progress.
    WSAENETRESET = WindowsError::ErrorCode.new("WSAENETRESET",0x00002744,"The connection has been broken due to keep-alive activity detecting a failure while the operation was in progress.")

    # (0x00002745) An established connection was aborted by the software in your host machine.
    WSAECONNABORTED = WindowsError::ErrorCode.new("WSAECONNABORTED",0x00002745,"An established connection was aborted by the software in your host machine.")

    # (0x00002746) An existing connection was forcibly closed by the remote host.
    WSAECONNRESET = WindowsError::ErrorCode.new("WSAECONNRESET",0x00002746,"An existing connection was forcibly closed by the remote host.")

    # (0x00002747) An operation on a socket could not be performed because the system lacked sufficient buffer space or because a queue was full.
    WSAENOBUFS = WindowsError::ErrorCode.new("WSAENOBUFS",0x00002747,"An operation on a socket could not be performed because the system lacked sufficient buffer space or because a queue was full.")

    # (0x00002748) A connect request was made on an already connected socket.
    WSAEISCONN = WindowsError::ErrorCode.new("WSAEISCONN",0x00002748,"A connect request was made on an already connected socket.")

    # (0x00002749) A request to send or receive data was disallowed because the socket is not connected and (when sending on a datagram socket using a sendto call) no address was supplied.
    WSAENOTCONN = WindowsError::ErrorCode.new("WSAENOTCONN",0x00002749,"A request to send or receive data was disallowed because the socket is not connected and (when sending on a datagram socket using a sendto call) no address was supplied.")

    # (0x0000274A) A request to send or receive data was disallowed because the socket had already been shut down in that direction with a previous shutdown call.
    WSAESHUTDOWN = WindowsError::ErrorCode.new("WSAESHUTDOWN",0x0000274A,"A request to send or receive data was disallowed because the socket had already been shut down in that direction with a previous shutdown call.")

    # (0x0000274B) Too many references to a kernel object.
    WSAETOOMANYREFS = WindowsError::ErrorCode.new("WSAETOOMANYREFS",0x0000274B,"Too many references to a kernel object.")

    # (0x0000274C) A connection attempt failed because the connected party did not properly respond after a period of time, or the established connection failed because the connected host failed to respond.
    WSAETIMEDOUT = WindowsError::ErrorCode.new("WSAETIMEDOUT",0x0000274C,"A connection attempt failed because the connected party did not properly respond after a period of time, or the established connection failed because the connected host failed to respond.")

    # (0x0000274D) No connection could be made because the target machine actively refused it.
    WSAECONNREFUSED = WindowsError::ErrorCode.new("WSAECONNREFUSED",0x0000274D,"No connection could be made because the target machine actively refused it.")

    # (0x0000274E) Cannot translate name.
    WSAELOOP = WindowsError::ErrorCode.new("WSAELOOP",0x0000274E,"Cannot translate name.")

    # (0x0000274F) Name or name component was too long.
    WSAENAMETOOLONG = WindowsError::ErrorCode.new("WSAENAMETOOLONG",0x0000274F,"Name or name component was too long.")

    # (0x00002750) A socket operation failed because the destination host was down.
    WSAEHOSTDOWN = WindowsError::ErrorCode.new("WSAEHOSTDOWN",0x00002750,"A socket operation failed because the destination host was down.")

    # (0x00002751) A socket operation was attempted to an unreachable host.
    WSAEHOSTUNREACH = WindowsError::ErrorCode.new("WSAEHOSTUNREACH",0x00002751,"A socket operation was attempted to an unreachable host.")

    # (0x00002752) Cannot remove a directory that is not empty.
    WSAENOTEMPTY = WindowsError::ErrorCode.new("WSAENOTEMPTY",0x00002752,"Cannot remove a directory that is not empty.")

    # (0x00002753) A Windows Sockets implementation may have a limit on the number of applications that may use it simultaneously.
    WSAEPROCLIM = WindowsError::ErrorCode.new("WSAEPROCLIM",0x00002753,"A Windows Sockets implementation may have a limit on the number of applications that may use it simultaneously.")

    # (0x00002754) Ran out of quota.
    WSAEUSERS = WindowsError::ErrorCode.new("WSAEUSERS",0x00002754,"Ran out of quota.")

    # (0x00002755) Ran out of disk quota.
    WSAEDQUOT = WindowsError::ErrorCode.new("WSAEDQUOT",0x00002755,"Ran out of disk quota.")

    # (0x00002756) File handle reference is no longer available.
    WSAESTALE = WindowsError::ErrorCode.new("WSAESTALE",0x00002756,"File handle reference is no longer available.")

    # (0x00002757) Item is not available locally.
    WSAEREMOTE = WindowsError::ErrorCode.new("WSAEREMOTE",0x00002757,"Item is not available locally.")

    # (0x0000276B) WSAStartup cannot function at this time because the underlying system it uses to provide network services is currently unavailable.
    WSASYSNOTREADY = WindowsError::ErrorCode.new("WSASYSNOTREADY",0x0000276B,"WSAStartup cannot function at this time because the underlying system it uses to provide network services is currently unavailable.")

    # (0x0000276C) The Windows Sockets version requested is not supported.
    WSAVERNOTSUPPORTED = WindowsError::ErrorCode.new("WSAVERNOTSUPPORTED",0x0000276C,"The Windows Sockets version requested is not supported.")

    # (0x0000276D) Either the application has not called WSAStartup, or WSAStartup failed.
    WSANOTINITIALISED = WindowsError::ErrorCode.new("WSANOTINITIALISED",0x0000276D,"Either the application has not called WSAStartup, or WSAStartup failed.")

    # (0x00002775) Returned by WSARecv or WSARecvFrom to indicate that the remote party has initiated a graceful shutdown sequence.
    WSAEDISCON = WindowsError::ErrorCode.new("WSAEDISCON",0x00002775,"Returned by WSARecv or WSARecvFrom to indicate that the remote party has initiated a graceful shutdown sequence.")

    # (0x00002776) No more results can be returned by WSALookupServiceNext.
    WSAENOMORE = WindowsError::ErrorCode.new("WSAENOMORE",0x00002776,"No more results can be returned by WSALookupServiceNext.")

    # (0x00002777) A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled.
    WSAECANCELLED = WindowsError::ErrorCode.new("WSAECANCELLED",0x00002777,"A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled.")

    # (0x00002778) The procedure call table is invalid.
    WSAEINVALIDPROCTABLE = WindowsError::ErrorCode.new("WSAEINVALIDPROCTABLE",0x00002778,"The procedure call table is invalid.")

    # (0x00002779) The requested service provider is invalid.
    WSAEINVALIDPROVIDER = WindowsError::ErrorCode.new("WSAEINVALIDPROVIDER",0x00002779,"The requested service provider is invalid.")

    # (0x0000277A) The requested service provider could not be loaded or initialized.
    WSAEPROVIDERFAILEDINIT = WindowsError::ErrorCode.new("WSAEPROVIDERFAILEDINIT",0x0000277A,"The requested service provider could not be loaded or initialized.")

    # (0x0000277B) A system call that should never fail has failed.
    WSASYSCALLFAILURE = WindowsError::ErrorCode.new("WSASYSCALLFAILURE",0x0000277B,"A system call that should never fail has failed.")

    # (0x0000277C) No such service is known. The service cannot be found in the specified namespace.
    WSASERVICE_NOT_FOUND = WindowsError::ErrorCode.new("WSASERVICE_NOT_FOUND",0x0000277C,"No such service is known. The service cannot be found in the specified namespace.")

    # (0x0000277D) The specified class was not found.
    WSATYPE_NOT_FOUND = WindowsError::ErrorCode.new("WSATYPE_NOT_FOUND",0x0000277D,"The specified class was not found.")

    # (0x0000277E) No more results can be returned by WSALookupServiceNext.
    WSA_E_NO_MORE = WindowsError::ErrorCode.new("WSA_E_NO_MORE",0x0000277E,"No more results can be returned by WSALookupServiceNext.")

    # (0x0000277F) A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled.
    WSA_E_CANCELLED = WindowsError::ErrorCode.new("WSA_E_CANCELLED",0x0000277F,"A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled.")

    # (0x00002780) A database query failed because it was actively refused.
    WSAEREFUSED = WindowsError::ErrorCode.new("WSAEREFUSED",0x00002780,"A database query failed because it was actively refused.")

    # (0x00002AF9) No such host is known.
    WSAHOST_NOT_FOUND = WindowsError::ErrorCode.new("WSAHOST_NOT_FOUND",0x00002AF9,"No such host is known.")

    # (0x00002AFA) This is usually a temporary error during host name resolution and means that the local server did not receive a response from an authoritative server.
    WSATRY_AGAIN = WindowsError::ErrorCode.new("WSATRY_AGAIN",0x00002AFA,"This is usually a temporary error during host name resolution and means that the local server did not receive a response from an authoritative server.")

    # (0x00002AFB) A nonrecoverable error occurred during a database lookup.
    WSANO_RECOVERY = WindowsError::ErrorCode.new("WSANO_RECOVERY",0x00002AFB,"A nonrecoverable error occurred during a database lookup.")

    # (0x00002AFC) The requested name is valid, but no data of the requested type was found.
    WSANO_DATA = WindowsError::ErrorCode.new("WSANO_DATA",0x00002AFC,"The requested name is valid, but no data of the requested type was found.")

    # (0x00002AFD) At least one reserve has arrived.
    WSA_QOS_RECEIVERS = WindowsError::ErrorCode.new("WSA_QOS_RECEIVERS",0x00002AFD,"At least one reserve has arrived.")

    # (0x00002AFE) At least one path has arrived.
    WSA_QOS_SENDERS = WindowsError::ErrorCode.new("WSA_QOS_SENDERS",0x00002AFE,"At least one path has arrived.")

    # (0x00002AFF) There are no senders.
    WSA_QOS_NO_SENDERS = WindowsError::ErrorCode.new("WSA_QOS_NO_SENDERS",0x00002AFF,"There are no senders.")

    # (0x00002B00) There are no receivers.
    WSA_QOS_NO_RECEIVERS = WindowsError::ErrorCode.new("WSA_QOS_NO_RECEIVERS",0x00002B00,"There are no receivers.")

    # (0x00002B01) Reserve has been confirmed.
    WSA_QOS_REQUEST_CONFIRMED = WindowsError::ErrorCode.new("WSA_QOS_REQUEST_CONFIRMED",0x00002B01,"Reserve has been confirmed.")

    # (0x00002B02) Error due to lack of resources.
    WSA_QOS_ADMISSION_FAILURE = WindowsError::ErrorCode.new("WSA_QOS_ADMISSION_FAILURE",0x00002B02,"Error due to lack of resources.")

    # (0x00002B03) Rejected for administrative reasons—bad credentials.
    WSA_QOS_POLICY_FAILURE = WindowsError::ErrorCode.new("WSA_QOS_POLICY_FAILURE",0x00002B03,"Rejected for administrative reasons\u{2014}bad credentials.")

    # (0x00002B04) Unknown or conflicting style.
    WSA_QOS_BAD_STYLE = WindowsError::ErrorCode.new("WSA_QOS_BAD_STYLE",0x00002B04,"Unknown or conflicting style.")

    # (0x00002B05) There is a problem with some part of the filterspec or provider-specific buffer in general.
    WSA_QOS_BAD_OBJECT = WindowsError::ErrorCode.new("WSA_QOS_BAD_OBJECT",0x00002B05,"There is a problem with some part of the filterspec or provider-specific buffer in general.")

    # (0x00002B06) There is a problem with some part of the flowspec.
    WSA_QOS_TRAFFIC_CTRL_ERROR = WindowsError::ErrorCode.new("WSA_QOS_TRAFFIC_CTRL_ERROR",0x00002B06,"There is a problem with some part of the flowspec.")

    # (0x00002B07) General quality of serve (QOS) error.
    WSA_QOS_GENERIC_ERROR = WindowsError::ErrorCode.new("WSA_QOS_GENERIC_ERROR",0x00002B07,"General quality of serve (QOS) error.")

    # (0x00002B08) An invalid or unrecognized service type was found in the flowspec.
    WSA_QOS_ESERVICETYPE = WindowsError::ErrorCode.new("WSA_QOS_ESERVICETYPE",0x00002B08,"An invalid or unrecognized service type was found in the flowspec.")

    # (0x00002B09) An invalid or inconsistent flowspec was found in the QOS structure.
    WSA_QOS_EFLOWSPEC = WindowsError::ErrorCode.new("WSA_QOS_EFLOWSPEC",0x00002B09,"An invalid or inconsistent flowspec was found in the QOS structure.")

    # (0x00002B0A) Invalid QOS provider-specific buffer.
    WSA_QOS_EPROVSPECBUF = WindowsError::ErrorCode.new("WSA_QOS_EPROVSPECBUF",0x00002B0A,"Invalid QOS provider-specific buffer.")

    # (0x00002B0B) An invalid QOS filter style was used.
    WSA_QOS_EFILTERSTYLE = WindowsError::ErrorCode.new("WSA_QOS_EFILTERSTYLE",0x00002B0B,"An invalid QOS filter style was used.")

    # (0x00002B0C) An invalid QOS filter type was used.
    WSA_QOS_EFILTERTYPE = WindowsError::ErrorCode.new("WSA_QOS_EFILTERTYPE",0x00002B0C,"An invalid QOS filter type was used.")

    # (0x00002B0D) An incorrect number of QOS FILTERSPECs were specified in the FLOWDESCRIPTOR.
    WSA_QOS_EFILTERCOUNT = WindowsError::ErrorCode.new("WSA_QOS_EFILTERCOUNT",0x00002B0D,"An incorrect number of QOS FILTERSPECs were specified in the FLOWDESCRIPTOR.")

    # (0x00002B0E) An object with an invalid ObjectLength field was specified in the QOS provider-specific buffer.
    WSA_QOS_EOBJLENGTH = WindowsError::ErrorCode.new("WSA_QOS_EOBJLENGTH",0x00002B0E,"An object with an invalid ObjectLength field was specified in the QOS provider-specific buffer.")

    # (0x00002B0F) An incorrect number of flow descriptors was specified in the QOS structure.
    WSA_QOS_EFLOWCOUNT = WindowsError::ErrorCode.new("WSA_QOS_EFLOWCOUNT",0x00002B0F,"An incorrect number of flow descriptors was specified in the QOS structure.")

    # (0x00002B10) An unrecognized object was found in the QOS provider-specific buffer.
    WSA_QOS_EUNKOWNPSOBJ = WindowsError::ErrorCode.new("WSA_QOS_EUNKOWNPSOBJ",0x00002B10,"An unrecognized object was found in the QOS provider-specific buffer.")

    # (0x00002B11) An invalid policy object was found in the QOS provider-specific buffer.
    WSA_QOS_EPOLICYOBJ = WindowsError::ErrorCode.new("WSA_QOS_EPOLICYOBJ",0x00002B11,"An invalid policy object was found in the QOS provider-specific buffer.")

    # (0x00002B12) An invalid QOS flow descriptor was found in the flow descriptor list.
    WSA_QOS_EFLOWDESC = WindowsError::ErrorCode.new("WSA_QOS_EFLOWDESC",0x00002B12,"An invalid QOS flow descriptor was found in the flow descriptor list.")

    # (0x00002B13) An invalid or inconsistent flowspec was found in the QOS provider-specific buffer.
    WSA_QOS_EPSFLOWSPEC = WindowsError::ErrorCode.new("WSA_QOS_EPSFLOWSPEC",0x00002B13,"An invalid or inconsistent flowspec was found in the QOS provider-specific buffer.")

    # (0x00002B14) An invalid FILTERSPEC was found in the QOS provider-specific buffer.
    WSA_QOS_EPSFILTERSPEC = WindowsError::ErrorCode.new("WSA_QOS_EPSFILTERSPEC",0x00002B14,"An invalid FILTERSPEC was found in the QOS provider-specific buffer.")

    # (0x00002B15) An invalid shape discard mode object was found in the QOS provider-specific buffer.
    WSA_QOS_ESDMODEOBJ = WindowsError::ErrorCode.new("WSA_QOS_ESDMODEOBJ",0x00002B15,"An invalid shape discard mode object was found in the QOS provider-specific buffer.")

    # (0x00002B16) An invalid shaping rate object was found in the QOS provider-specific buffer.
    WSA_QOS_ESHAPERATEOBJ = WindowsError::ErrorCode.new("WSA_QOS_ESHAPERATEOBJ",0x00002B16,"An invalid shaping rate object was found in the QOS provider-specific buffer.")

    # (0x00002B17) A reserved policy element was found in the QOS provider-specific buffer.
    WSA_QOS_RESERVED_PETYPE = WindowsError::ErrorCode.new("WSA_QOS_RESERVED_PETYPE",0x00002B17,"A reserved policy element was found in the QOS provider-specific buffer.")

    # (0x000032C8) The specified quick mode policy already exists.
    ERROR_IPSEC_QM_POLICY_EXISTS = WindowsError::ErrorCode.new("ERROR_IPSEC_QM_POLICY_EXISTS",0x000032C8,"The specified quick mode policy already exists.")

    # (0x000032C9) The specified quick mode policy was not found.
    ERROR_IPSEC_QM_POLICY_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_IPSEC_QM_POLICY_NOT_FOUND",0x000032C9,"The specified quick mode policy was not found.")

    # (0x000032CA) The specified quick mode policy is being used.
    ERROR_IPSEC_QM_POLICY_IN_USE = WindowsError::ErrorCode.new("ERROR_IPSEC_QM_POLICY_IN_USE",0x000032CA,"The specified quick mode policy is being used.")

    # (0x000032CB) The specified main mode policy already exists.
    ERROR_IPSEC_MM_POLICY_EXISTS = WindowsError::ErrorCode.new("ERROR_IPSEC_MM_POLICY_EXISTS",0x000032CB,"The specified main mode policy already exists.")

    # (0x000032CC) The specified main mode policy was not found.
    ERROR_IPSEC_MM_POLICY_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_IPSEC_MM_POLICY_NOT_FOUND",0x000032CC,"The specified main mode policy was not found.")

    # (0x000032CD) The specified main mode policy is being used.
    ERROR_IPSEC_MM_POLICY_IN_USE = WindowsError::ErrorCode.new("ERROR_IPSEC_MM_POLICY_IN_USE",0x000032CD,"The specified main mode policy is being used.")

    # (0x000032CE) The specified main mode filter already exists.
    ERROR_IPSEC_MM_FILTER_EXISTS = WindowsError::ErrorCode.new("ERROR_IPSEC_MM_FILTER_EXISTS",0x000032CE,"The specified main mode filter already exists.")

    # (0x000032CF) The specified main mode filter was not found.
    ERROR_IPSEC_MM_FILTER_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_IPSEC_MM_FILTER_NOT_FOUND",0x000032CF,"The specified main mode filter was not found.")

    # (0x000032D0) The specified transport mode filter already exists.
    ERROR_IPSEC_TRANSPORT_FILTER_EXISTS = WindowsError::ErrorCode.new("ERROR_IPSEC_TRANSPORT_FILTER_EXISTS",0x000032D0,"The specified transport mode filter already exists.")

    # (0x000032D1) The specified transport mode filter does not exist.
    ERROR_IPSEC_TRANSPORT_FILTER_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_IPSEC_TRANSPORT_FILTER_NOT_FOUND",0x000032D1,"The specified transport mode filter does not exist.")

    # (0x000032D2) The specified main mode authentication list exists.
    ERROR_IPSEC_MM_AUTH_EXISTS = WindowsError::ErrorCode.new("ERROR_IPSEC_MM_AUTH_EXISTS",0x000032D2,"The specified main mode authentication list exists.")

    # (0x000032D3) The specified main mode authentication list was not found.
    ERROR_IPSEC_MM_AUTH_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_IPSEC_MM_AUTH_NOT_FOUND",0x000032D3,"The specified main mode authentication list was not found.")

    # (0x000032D4) The specified main mode authentication list is being used.
    ERROR_IPSEC_MM_AUTH_IN_USE = WindowsError::ErrorCode.new("ERROR_IPSEC_MM_AUTH_IN_USE",0x000032D4,"The specified main mode authentication list is being used.")

    # (0x000032D5) The specified default main mode policy was not found.
    ERROR_IPSEC_DEFAULT_MM_POLICY_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_IPSEC_DEFAULT_MM_POLICY_NOT_FOUND",0x000032D5,"The specified default main mode policy was not found.")

    # (0x000032D6) The specified default main mode authentication list was not found.
    ERROR_IPSEC_DEFAULT_MM_AUTH_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_IPSEC_DEFAULT_MM_AUTH_NOT_FOUND",0x000032D6,"The specified default main mode authentication list was not found.")

    # (0x000032D7) The specified default quick mode policy was not found.
    ERROR_IPSEC_DEFAULT_QM_POLICY_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_IPSEC_DEFAULT_QM_POLICY_NOT_FOUND",0x000032D7,"The specified default quick mode policy was not found.")

    # (0x000032D8) The specified tunnel mode filter exists.
    ERROR_IPSEC_TUNNEL_FILTER_EXISTS = WindowsError::ErrorCode.new("ERROR_IPSEC_TUNNEL_FILTER_EXISTS",0x000032D8,"The specified tunnel mode filter exists.")

    # (0x000032D9) The specified tunnel mode filter was not found.
    ERROR_IPSEC_TUNNEL_FILTER_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_IPSEC_TUNNEL_FILTER_NOT_FOUND",0x000032D9,"The specified tunnel mode filter was not found.")

    # (0x000032DA) The main mode filter is pending deletion.
    ERROR_IPSEC_MM_FILTER_PENDING_DELETION = WindowsError::ErrorCode.new("ERROR_IPSEC_MM_FILTER_PENDING_DELETION",0x000032DA,"The main mode filter is pending deletion.")

    # (0x000032DB) The transport filter is pending deletion.
    ERROR_IPSEC_TRANSPORT_FILTER_ENDING_DELETION = WindowsError::ErrorCode.new("ERROR_IPSEC_TRANSPORT_FILTER_ENDING_DELETION",0x000032DB,"The transport filter is pending deletion.")

    # (0x000032DC) The tunnel filter is pending deletion.
    ERROR_IPSEC_TUNNEL_FILTER_PENDING_DELETION = WindowsError::ErrorCode.new("ERROR_IPSEC_TUNNEL_FILTER_PENDING_DELETION",0x000032DC,"The tunnel filter is pending deletion.")

    # (0x000032DD) The main mode policy is pending deletion.
    ERROR_IPSEC_MM_POLICY_PENDING_ELETION = WindowsError::ErrorCode.new("ERROR_IPSEC_MM_POLICY_PENDING_ELETION",0x000032DD,"The main mode policy is pending deletion.")

    # (0x000032DE) The main mode authentication bundle is pending deletion.
    ERROR_IPSEC_MM_AUTH_PENDING_DELETION = WindowsError::ErrorCode.new("ERROR_IPSEC_MM_AUTH_PENDING_DELETION",0x000032DE,"The main mode authentication bundle is pending deletion.")

    # (0x000032DF) The quick mode policy is pending deletion.
    ERROR_IPSEC_QM_POLICY_PENDING_DELETION = WindowsError::ErrorCode.new("ERROR_IPSEC_QM_POLICY_PENDING_DELETION",0x000032DF,"The quick mode policy is pending deletion.")

    # (0x000032E0) The main mode policy was successfully added, but some of the requested offers are not supported.
    WARNING_IPSEC_MM_POLICY_PRUNED = WindowsError::ErrorCode.new("WARNING_IPSEC_MM_POLICY_PRUNED",0x000032E0,"The main mode policy was successfully added, but some of the requested offers are not supported.")

    # (0x000032E1) The quick mode policy was successfully added, but some of the requested offers are not supported.
    WARNING_IPSEC_QM_POLICY_PRUNED = WindowsError::ErrorCode.new("WARNING_IPSEC_QM_POLICY_PRUNED",0x000032E1,"The quick mode policy was successfully added, but some of the requested offers are not supported.")

    # (0x000035E8) Starts the list of frequencies of various IKE Win32 error codes encountered during negotiations.
    ERROR_IPSEC_IKE_NEG_STATUS_BEGIN = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_NEG_STATUS_BEGIN",0x000035E8,"Starts the list of frequencies of various IKE Win32 error codes encountered during negotiations.")

    # (0x000035E9) The IKE authentication credentials are unacceptable.
    ERROR_IPSEC_IKE_AUTH_FAIL = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_AUTH_FAIL",0x000035E9,"The IKE authentication credentials are unacceptable.")

    # (0x000035EA) The IKE security attributes are unacceptable.
    ERROR_IPSEC_IKE_ATTRIB_FAIL = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_ATTRIB_FAIL",0x000035EA,"The IKE security attributes are unacceptable.")

    # (0x000035EB) The IKE negotiation is in progress.
    ERROR_IPSEC_IKE_NEGOTIATION_PENDING = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_NEGOTIATION_PENDING",0x000035EB,"The IKE negotiation is in progress.")

    # (0x000035EC) General processing error.
    ERROR_IPSEC_IKE_GENERAL_PROCESSING_ERROR = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_GENERAL_PROCESSING_ERROR",0x000035EC,"General processing error.")

    # (0x000035ED) Negotiation timed out.
    ERROR_IPSEC_IKE_TIMED_OUT = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_TIMED_OUT",0x000035ED,"Negotiation timed out.")

    # (0x000035EE) The IKE failed to find a valid machine certificate. Contact your network security administrator about installing a valid certificate in the appropriate certificate store.
    ERROR_IPSEC_IKE_NO_CERT = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_NO_CERT",0x000035EE,"The IKE failed to find a valid machine certificate. Contact your network security administrator about installing a valid certificate in the appropriate certificate store.")

    # (0x000035EF) The IKE security association (SA) was deleted by a peer before it was completely established.
    ERROR_IPSEC_IKE_SA_DELETED = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_SA_DELETED",0x000035EF,"The IKE security association (SA) was deleted by a peer before it was completely established.")

    # (0x000035F0) The IKE SA was deleted before it was completely established.
    ERROR_IPSEC_IKE_SA_REAPED = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_SA_REAPED",0x000035F0,"The IKE SA was deleted before it was completely established.")

    # (0x000035F1) The negotiation request sat in the queue too long.
    ERROR_IPSEC_IKE_MM_ACQUIRE_DROP = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_MM_ACQUIRE_DROP",0x000035F1,"The negotiation request sat in the queue too long.")

    # (0x000035F2) The negotiation request sat in the queue too long.
    ERROR_IPSEC_IKE_QM_ACQUIRE_DROP = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_QM_ACQUIRE_DROP",0x000035F2,"The negotiation request sat in the queue too long.")

    # (0x000035F3) The negotiation request sat in the queue too long.
    ERROR_IPSEC_IKE_QUEUE_DROP_MM = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_QUEUE_DROP_MM",0x000035F3,"The negotiation request sat in the queue too long.")

    # (0x000035F4) The negotiation request sat in the queue too long.
    ERROR_IPSEC_IKE_QUEUE_DROP_NO_MM = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_QUEUE_DROP_NO_MM",0x000035F4,"The negotiation request sat in the queue too long.")

    # (0x000035F5) There was no response from a peer.
    ERROR_IPSEC_IKE_DROP_NO_RESPONSE = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_DROP_NO_RESPONSE",0x000035F5,"There was no response from a peer.")

    # (0x000035F6) The negotiation took too long.
    ERROR_IPSEC_IKE_MM_DELAY_DROP = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_MM_DELAY_DROP",0x000035F6,"The negotiation took too long.")

    # (0x000035F7) The negotiation took too long.
    ERROR_IPSEC_IKE_QM_DELAY_DROP = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_QM_DELAY_DROP",0x000035F7,"The negotiation took too long.")

    # (0x000035F8) An unknown error occurred.
    ERROR_IPSEC_IKE_ERROR = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_ERROR",0x000035F8,"An unknown error occurred.")

    # (0x000035F9) The certificate revocation check failed.
    ERROR_IPSEC_IKE_CRL_FAILED = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_CRL_FAILED",0x000035F9,"The certificate revocation check failed.")

    # (0x000035FA) Invalid certificate key usage.
    ERROR_IPSEC_IKE_INVALID_KEY_USAGE = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_KEY_USAGE",0x000035FA,"Invalid certificate key usage.")

    # (0x000035FB) Invalid certificate type.
    ERROR_IPSEC_IKE_INVALID_CERT_TYPE = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_CERT_TYPE",0x000035FB,"Invalid certificate type.")

    # (0x000035FC) The IKE negotiation failed because the machine certificate used does not have a private key. IPsec certificates require a private key. Contact your network security administrator about a certificate that has a private key.
    ERROR_IPSEC_IKE_NO_PRIVATE_KEY = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_NO_PRIVATE_KEY",0x000035FC,"The IKE negotiation failed because the machine certificate used does not have a private key. IPsec certificates require a private key. Contact your network security administrator about a certificate that has a private key.")

    # (0x000035FE) There was a failure in the Diffie-Hellman computation.
    ERROR_IPSEC_IKE_DH_FAIL = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_DH_FAIL",0x000035FE,"There was a failure in the Diffie-Hellman computation.")

    # (0x00003600) Invalid header.
    ERROR_IPSEC_IKE_INVALID_HEADER = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_HEADER",0x00003600,"Invalid header.")

    # (0x00003601) No policy configured.
    ERROR_IPSEC_IKE_NO_POLICY = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_NO_POLICY",0x00003601,"No policy configured.")

    # (0x00003602) Failed to verify signature.
    ERROR_IPSEC_IKE_INVALID_SIGNATURE = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_SIGNATURE",0x00003602,"Failed to verify signature.")

    # (0x00003603) Failed to authenticate using Kerberos.
    ERROR_IPSEC_IKE_KERBEROS_ERROR = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_KERBEROS_ERROR",0x00003603,"Failed to authenticate using Kerberos.")

    # (0x00003604) The peer's certificate did not have a public key.
    ERROR_IPSEC_IKE_NO_PUBLIC_KEY = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_NO_PUBLIC_KEY",0x00003604,"The peer's certificate did not have a public key.")

    # (0x00003605) Error processing the error payload.
    ERROR_IPSEC_IKE_PROCESS_ERR = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_PROCESS_ERR",0x00003605,"Error processing the error payload.")

    # (0x00003606) Error processing the SA payload.
    ERROR_IPSEC_IKE_PROCESS_ERR_SA = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_PROCESS_ERR_SA",0x00003606,"Error processing the SA payload.")

    # (0x00003607) Error processing the proposal payload.
    ERROR_IPSEC_IKE_PROCESS_ERR_PROP = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_PROCESS_ERR_PROP",0x00003607,"Error processing the proposal payload.")

    # (0x00003608) Error processing the transform payload.
    ERROR_IPSEC_IKE_PROCESS_ERR_TRANS = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_PROCESS_ERR_TRANS",0x00003608,"Error processing the transform payload.")

    # (0x00003609) Error processing the key exchange payload.
    ERROR_IPSEC_IKE_PROCESS_ERR_KE = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_PROCESS_ERR_KE",0x00003609,"Error processing the key exchange payload.")

    # (0x0000360A) Error processing the ID payload.
    ERROR_IPSEC_IKE_PROCESS_ERR_ID = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_PROCESS_ERR_ID",0x0000360A,"Error processing the ID payload.")

    # (0x0000360B) Error processing the certification payload.
    ERROR_IPSEC_IKE_PROCESS_ERR_CERT = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_PROCESS_ERR_CERT",0x0000360B,"Error processing the certification payload.")

    # (0x0000360C) Error processing the certificate request payload.
    ERROR_IPSEC_IKE_PROCESS_ERR_CERT_REQ = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_PROCESS_ERR_CERT_REQ",0x0000360C,"Error processing the certificate request payload.")

    # (0x0000360D) Error processing the hash payload.
    ERROR_IPSEC_IKE_PROCESS_ERR_HASH = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_PROCESS_ERR_HASH",0x0000360D,"Error processing the hash payload.")

    # (0x0000360E) Error processing the signature payload.
    ERROR_IPSEC_IKE_PROCESS_ERR_SIG = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_PROCESS_ERR_SIG",0x0000360E,"Error processing the signature payload.")

    # (0x0000360F) Error processing the nonce payload.
    ERROR_IPSEC_IKE_PROCESS_ERR_NONCE = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_PROCESS_ERR_NONCE",0x0000360F,"Error processing the nonce payload.")

    # (0x00003610) Error processing the notify payload.
    ERROR_IPSEC_IKE_PROCESS_ERR_NOTIFY = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_PROCESS_ERR_NOTIFY",0x00003610,"Error processing the notify payload.")

    # (0x00003611) Error processing the delete payload.
    ERROR_IPSEC_IKE_PROCESS_ERR_DELETE = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_PROCESS_ERR_DELETE",0x00003611,"Error processing the delete payload.")

    # (0x00003612) Error processing the VendorId payload.
    ERROR_IPSEC_IKE_PROCESS_ERR_VENDOR = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_PROCESS_ERR_VENDOR",0x00003612,"Error processing the VendorId payload.")

    # (0x00003613) Invalid payload received.
    ERROR_IPSEC_IKE_INVALID_PAYLOAD = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_PAYLOAD",0x00003613,"Invalid payload received.")

    # (0x00003614) Soft SA loaded.
    ERROR_IPSEC_IKE_LOAD_SOFT_SA = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_LOAD_SOFT_SA",0x00003614,"Soft SA loaded.")

    # (0x00003615) Soft SA torn down.
    ERROR_IPSEC_IKE_SOFT_SA_TORN_DOWN = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_SOFT_SA_TORN_DOWN",0x00003615,"Soft SA torn down.")

    # (0x00003616) Invalid cookie received.
    ERROR_IPSEC_IKE_INVALID_COOKIE = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_COOKIE",0x00003616,"Invalid cookie received.")

    # (0x00003617) Peer failed to send valid machine certificate.
    ERROR_IPSEC_IKE_NO_PEER_CERT = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_NO_PEER_CERT",0x00003617,"Peer failed to send valid machine certificate.")

    # (0x00003618) Certification revocation check of peer's certificate failed.
    ERROR_IPSEC_IKE_PEER_CRL_FAILED = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_PEER_CRL_FAILED",0x00003618,"Certification revocation check of peer's certificate failed.")

    # (0x00003619) New policy invalidated SAs formed with the old policy.
    ERROR_IPSEC_IKE_POLICY_CHANGE = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_POLICY_CHANGE",0x00003619,"New policy invalidated SAs formed with the old policy.")

    # (0x0000361A) There is no available main mode IKE policy.
    ERROR_IPSEC_IKE_NO_MM_POLICY = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_NO_MM_POLICY",0x0000361A,"There is no available main mode IKE policy.")

    # (0x0000361B) Failed to enabled trusted computer base (TCB) privilege.
    ERROR_IPSEC_IKE_NOTCBPRIV = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_NOTCBPRIV",0x0000361B,"Failed to enabled trusted computer base (TCB) privilege.")

    # (0x0000361C) Failed to load SECURITY.DLL.
    ERROR_IPSEC_IKE_SECLOADFAIL = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_SECLOADFAIL",0x0000361C,"Failed to load SECURITY.DLL.")

    # (0x0000361D) Failed to obtain the security function table dispatch address from the SSPI.
    ERROR_IPSEC_IKE_FAILSSPINIT = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_FAILSSPINIT",0x0000361D,"Failed to obtain the security function table dispatch address from the SSPI.")

    # (0x0000361E) Failed to query the Kerberos package to obtain the max token size.
    ERROR_IPSEC_IKE_FAILQUERYSSP = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_FAILQUERYSSP",0x0000361E,"Failed to query the Kerberos package to obtain the max token size.")

    # (0x0000361F) Failed to obtain the Kerberos server credentials for the Internet Security Association and Key Management Protocol (ISAKMP)/ERROR_IPSEC_IKE service. Kerberos authentication will not function. The most likely reason for this is lack of domain membership. This is normal if your computer is a member of a workgroup.
    ERROR_IPSEC_IKE_SRVACQFAIL = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_SRVACQFAIL",0x0000361F,"Failed to obtain the Kerberos server credentials for the Internet Security Association and Key Management Protocol (ISAKMP)/ERROR_IPSEC_IKE service. Kerberos authentication will not function. The most likely reason for this is lack of domain membership. This is normal if your computer is a member of a workgroup.")

    # (0x00003620) Failed to determine the SSPI principal name for ISAKMP/ERROR_IPSEC_IKE service (QueryCredentialsAttributes).
    ERROR_IPSEC_IKE_SRVQUERYCRED = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_SRVQUERYCRED",0x00003620,"Failed to determine the SSPI principal name for ISAKMP/ERROR_IPSEC_IKE service (QueryCredentialsAttributes).")

    # (0x00003621) Failed to obtain a new service provider interface (SPI) for the inbound SA from the IPsec driver. The most common cause for this is that the driver does not have the correct filter. Check your policy to verify the filters.
    ERROR_IPSEC_IKE_GETSPIFAIL = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_GETSPIFAIL",0x00003621,"Failed to obtain a new service provider interface (SPI) for the inbound SA from the IPsec driver. The most common cause for this is that the driver does not have the correct filter. Check your policy to verify the filters.")

    # (0x00003622) Given filter is invalid.
    ERROR_IPSEC_IKE_INVALID_FILTER = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_FILTER",0x00003622,"Given filter is invalid.")

    # (0x00003623) Memory allocation failed.
    ERROR_IPSEC_IKE_OUT_OF_MEMORY = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_OUT_OF_MEMORY",0x00003623,"Memory allocation failed.")

    # (0x00003624) Failed to add an SA to the IPSec driver. The most common cause for this is if the IKE negotiation took too long to complete. If the problem persists, reduce the load on the faulting machine.
    ERROR_IPSEC_IKE_ADD_UPDATE_KEY_FAILED = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_ADD_UPDATE_KEY_FAILED",0x00003624,"Failed to add an SA to the IPSec driver. The most common cause for this is if the IKE negotiation took too long to complete. If the problem persists, reduce the load on the faulting machine.")

    # (0x00003625) Invalid policy.
    ERROR_IPSEC_IKE_INVALID_POLICY = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_POLICY",0x00003625,"Invalid policy.")

    # (0x00003626) Invalid digital object identifier (DOI).
    ERROR_IPSEC_IKE_UNKNOWN_DOI = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_UNKNOWN_DOI",0x00003626,"Invalid digital object identifier (DOI).")

    # (0x00003627) Invalid situation.
    ERROR_IPSEC_IKE_INVALID_SITUATION = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_SITUATION",0x00003627,"Invalid situation.")

    # (0x00003628) Diffie-Hellman failure.
    ERROR_IPSEC_IKE_DH_FAILURE = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_DH_FAILURE",0x00003628,"Diffie-Hellman failure.")

    # (0x00003629) Invalid Diffie-Hellman group.
    ERROR_IPSEC_IKE_INVALID_GROUP = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_GROUP",0x00003629,"Invalid Diffie-Hellman group.")

    # (0x0000362A) Error encrypting payload.
    ERROR_IPSEC_IKE_ENCRYPT = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_ENCRYPT",0x0000362A,"Error encrypting payload.")

    # (0x0000362B) Error decrypting payload.
    ERROR_IPSEC_IKE_DECRYPT = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_DECRYPT",0x0000362B,"Error decrypting payload.")

    # (0x0000362C) Policy match error.
    ERROR_IPSEC_IKE_POLICY_MATCH = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_POLICY_MATCH",0x0000362C,"Policy match error.")

    # (0x0000362D) Unsupported ID.
    ERROR_IPSEC_IKE_UNSUPPORTED_ID = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_UNSUPPORTED_ID",0x0000362D,"Unsupported ID.")

    # (0x0000362E) Hash verification failed.
    ERROR_IPSEC_IKE_INVALID_HASH = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_HASH",0x0000362E,"Hash verification failed.")

    # (0x0000362F) Invalid hash algorithm.
    ERROR_IPSEC_IKE_INVALID_HASH_ALG = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_HASH_ALG",0x0000362F,"Invalid hash algorithm.")

    # (0x00003630) Invalid hash size.
    ERROR_IPSEC_IKE_INVALID_HASH_SIZE = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_HASH_SIZE",0x00003630,"Invalid hash size.")

    # (0x00003631) Invalid encryption algorithm.
    ERROR_IPSEC_IKE_INVALID_ENCRYPT_ALG = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_ENCRYPT_ALG",0x00003631,"Invalid encryption algorithm.")

    # (0x00003632) Invalid authentication algorithm.
    ERROR_IPSEC_IKE_INVALID_AUTH_ALG = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_AUTH_ALG",0x00003632,"Invalid authentication algorithm.")

    # (0x00003633) Invalid certificate signature.
    ERROR_IPSEC_IKE_INVALID_SIG = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_SIG",0x00003633,"Invalid certificate signature.")

    # (0x00003634) Load failed.
    ERROR_IPSEC_IKE_LOAD_FAILED = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_LOAD_FAILED",0x00003634,"Load failed.")

    # (0x00003635) Deleted by using an RPC call.
    ERROR_IPSEC_IKE_RPC_DELETE = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_RPC_DELETE",0x00003635,"Deleted by using an RPC call.")

    # (0x00003636) A temporary state was created to perform reinitialization. This is not a real failure.
    ERROR_IPSEC_IKE_BENIGN_REINIT = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_BENIGN_REINIT",0x00003636,"A temporary state was created to perform reinitialization. This is not a real failure.")

    # (0x00003637) The lifetime value received in the Responder Lifetime Notify is below the Windows 2000 configured minimum value. Fix the policy on the peer machine.
    ERROR_IPSEC_IKE_INVALID_RESPONDER_LIFETIME_NOTIFY = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_RESPONDER_LIFETIME_NOTIFY",0x00003637,"The lifetime value received in the Responder Lifetime Notify is below the Windows 2000 configured minimum value. Fix the policy on the peer machine.")

    # (0x00003639) Key length in the certificate is too small for configured security requirements.
    ERROR_IPSEC_IKE_INVALID_CERT_KEYLEN = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_CERT_KEYLEN",0x00003639,"Key length in the certificate is too small for configured security requirements.")

    # (0x0000363A) Maximum number of established MM SAs to peer exceeded.
    ERROR_IPSEC_IKE_MM_LIMIT = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_MM_LIMIT",0x0000363A,"Maximum number of established MM SAs to peer exceeded.")

    # (0x0000363B) The IKE received a policy that disables negotiation.
    ERROR_IPSEC_IKE_NEGOTIATION_DISABLED = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_NEGOTIATION_DISABLED",0x0000363B,"The IKE received a policy that disables negotiation.")

    # (0x0000363C) Reached maximum quick mode limit for the main mode. New main mode will be started.
    ERROR_IPSEC_IKE_QM_LIMIT = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_QM_LIMIT",0x0000363C,"Reached maximum quick mode limit for the main mode. New main mode will be started.")

    # (0x0000363D) Main mode SA lifetime expired or the peer sent a main mode delete.
    ERROR_IPSEC_IKE_MM_EXPIRED = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_MM_EXPIRED",0x0000363D,"Main mode SA lifetime expired or the peer sent a main mode delete.")

    # (0x0000363E) Main mode SA assumed to be invalid because peer stopped responding.
    ERROR_IPSEC_IKE_PEER_MM_ASSUMED_INVALID = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_PEER_MM_ASSUMED_INVALID",0x0000363E,"Main mode SA assumed to be invalid because peer stopped responding.")

    # (0x0000363F) Certificate does not chain to a trusted root in IPsec policy.
    ERROR_IPSEC_IKE_CERT_CHAIN_POLICY_MISMATCH = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_CERT_CHAIN_POLICY_MISMATCH",0x0000363F,"Certificate does not chain to a trusted root in IPsec policy.")

    # (0x00003640) Received unexpected message ID.
    ERROR_IPSEC_IKE_UNEXPECTED_MESSAGE_ID = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_UNEXPECTED_MESSAGE_ID",0x00003640,"Received unexpected message ID.")

    # (0x00003641) Received invalid AuthIP user mode attributes.
    ERROR_IPSEC_IKE_INVALID_UMATTS = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_UMATTS",0x00003641,"Received invalid AuthIP user mode attributes.")

    # (0x00003642) Sent DOS cookie notify to initiator.
    ERROR_IPSEC_IKE_DOS_COOKIE_SENT = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_DOS_COOKIE_SENT",0x00003642,"Sent DOS cookie notify to initiator.")

    # (0x00003643) The IKE service is shutting down.
    ERROR_IPSEC_IKE_SHUTTING_DOWN = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_SHUTTING_DOWN",0x00003643,"The IKE service is shutting down.")

    # (0x00003644) Could not verify the binding between the color graphics adapter (CGA) address and the certificate.
    ERROR_IPSEC_IKE_CGA_AUTH_FAILED = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_CGA_AUTH_FAILED",0x00003644,"Could not verify the binding between the color graphics adapter (CGA) address and the certificate.")

    # (0x00003645) Error processing the NatOA payload.
    ERROR_IPSEC_IKE_PROCESS_ERR_NATOA = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_PROCESS_ERR_NATOA",0x00003645,"Error processing the NatOA payload.")

    # (0x00003646) The parameters of the main mode are invalid for this quick mode.
    ERROR_IPSEC_IKE_INVALID_MM_FOR_QM = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_INVALID_MM_FOR_QM",0x00003646,"The parameters of the main mode are invalid for this quick mode.")

    # (0x00003647) The quick mode SA was expired by the IPsec driver.
    ERROR_IPSEC_IKE_QM_EXPIRED = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_QM_EXPIRED",0x00003647,"The quick mode SA was expired by the IPsec driver.")

    # (0x00003648) Too many dynamically added IKEEXT filters were detected.
    ERROR_IPSEC_IKE_TOO_MANY_FILTERS = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_TOO_MANY_FILTERS",0x00003648,"Too many dynamically added IKEEXT filters were detected.")

    # (0x00003649) Ends the list of frequencies of various IKE Win32 error codes encountered during negotiations.
    ERROR_IPSEC_IKE_NEG_STATUS_END = WindowsError::ErrorCode.new("ERROR_IPSEC_IKE_NEG_STATUS_END",0x00003649,"Ends the list of frequencies of various IKE Win32 error codes encountered during negotiations.")

    # (0x000036B0) The requested section was not present in the activation context.
    ERROR_SXS_SECTION_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_SXS_SECTION_NOT_FOUND",0x000036B0,"The requested section was not present in the activation context.")

    # (0x000036B1) The application has failed to start because its side-by-side configuration is incorrect. See the application event log for more detail.
    ERROR_SXS_CANT_GEN_ACTCTX = WindowsError::ErrorCode.new("ERROR_SXS_CANT_GEN_ACTCTX",0x000036B1,"The application has failed to start because its side-by-side configuration is incorrect. See the application event log for more detail.")

    # (0x000036B2) The application binding data format is invalid.
    ERROR_SXS_INVALID_ACTCTXDATA_FORMAT = WindowsError::ErrorCode.new("ERROR_SXS_INVALID_ACTCTXDATA_FORMAT",0x000036B2,"The application binding data format is invalid.")

    # (0x000036B3) The referenced assembly is not installed on your system.
    ERROR_SXS_ASSEMBLY_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_SXS_ASSEMBLY_NOT_FOUND",0x000036B3,"The referenced assembly is not installed on your system.")

    # (0x000036B4) The manifest file does not begin with the required tag and format information.
    ERROR_SXS_MANIFEST_FORMAT_ERROR = WindowsError::ErrorCode.new("ERROR_SXS_MANIFEST_FORMAT_ERROR",0x000036B4,"The manifest file does not begin with the required tag and format information.")

    # (0x000036B5) The manifest file contains one or more syntax errors.
    ERROR_SXS_MANIFEST_PARSE_ERROR = WindowsError::ErrorCode.new("ERROR_SXS_MANIFEST_PARSE_ERROR",0x000036B5,"The manifest file contains one or more syntax errors.")

    # (0x000036B6) The application attempted to activate a disabled activation context.
    ERROR_SXS_ACTIVATION_CONTEXT_DISABLED = WindowsError::ErrorCode.new("ERROR_SXS_ACTIVATION_CONTEXT_DISABLED",0x000036B6,"The application attempted to activate a disabled activation context.")

    # (0x000036B7) The requested lookup key was not found in any active activation context.
    ERROR_SXS_KEY_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_SXS_KEY_NOT_FOUND",0x000036B7,"The requested lookup key was not found in any active activation context.")

    # (0x000036B8) A component version required by the application conflicts with another active component version.
    ERROR_SXS_VERSION_CONFLICT = WindowsError::ErrorCode.new("ERROR_SXS_VERSION_CONFLICT",0x000036B8,"A component version required by the application conflicts with another active component version.")

    # (0x000036B9) The type requested activation context section does not match the query API used.
    ERROR_SXS_WRONG_SECTION_TYPE = WindowsError::ErrorCode.new("ERROR_SXS_WRONG_SECTION_TYPE",0x000036B9,"The type requested activation context section does not match the query API used.")

    # (0x000036BA) Lack of system resources has required isolated activation to be disabled for the current thread of execution.
    ERROR_SXS_THREAD_QUERIES_DISABLED = WindowsError::ErrorCode.new("ERROR_SXS_THREAD_QUERIES_DISABLED",0x000036BA,"Lack of system resources has required isolated activation to be disabled for the current thread of execution.")

    # (0x000036BB) An attempt to set the process default activation context failed because the process default activation context was already set.
    ERROR_SXS_PROCESS_DEFAULT_ALREADY_SET = WindowsError::ErrorCode.new("ERROR_SXS_PROCESS_DEFAULT_ALREADY_SET",0x000036BB,"An attempt to set the process default activation context failed because the process default activation context was already set.")

    # (0x000036BC) The encoding group identifier specified is not recognized.
    ERROR_SXS_UNKNOWN_ENCODING_GROUP = WindowsError::ErrorCode.new("ERROR_SXS_UNKNOWN_ENCODING_GROUP",0x000036BC,"The encoding group identifier specified is not recognized.")

    # (0x000036BD) The encoding requested is not recognized.
    ERROR_SXS_UNKNOWN_ENCODING = WindowsError::ErrorCode.new("ERROR_SXS_UNKNOWN_ENCODING",0x000036BD,"The encoding requested is not recognized.")

    # (0x000036BE) The manifest contains a reference to an invalid URI.
    ERROR_SXS_INVALID_XML_NAMESPACE_URI = WindowsError::ErrorCode.new("ERROR_SXS_INVALID_XML_NAMESPACE_URI",0x000036BE,"The manifest contains a reference to an invalid URI.")

    # (0x000036BF) The application manifest contains a reference to a dependent assembly that is not installed.
    ERROR_SXS_ROOT_MANIFEST_DEPENDENCY_OT_INSTALLED = WindowsError::ErrorCode.new("ERROR_SXS_ROOT_MANIFEST_DEPENDENCY_OT_INSTALLED",0x000036BF,"The application manifest contains a reference to a dependent assembly that is not installed.")

    # (0x000036C0) The manifest for an assembly used by the application has a reference to a dependent assembly that is not installed.
    ERROR_SXS_LEAF_MANIFEST_DEPENDENCY_NOT_INSTALLED = WindowsError::ErrorCode.new("ERROR_SXS_LEAF_MANIFEST_DEPENDENCY_NOT_INSTALLED",0x000036C0,"The manifest for an assembly used by the application has a reference to a dependent assembly that is not installed.")

    # (0x000036C1) The manifest contains an attribute for the assembly identity that is not valid.
    ERROR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE = WindowsError::ErrorCode.new("ERROR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE",0x000036C1,"The manifest contains an attribute for the assembly identity that is not valid.")

    # (0x000036C2) The manifest is missing the required default namespace specification on the assembly element.
    ERROR_SXS_MANIFEST_MISSING_REQUIRED_DEFAULT_NAMESPACE = WindowsError::ErrorCode.new("ERROR_SXS_MANIFEST_MISSING_REQUIRED_DEFAULT_NAMESPACE",0x000036C2,"The manifest is missing the required default namespace specification on the assembly element.")

    # (0x000036C3) The manifest has a default namespace specified on the assembly element but its value is not urn:schemas-microsoft-com:asm.v1"."
    ERROR_SXS_MANIFEST_INVALID_REQUIRED_DEFAULT_NAMESPACE = WindowsError::ErrorCode.new("ERROR_SXS_MANIFEST_INVALID_REQUIRED_DEFAULT_NAMESPACE",0x000036C3,"The manifest has a default namespace specified on the assembly element but its value is not urn:schemas-microsoft-com:asm.v1\".\"")

    # (0x000036C4) The private manifest probed has crossed the reparse-point-associated path.
    ERROR_SXS_PRIVATE_MANIFEST_CROSS_PATH_WITH_REPARSE_POINT = WindowsError::ErrorCode.new("ERROR_SXS_PRIVATE_MANIFEST_CROSS_PATH_WITH_REPARSE_POINT",0x000036C4,"The private manifest probed has crossed the reparse-point-associated path.")

    # (0x000036C5) Two or more components referenced directly or indirectly by the application manifest have files by the same name.
    ERROR_SXS_DUPLICATE_DLL_NAME = WindowsError::ErrorCode.new("ERROR_SXS_DUPLICATE_DLL_NAME",0x000036C5,"Two or more components referenced directly or indirectly by the application manifest have files by the same name.")

    # (0x000036C6) Two or more components referenced directly or indirectly by the application manifest have window classes with the same name.
    ERROR_SXS_DUPLICATE_WINDOWCLASS_NAME = WindowsError::ErrorCode.new("ERROR_SXS_DUPLICATE_WINDOWCLASS_NAME",0x000036C6,"Two or more components referenced directly or indirectly by the application manifest have window classes with the same name.")

    # (0x000036C7) Two or more components referenced directly or indirectly by the application manifest have the same COM server CLSIDs.
    ERROR_SXS_DUPLICATE_CLSID = WindowsError::ErrorCode.new("ERROR_SXS_DUPLICATE_CLSID",0x000036C7,"Two or more components referenced directly or indirectly by the application manifest have the same COM server CLSIDs.")

    # (0x000036C8) Two or more components referenced directly or indirectly by the application manifest have proxies for the same COM interface IIDs.
    ERROR_SXS_DUPLICATE_IID = WindowsError::ErrorCode.new("ERROR_SXS_DUPLICATE_IID",0x000036C8,"Two or more components referenced directly or indirectly by the application manifest have proxies for the same COM interface IIDs.")

    # (0x000036C9) Two or more components referenced directly or indirectly by the application manifest have the same COM type library TLBIDs.
    ERROR_SXS_DUPLICATE_TLBID = WindowsError::ErrorCode.new("ERROR_SXS_DUPLICATE_TLBID",0x000036C9,"Two or more components referenced directly or indirectly by the application manifest have the same COM type library TLBIDs.")

    # (0x000036CA) Two or more components referenced directly or indirectly by the application manifest have the same COM ProgIDs.
    ERROR_SXS_DUPLICATE_PROGID = WindowsError::ErrorCode.new("ERROR_SXS_DUPLICATE_PROGID",0x000036CA,"Two or more components referenced directly or indirectly by the application manifest have the same COM ProgIDs.")

    # (0x000036CB) Two or more components referenced directly or indirectly by the application manifest are different versions of the same component, which is not permitted.
    ERROR_SXS_DUPLICATE_ASSEMBLY_NAME = WindowsError::ErrorCode.new("ERROR_SXS_DUPLICATE_ASSEMBLY_NAME",0x000036CB,"Two or more components referenced directly or indirectly by the application manifest are different versions of the same component, which is not permitted.")

    # (0x000036CC) A component's file does not match the verification information present in the component manifest.
    ERROR_SXS_FILE_HASH_MISMATCH = WindowsError::ErrorCode.new("ERROR_SXS_FILE_HASH_MISMATCH",0x000036CC,"A component's file does not match the verification information present in the component manifest.")

    # (0x000036CD) The policy manifest contains one or more syntax errors.
    ERROR_SXS_POLICY_PARSE_ERROR = WindowsError::ErrorCode.new("ERROR_SXS_POLICY_PARSE_ERROR",0x000036CD,"The policy manifest contains one or more syntax errors.")

    # (0x000036CE) Manifest Parse Error: A string literal was expected, but no opening quotation mark was found.
    ERROR_SXS_XML_E_MISSINGQUOTE = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_MISSINGQUOTE",0x000036CE,"Manifest Parse Error: A string literal was expected, but no opening quotation mark was found.")

    # (0x000036CF) Manifest Parse Error: Incorrect syntax was used in a comment.
    ERROR_SXS_XML_E_COMMENTSYNTAX = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_COMMENTSYNTAX",0x000036CF,"Manifest Parse Error: Incorrect syntax was used in a comment.")

    # (0x000036D0) Manifest Parse Error: A name started with an invalid character.
    ERROR_SXS_XML_E_BADSTARTNAMECHAR = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_BADSTARTNAMECHAR",0x000036D0,"Manifest Parse Error: A name started with an invalid character.")

    # (0x000036D1) Manifest Parse Error: A name contained an invalid character.
    ERROR_SXS_XML_E_BADNAMECHAR = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_BADNAMECHAR",0x000036D1,"Manifest Parse Error: A name contained an invalid character.")

    # (0x000036D2) Manifest Parse Error: A string literal contained an invalid character.
    ERROR_SXS_XML_E_BADCHARINSTRING = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_BADCHARINSTRING",0x000036D2,"Manifest Parse Error: A string literal contained an invalid character.")

    # (0x000036D3) Manifest Parse Error: Invalid syntax for an XML declaration.
    ERROR_SXS_XML_E_XMLDECLSYNTAX = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_XMLDECLSYNTAX",0x000036D3,"Manifest Parse Error: Invalid syntax for an XML declaration.")

    # (0x000036D4) Manifest Parse Error: An Invalid character was found in text content.
    ERROR_SXS_XML_E_BADCHARDATA = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_BADCHARDATA",0x000036D4,"Manifest Parse Error: An Invalid character was found in text content.")

    # (0x000036D5) Manifest Parse Error: Required white space was missing.
    ERROR_SXS_XML_E_MISSINGWHITESPACE = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_MISSINGWHITESPACE",0x000036D5,"Manifest Parse Error: Required white space was missing.")

    # (0x000036D6) Manifest Parse Error: The angle bracket (>) character was expected.
    ERROR_SXS_XML_E_EXPECTINGTAGEND = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_EXPECTINGTAGEND",0x000036D6,"Manifest Parse Error: The angle bracket (>) character was expected.")

    # (0x000036D7) Manifest Parse Error: A semicolon (;) was expected.
    ERROR_SXS_XML_E_MISSINGSEMICOLON = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_MISSINGSEMICOLON",0x000036D7,"Manifest Parse Error: A semicolon (;) was expected.")

    # (0x000036D8) Manifest Parse Error: Unbalanced parentheses.
    ERROR_SXS_XML_E_UNBALANCEDPAREN = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_UNBALANCEDPAREN",0x000036D8,"Manifest Parse Error: Unbalanced parentheses.")

    # (0x000036D9) Manifest Parse Error: Internal error.
    ERROR_SXS_XML_E_INTERNALERROR = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_INTERNALERROR",0x000036D9,"Manifest Parse Error: Internal error.")

    # (0x000036DA) Manifest Parse Error: Whitespace is not allowed at this location.
    ERROR_SXS_XML_E_UNEXPECTED_WHITESPACE = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_UNEXPECTED_WHITESPACE",0x000036DA,"Manifest Parse Error: Whitespace is not allowed at this location.")

    # (0x000036DB) Manifest Parse Error: End of file reached in invalid state for current encoding.
    ERROR_SXS_XML_E_INCOMPLETE_ENCODING = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_INCOMPLETE_ENCODING",0x000036DB,"Manifest Parse Error: End of file reached in invalid state for current encoding.")

    # (0x000036DC) Manifest Parse Error: Missing parenthesis.
    ERROR_SXS_XML_E_MISSING_PAREN = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_MISSING_PAREN",0x000036DC,"Manifest Parse Error: Missing parenthesis.")

    # (0x000036DD) Manifest Parse Error: A single (') or double (") quotation mark is missing.
    ERROR_SXS_XML_E_EXPECTINGCLOSEQUOTE = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_EXPECTINGCLOSEQUOTE",0x000036DD,"Manifest Parse Error: A single (') or double (\") quotation mark is missing.")

    # (0x000036DE) Manifest Parse Error: Multiple colons are not allowed in a name.
    ERROR_SXS_XML_E_MULTIPLE_COLONS = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_MULTIPLE_COLONS",0x000036DE,"Manifest Parse Error: Multiple colons are not allowed in a name.")

    # (0x000036DF) Manifest Parse Error: Invalid character for decimal digit.
    ERROR_SXS_XML_E_INVALID_DECIMAL = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_INVALID_DECIMAL",0x000036DF,"Manifest Parse Error: Invalid character for decimal digit.")

    # (0x000036E0) Manifest Parse Error: Invalid character for hexadecimal digit.
    ERROR_SXS_XML_E_INVALID_HEXIDECIMAL = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_INVALID_HEXIDECIMAL",0x000036E0,"Manifest Parse Error: Invalid character for hexadecimal digit.")

    # (0x000036E1) Manifest Parse Error: Invalid Unicode character value for this platform.
    ERROR_SXS_XML_E_INVALID_UNICODE = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_INVALID_UNICODE",0x000036E1,"Manifest Parse Error: Invalid Unicode character value for this platform.")

    # (0x000036E2) Manifest Parse Error: Expecting whitespace or question mark (?).
    ERROR_SXS_XML_E_WHITESPACEORQUESTIONMARK = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_WHITESPACEORQUESTIONMARK",0x000036E2,"Manifest Parse Error: Expecting whitespace or question mark (?).")

    # (0x000036E3) Manifest Parse Error: End tag was not expected at this location.
    ERROR_SXS_XML_E_UNEXPECTEDENDTAG = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_UNEXPECTEDENDTAG",0x000036E3,"Manifest Parse Error: End tag was not expected at this location.")

    # (0x000036E4) Manifest Parse Error: The following tags were not closed: %1.
    ERROR_SXS_XML_E_UNCLOSEDTAG = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_UNCLOSEDTAG",0x000036E4,"Manifest Parse Error: The following tags were not closed: %1.")

    # (0x000036E5) Manifest Parse Error: Duplicate attribute.
    ERROR_SXS_XML_E_DUPLICATEATTRIBUTE = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_DUPLICATEATTRIBUTE",0x000036E5,"Manifest Parse Error: Duplicate attribute.")

    # (0x000036E6) Manifest Parse Error: Only one top-level element is allowed in an XML document.
    ERROR_SXS_XML_E_MULTIPLEROOTS = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_MULTIPLEROOTS",0x000036E6,"Manifest Parse Error: Only one top-level element is allowed in an XML document.")

    # (0x000036E7) Manifest Parse Error: Invalid at the top level of the document.
    ERROR_SXS_XML_E_INVALIDATROOTLEVEL = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_INVALIDATROOTLEVEL",0x000036E7,"Manifest Parse Error: Invalid at the top level of the document.")

    # (0x000036E8) Manifest Parse Error: Invalid XML declaration.
    ERROR_SXS_XML_E_BADXMLDECL = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_BADXMLDECL",0x000036E8,"Manifest Parse Error: Invalid XML declaration.")

    # (0x000036E9) Manifest Parse Error: XML document must have a top-level element.
    ERROR_SXS_XML_E_MISSINGROOT = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_MISSINGROOT",0x000036E9,"Manifest Parse Error: XML document must have a top-level element.")

    # (0x000036EA) Manifest Parse Error: Unexpected end of file.
    ERROR_SXS_XML_E_UNEXPECTEDEOF = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_UNEXPECTEDEOF",0x000036EA,"Manifest Parse Error: Unexpected end of file.")

    # (0x000036EB) Manifest Parse Error: Parameter entities cannot be used inside markup declarations in an internal subset.
    ERROR_SXS_XML_E_BADPEREFINSUBSET = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_BADPEREFINSUBSET",0x000036EB,"Manifest Parse Error: Parameter entities cannot be used inside markup declarations in an internal subset.")

    # (0x000036EC) Manifest Parse Error: Element was not closed.
    ERROR_SXS_XML_E_UNCLOSEDSTARTTAG = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_UNCLOSEDSTARTTAG",0x000036EC,"Manifest Parse Error: Element was not closed.")

    # (0x000036ED) Manifest Parse Error: End element was missing the angle bracket (>) character.
    ERROR_SXS_XML_E_UNCLOSEDENDTAG = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_UNCLOSEDENDTAG",0x000036ED,"Manifest Parse Error: End element was missing the angle bracket (>) character.")

    # (0x000036EE) Manifest Parse Error: A string literal was not closed.
    ERROR_SXS_XML_E_UNCLOSEDSTRING = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_UNCLOSEDSTRING",0x000036EE,"Manifest Parse Error: A string literal was not closed.")

    # (0x000036EF) Manifest Parse Error: A comment was not closed.
    ERROR_SXS_XML_E_UNCLOSEDCOMMENT = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_UNCLOSEDCOMMENT",0x000036EF,"Manifest Parse Error: A comment was not closed.")

    # (0x000036F0) Manifest Parse Error: A declaration was not closed.
    ERROR_SXS_XML_E_UNCLOSEDDECL = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_UNCLOSEDDECL",0x000036F0,"Manifest Parse Error: A declaration was not closed.")

    # (0x000036F1) Manifest Parse Error: A CDATA section was not closed.
    ERROR_SXS_XML_E_UNCLOSEDCDATA = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_UNCLOSEDCDATA",0x000036F1,"Manifest Parse Error: A CDATA section was not closed.")

    # (0x000036F2) Manifest Parse Error: The namespace prefix is not allowed to start with the reserved string xml"."
    ERROR_SXS_XML_E_RESERVEDNAMESPACE = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_RESERVEDNAMESPACE",0x000036F2,"Manifest Parse Error: The namespace prefix is not allowed to start with the reserved string xml\".\"")

    # (0x000036F3) Manifest Parse Error: System does not support the specified encoding.
    ERROR_SXS_XML_E_INVALIDENCODING = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_INVALIDENCODING",0x000036F3,"Manifest Parse Error: System does not support the specified encoding.")

    # (0x000036F4) Manifest Parse Error: Switch from current encoding to specified encoding not supported.
    ERROR_SXS_XML_E_INVALIDSWITCH = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_INVALIDSWITCH",0x000036F4,"Manifest Parse Error: Switch from current encoding to specified encoding not supported.")

    # (0x000036F5) Manifest Parse Error: The name "xml" is reserved and must be lowercase.
    ERROR_SXS_XML_E_BADXMLCASE = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_BADXMLCASE",0x000036F5,"Manifest Parse Error: The name \"xml\" is reserved and must be lowercase.")

    # (0x000036F6) Manifest Parse Error: The stand-alone attribute must have the value "yes" or "no".
    ERROR_SXS_XML_E_INVALID_STANDALONE = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_INVALID_STANDALONE",0x000036F6,"Manifest Parse Error: The stand-alone attribute must have the value \"yes\" or \"no\".")

    # (0x000036F7) Manifest Parse Error: The stand-alone attribute cannot be used in external entities.
    ERROR_SXS_XML_E_UNEXPECTED_STANDALONE = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_UNEXPECTED_STANDALONE",0x000036F7,"Manifest Parse Error: The stand-alone attribute cannot be used in external entities.")

    # (0x000036F8) Manifest Parse Error: Invalid version number.
    ERROR_SXS_XML_E_INVALID_VERSION = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_INVALID_VERSION",0x000036F8,"Manifest Parse Error: Invalid version number.")

    # (0x000036F9) Manifest Parse Error: Missing equal sign (=) between the attribute and the attribute value.
    ERROR_SXS_XML_E_MISSINGEQUALS = WindowsError::ErrorCode.new("ERROR_SXS_XML_E_MISSINGEQUALS",0x000036F9,"Manifest Parse Error: Missing equal sign (=) between the attribute and the attribute value.")

    # (0x000036FA) Assembly Protection Error: Unable to recover the specified assembly.
    ERROR_SXS_PROTECTION_RECOVERY_FAILED = WindowsError::ErrorCode.new("ERROR_SXS_PROTECTION_RECOVERY_FAILED",0x000036FA,"Assembly Protection Error: Unable to recover the specified assembly.")

    # (0x000036FB) Assembly Protection Error: The public key for an assembly was too short to be allowed.
    ERROR_SXS_PROTECTION_PUBLIC_KEY_OO_SHORT = WindowsError::ErrorCode.new("ERROR_SXS_PROTECTION_PUBLIC_KEY_OO_SHORT",0x000036FB,"Assembly Protection Error: The public key for an assembly was too short to be allowed.")

    # (0x000036FC) Assembly Protection Error: The catalog for an assembly is not valid, or does not match the assembly's manifest.
    ERROR_SXS_PROTECTION_CATALOG_NOT_VALID = WindowsError::ErrorCode.new("ERROR_SXS_PROTECTION_CATALOG_NOT_VALID",0x000036FC,"Assembly Protection Error: The catalog for an assembly is not valid, or does not match the assembly's manifest.")

    # (0x000036FD) An HRESULT could not be translated to a corresponding Win32 error code.
    ERROR_SXS_UNTRANSLATABLE_HRESULT = WindowsError::ErrorCode.new("ERROR_SXS_UNTRANSLATABLE_HRESULT",0x000036FD,"An HRESULT could not be translated to a corresponding Win32 error code.")

    # (0x000036FE) Assembly Protection Error: The catalog for an assembly is missing.
    ERROR_SXS_PROTECTION_CATALOG_FILE_MISSING = WindowsError::ErrorCode.new("ERROR_SXS_PROTECTION_CATALOG_FILE_MISSING",0x000036FE,"Assembly Protection Error: The catalog for an assembly is missing.")

    # (0x000036FF) The supplied assembly identity is missing one or more attributes that must be present in this context.
    ERROR_SXS_MISSING_ASSEMBLY_IDENTITY_ATTRIBUTE = WindowsError::ErrorCode.new("ERROR_SXS_MISSING_ASSEMBLY_IDENTITY_ATTRIBUTE",0x000036FF,"The supplied assembly identity is missing one or more attributes that must be present in this context.")

    # (0x00003700) The supplied assembly identity has one or more attribute names that contain characters not permitted in XML names.
    ERROR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE_NAME = WindowsError::ErrorCode.new("ERROR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE_NAME",0x00003700,"The supplied assembly identity has one or more attribute names that contain characters not permitted in XML names.")

    # (0x00003701) The referenced assembly could not be found.
    ERROR_SXS_ASSEMBLY_MISSING = WindowsError::ErrorCode.new("ERROR_SXS_ASSEMBLY_MISSING",0x00003701,"The referenced assembly could not be found.")

    # (0x00003702) The activation context activation stack for the running thread of execution is corrupt.
    ERROR_SXS_CORRUPT_ACTIVATION_STACK = WindowsError::ErrorCode.new("ERROR_SXS_CORRUPT_ACTIVATION_STACK",0x00003702,"The activation context activation stack for the running thread of execution is corrupt.")

    # (0x00003703) The application isolation metadata for this process or thread has become corrupt.
    ERROR_SXS_CORRUPTION = WindowsError::ErrorCode.new("ERROR_SXS_CORRUPTION",0x00003703,"The application isolation metadata for this process or thread has become corrupt.")

    # (0x00003704) The activation context being deactivated is not the most recently activated one.
    ERROR_SXS_EARLY_DEACTIVATION = WindowsError::ErrorCode.new("ERROR_SXS_EARLY_DEACTIVATION",0x00003704,"The activation context being deactivated is not the most recently activated one.")

    # (0x00003705) The activation context being deactivated is not active for the current thread of execution.
    ERROR_SXS_INVALID_DEACTIVATION = WindowsError::ErrorCode.new("ERROR_SXS_INVALID_DEACTIVATION",0x00003705,"The activation context being deactivated is not active for the current thread of execution.")

    # (0x00003706) The activation context being deactivated has already been deactivated.
    ERROR_SXS_MULTIPLE_DEACTIVATION = WindowsError::ErrorCode.new("ERROR_SXS_MULTIPLE_DEACTIVATION",0x00003706,"The activation context being deactivated has already been deactivated.")

    # (0x00003707) A component used by the isolation facility has requested to terminate the process.
    ERROR_SXS_PROCESS_TERMINATION_REQUESTED = WindowsError::ErrorCode.new("ERROR_SXS_PROCESS_TERMINATION_REQUESTED",0x00003707,"A component used by the isolation facility has requested to terminate the process.")

    # (0x00003708) A kernel mode component is releasing a reference on an activation context.
    ERROR_SXS_RELEASE_ACTIVATION_ONTEXT = WindowsError::ErrorCode.new("ERROR_SXS_RELEASE_ACTIVATION_ONTEXT",0x00003708,"A kernel mode component is releasing a reference on an activation context.")

    # (0x00003709) The activation context of the system default assembly could not be generated.
    ERROR_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY = WindowsError::ErrorCode.new("ERROR_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY",0x00003709,"The activation context of the system default assembly could not be generated.")

    # (0x0000370A) The value of an attribute in an identity is not within the legal range.
    ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE = WindowsError::ErrorCode.new("ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE",0x0000370A,"The value of an attribute in an identity is not within the legal range.")

    # (0x0000370B) The name of an attribute in an identity is not within the legal range.
    ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME = WindowsError::ErrorCode.new("ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME",0x0000370B,"The name of an attribute in an identity is not within the legal range.")

    # (0x0000370C) An identity contains two definitions for the same attribute.
    ERROR_SXS_IDENTITY_DUPLICATE_ATTRIBUTE = WindowsError::ErrorCode.new("ERROR_SXS_IDENTITY_DUPLICATE_ATTRIBUTE",0x0000370C,"An identity contains two definitions for the same attribute.")

    # (0x0000370D) The identity string is malformed. This may be due to a trailing comma, more than two unnamed attributes, a missing attribute name, or a missing attribute value.
    ERROR_SXS_IDENTITY_PARSE_ERROR = WindowsError::ErrorCode.new("ERROR_SXS_IDENTITY_PARSE_ERROR",0x0000370D,"The identity string is malformed. This may be due to a trailing comma, more than two unnamed attributes, a missing attribute name, or a missing attribute value.")

    # (0x0000370E) A string containing localized substitutable content was malformed. Either a dollar sign ($) was followed by something other than a left parenthesis or another dollar sign, or a substitution's right parenthesis was not found.
    ERROR_MALFORMED_SUBSTITUTION_STRING = WindowsError::ErrorCode.new("ERROR_MALFORMED_SUBSTITUTION_STRING",0x0000370E,"A string containing localized substitutable content was malformed. Either a dollar sign ($) was followed by something other than a left parenthesis or another dollar sign, or a substitution's right parenthesis was not found.")

    # (0x0000370F) The public key token does not correspond to the public key specified.
    ERROR_SXS_INCORRECT_PUBLIC_KEY_OKEN = WindowsError::ErrorCode.new("ERROR_SXS_INCORRECT_PUBLIC_KEY_OKEN",0x0000370F,"The public key token does not correspond to the public key specified.")

    # (0x00003710) A substitution string had no mapping.
    ERROR_UNMAPPED_SUBSTITUTION_STRING = WindowsError::ErrorCode.new("ERROR_UNMAPPED_SUBSTITUTION_STRING",0x00003710,"A substitution string had no mapping.")

    # (0x00003711) The component must be locked before making the request.
    ERROR_SXS_ASSEMBLY_NOT_LOCKED = WindowsError::ErrorCode.new("ERROR_SXS_ASSEMBLY_NOT_LOCKED",0x00003711,"The component must be locked before making the request.")

    # (0x00003712) The component store has been corrupted.
    ERROR_SXS_COMPONENT_STORE_CORRUPT = WindowsError::ErrorCode.new("ERROR_SXS_COMPONENT_STORE_CORRUPT",0x00003712,"The component store has been corrupted.")

    # (0x00003713) An advanced installer failed during setup or servicing.
    ERROR_ADVANCED_INSTALLER_FAILED = WindowsError::ErrorCode.new("ERROR_ADVANCED_INSTALLER_FAILED",0x00003713,"An advanced installer failed during setup or servicing.")

    # (0x00003714) The character encoding in the XML declaration did not match the encoding used in the document.
    ERROR_XML_ENCODING_MISMATCH = WindowsError::ErrorCode.new("ERROR_XML_ENCODING_MISMATCH",0x00003714,"The character encoding in the XML declaration did not match the encoding used in the document.")

    # (0x00003715) The identities of the manifests are identical, but the contents are different.
    ERROR_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT = WindowsError::ErrorCode.new("ERROR_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT",0x00003715,"The identities of the manifests are identical, but the contents are different.")

    # (0x00003716) The component identities are different.
    ERROR_SXS_IDENTITIES_DIFFERENT = WindowsError::ErrorCode.new("ERROR_SXS_IDENTITIES_DIFFERENT",0x00003716,"The component identities are different.")

    # (0x00003717) The assembly is not a deployment.
    ERROR_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT = WindowsError::ErrorCode.new("ERROR_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT",0x00003717,"The assembly is not a deployment.")

    # (0x00003718) The file is not a part of the assembly.
    ERROR_SXS_FILE_NOT_PART_OF_ASSEMBLY = WindowsError::ErrorCode.new("ERROR_SXS_FILE_NOT_PART_OF_ASSEMBLY",0x00003718,"The file is not a part of the assembly.")

    # (0x00003719) The size of the manifest exceeds the maximum allowed.
    ERROR_SXS_MANIFEST_TOO_BIG = WindowsError::ErrorCode.new("ERROR_SXS_MANIFEST_TOO_BIG",0x00003719,"The size of the manifest exceeds the maximum allowed.")

    # (0x0000371A) The setting is not registered.
    ERROR_SXS_SETTING_NOT_REGISTERED = WindowsError::ErrorCode.new("ERROR_SXS_SETTING_NOT_REGISTERED",0x0000371A,"The setting is not registered.")

    # (0x0000371B) One or more required members of the transaction are not present.
    ERROR_SXS_TRANSACTION_CLOSURE_INCOMPLETE = WindowsError::ErrorCode.new("ERROR_SXS_TRANSACTION_CLOSURE_INCOMPLETE",0x0000371B,"One or more required members of the transaction are not present.")

    # (0x00003A98) The specified channel path is invalid.
    ERROR_EVT_INVALID_CHANNEL_PATH = WindowsError::ErrorCode.new("ERROR_EVT_INVALID_CHANNEL_PATH",0x00003A98,"The specified channel path is invalid.")

    # (0x00003A99) The specified query is invalid.
    ERROR_EVT_INVALID_QUERY = WindowsError::ErrorCode.new("ERROR_EVT_INVALID_QUERY",0x00003A99,"The specified query is invalid.")

    # (0x00003A9A) The publisher metadata cannot be found in the resource.
    ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND",0x00003A9A,"The publisher metadata cannot be found in the resource.")

    # (0x00003A9B) The template for an event definition cannot be found in the resource (error = %1).
    ERROR_EVT_EVENT_TEMPLATE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_EVT_EVENT_TEMPLATE_NOT_FOUND",0x00003A9B,"The template for an event definition cannot be found in the resource (error = %1).")

    # (0x00003A9C) The specified publisher name is invalid.
    ERROR_EVT_INVALID_PUBLISHER_NAME = WindowsError::ErrorCode.new("ERROR_EVT_INVALID_PUBLISHER_NAME",0x00003A9C,"The specified publisher name is invalid.")

    # (0x00003A9D) The event data raised by the publisher is not compatible with the event template definition in the publisher's manifest.
    ERROR_EVT_INVALID_EVENT_DATA = WindowsError::ErrorCode.new("ERROR_EVT_INVALID_EVENT_DATA",0x00003A9D,"The event data raised by the publisher is not compatible with the event template definition in the publisher's manifest.")

    # (0x00003A9F) The specified channel could not be found. Check channel configuration.
    ERROR_EVT_CHANNEL_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_EVT_CHANNEL_NOT_FOUND",0x00003A9F,"The specified channel could not be found. Check channel configuration.")

    # (0x00003AA0) The specified XML text was not well-formed. See extended error for more details.
    ERROR_EVT_MALFORMED_XML_TEXT = WindowsError::ErrorCode.new("ERROR_EVT_MALFORMED_XML_TEXT",0x00003AA0,"The specified XML text was not well-formed. See extended error for more details.")

    # (0x00003AA1) The caller is trying to subscribe to a direct channel which is not allowed. The events for a direct channel go directly to a log file and cannot be subscribed to.
    ERROR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL = WindowsError::ErrorCode.new("ERROR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL",0x00003AA1,"The caller is trying to subscribe to a direct channel which is not allowed. The events for a direct channel go directly to a log file and cannot be subscribed to.")

    # (0x00003AA2) Configuration error.
    ERROR_EVT_CONFIGURATION_ERROR = WindowsError::ErrorCode.new("ERROR_EVT_CONFIGURATION_ERROR",0x00003AA2,"Configuration error.")

    # (0x00003AA3) The query result is stale or invalid. This may be due to the log being cleared or rolling over after the query result was created. Users should handle this code by releasing the query result object and reissuing the query.
    ERROR_EVT_QUERY_RESULT_STALE = WindowsError::ErrorCode.new("ERROR_EVT_QUERY_RESULT_STALE",0x00003AA3,"The query result is stale or invalid. This may be due to the log being cleared or rolling over after the query result was created. Users should handle this code by releasing the query result object and reissuing the query.")

    # (0x00003AA4) Query result is currently at an invalid position.
    ERROR_EVT_QUERY_RESULT_INVALID_POSITION = WindowsError::ErrorCode.new("ERROR_EVT_QUERY_RESULT_INVALID_POSITION",0x00003AA4,"Query result is currently at an invalid position.")

    # (0x00003AA5) Registered Microsoft XML (MSXML) does not support validation.
    ERROR_EVT_NON_VALIDATING_MSXML = WindowsError::ErrorCode.new("ERROR_EVT_NON_VALIDATING_MSXML",0x00003AA5,"Registered Microsoft XML (MSXML) does not support validation.")

    # (0x00003AA6) An expression can only be followed by a change-of-scope operation if it itself evaluates to a node set and is not already part of some other change-of-scope operation.
    ERROR_EVT_FILTER_ALREADYSCOPED = WindowsError::ErrorCode.new("ERROR_EVT_FILTER_ALREADYSCOPED",0x00003AA6,"An expression can only be followed by a change-of-scope operation if it itself evaluates to a node set and is not already part of some other change-of-scope operation.")

    # (0x00003AA7) Cannot perform a step operation from a term that does not represent an element set.
    ERROR_EVT_FILTER_NOTELTSET = WindowsError::ErrorCode.new("ERROR_EVT_FILTER_NOTELTSET",0x00003AA7,"Cannot perform a step operation from a term that does not represent an element set.")

    # (0x00003AA8) Left side arguments to binary operators must be either attributes, nodes, or variables and right side arguments must be constants.
    ERROR_EVT_FILTER_INVARG = WindowsError::ErrorCode.new("ERROR_EVT_FILTER_INVARG",0x00003AA8,"Left side arguments to binary operators must be either attributes, nodes, or variables and right side arguments must be constants.")

    # (0x00003AA9) A step operation must involve either a node test or, in the case of a predicate, an algebraic expression against which to test each node in the node set identified by the preceding node set can be evaluated.
    ERROR_EVT_FILTER_INVTEST = WindowsError::ErrorCode.new("ERROR_EVT_FILTER_INVTEST",0x00003AA9,"A step operation must involve either a node test or, in the case of a predicate, an algebraic expression against which to test each node in the node set identified by the preceding node set can be evaluated.")

    # (0x00003AAA) This data type is currently unsupported.
    ERROR_EVT_FILTER_INVTYPE = WindowsError::ErrorCode.new("ERROR_EVT_FILTER_INVTYPE",0x00003AAA,"This data type is currently unsupported.")

    # (0x00003AAB) A syntax error occurred at position %1!d!
    ERROR_EVT_FILTER_PARSEERR = WindowsError::ErrorCode.new("ERROR_EVT_FILTER_PARSEERR",0x00003AAB,"A syntax error occurred at position %1!d!")

    # (0x00003AAC) This operator is unsupported by this implementation of the filter.
    ERROR_EVT_FILTER_UNSUPPORTEDOP = WindowsError::ErrorCode.new("ERROR_EVT_FILTER_UNSUPPORTEDOP",0x00003AAC,"This operator is unsupported by this implementation of the filter.")

    # (0x00003AAD) The token encountered was unexpected.
    ERROR_EVT_FILTER_UNEXPECTEDTOKEN = WindowsError::ErrorCode.new("ERROR_EVT_FILTER_UNEXPECTEDTOKEN",0x00003AAD,"The token encountered was unexpected.")

    # (0x00003AAE) The requested operation cannot be performed over an enabled direct channel. The channel must first be disabled before performing the requested operation.
    ERROR_EVT_INVALID_OPERATION_OVER_ENABLED_DIRECT_CHANNEL = WindowsError::ErrorCode.new("ERROR_EVT_INVALID_OPERATION_OVER_ENABLED_DIRECT_CHANNEL",0x00003AAE,"The requested operation cannot be performed over an enabled direct channel. The channel must first be disabled before performing the requested operation.")

    # (0x00003AAF) Channel property %1!s! contains an invalid value. The value has an invalid type, is outside the valid range, cannot be updated, or is not supported by this type of channel.
    ERROR_EVT_INVALID_CHANNEL_PROPERTY_VALUE = WindowsError::ErrorCode.new("ERROR_EVT_INVALID_CHANNEL_PROPERTY_VALUE",0x00003AAF,"Channel property %1!s! contains an invalid value. The value has an invalid type, is outside the valid range, cannot be updated, or is not supported by this type of channel.")

    # (0x00003AB0) Publisher property %1!s! contains an invalid value. The value has an invalid type, is outside the valid range, cannot be updated, or is not supported by this type of publisher.
    ERROR_EVT_INVALID_PUBLISHER_PROPERTY_VALUE = WindowsError::ErrorCode.new("ERROR_EVT_INVALID_PUBLISHER_PROPERTY_VALUE",0x00003AB0,"Publisher property %1!s! contains an invalid value. The value has an invalid type, is outside the valid range, cannot be updated, or is not supported by this type of publisher.")

    # (0x00003AB1) The channel fails to activate.
    ERROR_EVT_CHANNEL_CANNOT_ACTIVATE = WindowsError::ErrorCode.new("ERROR_EVT_CHANNEL_CANNOT_ACTIVATE",0x00003AB1,"The channel fails to activate.")

    # (0x00003AB2) The xpath expression exceeded supported complexity. Simplify it or split it into two or more simple expressions.
    ERROR_EVT_FILTER_TOO_COMPLEX = WindowsError::ErrorCode.new("ERROR_EVT_FILTER_TOO_COMPLEX",0x00003AB2,"The xpath expression exceeded supported complexity. Simplify it or split it into two or more simple expressions.")

    # (0x00003AB3) The message resource is present but the message is not found in the string or message table.
    ERROR_EVT_MESSAGE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_EVT_MESSAGE_NOT_FOUND",0x00003AB3,"The message resource is present but the message is not found in the string or message table.")

    # (0x00003AB4) The message ID for the desired message could not be found.
    ERROR_EVT_MESSAGE_ID_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_EVT_MESSAGE_ID_NOT_FOUND",0x00003AB4,"The message ID for the desired message could not be found.")

    # (0x00003AB5) The substitution string for the insert index (%1) could not be found.
    ERROR_EVT_UNRESOLVED_VALUE_INSERT = WindowsError::ErrorCode.new("ERROR_EVT_UNRESOLVED_VALUE_INSERT",0x00003AB5,"The substitution string for the insert index (%1) could not be found.")

    # (0x00003AB6) The description string for the parameter reference (%1) could not be found.
    ERROR_EVT_UNRESOLVED_PARAMETER_INSERT = WindowsError::ErrorCode.new("ERROR_EVT_UNRESOLVED_PARAMETER_INSERT",0x00003AB6,"The description string for the parameter reference (%1) could not be found.")

    # (0x00003AB7) The maximum number of replacements has been reached.
    ERROR_EVT_MAX_INSERTS_REACHED = WindowsError::ErrorCode.new("ERROR_EVT_MAX_INSERTS_REACHED",0x00003AB7,"The maximum number of replacements has been reached.")

    # (0x00003AB8) The event definition could not be found for the event ID (%1).
    ERROR_EVT_EVENT_DEFINITION_NOT_OUND = WindowsError::ErrorCode.new("ERROR_EVT_EVENT_DEFINITION_NOT_OUND",0x00003AB8,"The event definition could not be found for the event ID (%1).")

    # (0x00003AB9) The locale-specific resource for the desired message is not present.
    ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND",0x00003AB9,"The locale-specific resource for the desired message is not present.")

    # (0x00003ABA) The resource is too old to be compatible.
    ERROR_EVT_VERSION_TOO_OLD = WindowsError::ErrorCode.new("ERROR_EVT_VERSION_TOO_OLD",0x00003ABA,"The resource is too old to be compatible.")

    # (0x00003ABB) The resource is too new to be compatible.
    ERROR_EVT_VERSION_TOO_NEW = WindowsError::ErrorCode.new("ERROR_EVT_VERSION_TOO_NEW",0x00003ABB,"The resource is too new to be compatible.")

    # (0x00003ABC) The channel at index %1 of the query cannot be opened.
    ERROR_EVT_CANNOT_OPEN_CHANNEL_OF_QUERY = WindowsError::ErrorCode.new("ERROR_EVT_CANNOT_OPEN_CHANNEL_OF_QUERY",0x00003ABC,"The channel at index %1 of the query cannot be opened.")

    # (0x00003ABD) The publisher has been disabled and its resource is not available. This usually occurs when the publisher is in the process of being uninstalled or upgraded.
    ERROR_EVT_PUBLISHER_DISABLED = WindowsError::ErrorCode.new("ERROR_EVT_PUBLISHER_DISABLED",0x00003ABD,"The publisher has been disabled and its resource is not available. This usually occurs when the publisher is in the process of being uninstalled or upgraded.")

    # (0x00003AE8) The subscription fails to activate.
    ERROR_EC_SUBSCRIPTION_CANNOT_ACTIVATE = WindowsError::ErrorCode.new("ERROR_EC_SUBSCRIPTION_CANNOT_ACTIVATE",0x00003AE8,"The subscription fails to activate.")

    # (0x00003AE9) The log of the subscription is in a disabled state and events cannot be forwarded to it. The log must first be enabled before the subscription can be activated.
    ERROR_EC_LOG_DISABLED = WindowsError::ErrorCode.new("ERROR_EC_LOG_DISABLED",0x00003AE9,"The log of the subscription is in a disabled state and events cannot be forwarded to it. The log must first be enabled before the subscription can be activated.")

    # (0x00003AFC) The resource loader failed to find the Multilingual User Interface (MUI) file.
    ERROR_MUI_FILE_NOT_FOUND = WindowsError::ErrorCode.new("ERROR_MUI_FILE_NOT_FOUND",0x00003AFC,"The resource loader failed to find the Multilingual User Interface (MUI) file.")

    # (0x00003AFD) The resource loader failed to load the MUI file because the file failed to pass validation.
    ERROR_MUI_INVALID_FILE = WindowsError::ErrorCode.new("ERROR_MUI_INVALID_FILE",0x00003AFD,"The resource loader failed to load the MUI file because the file failed to pass validation.")

    # (0x00003AFE) The release candidate (RC) manifest is corrupted with garbage data, is an unsupported version, or is missing a required item.
    ERROR_MUI_INVALID_RC_CONFIG = WindowsError::ErrorCode.new("ERROR_MUI_INVALID_RC_CONFIG",0x00003AFE,"The release candidate (RC) manifest is corrupted with garbage data, is an unsupported version, or is missing a required item.")

    # (0x00003AFF) The RC manifest has an invalid culture name.
    ERROR_MUI_INVALID_LOCALE_NAME = WindowsError::ErrorCode.new("ERROR_MUI_INVALID_LOCALE_NAME",0x00003AFF,"The RC manifest has an invalid culture name.")

    # (0x00003B00) The RC Manifest has an invalid ultimate fallback name.
    ERROR_MUI_INVALID_ULTIMATEFALLBACK_NAME = WindowsError::ErrorCode.new("ERROR_MUI_INVALID_ULTIMATEFALLBACK_NAME",0x00003B00,"The RC Manifest has an invalid ultimate fallback name.")

    # (0x00003B01) The resource loader cache does not have a loaded MUI entry.
    ERROR_MUI_FILE_NOT_LOADED = WindowsError::ErrorCode.new("ERROR_MUI_FILE_NOT_LOADED",0x00003B01,"The resource loader cache does not have a loaded MUI entry.")

    # (0x00003B02) The user stopped resource enumeration.
    ERROR_RESOURCE_ENUM_USER_STOP = WindowsError::ErrorCode.new("ERROR_RESOURCE_ENUM_USER_STOP",0x00003B02,"The user stopped resource enumeration.")

    # (0x00003B03) User interface language installation failed.
    ERROR_MUI_INTLSETTINGS_UILANG_NOT_INSTALLED = WindowsError::ErrorCode.new("ERROR_MUI_INTLSETTINGS_UILANG_NOT_INSTALLED",0x00003B03,"User interface language installation failed.")

    # (0x00003B04) Locale installation failed.
    ERROR_MUI_INTLSETTINGS_INVALID_LOCALE_NAME = WindowsError::ErrorCode.new("ERROR_MUI_INTLSETTINGS_INVALID_LOCALE_NAME",0x00003B04,"Locale installation failed.")

    # (0x00003B60) The monitor returned a DDC/CI capabilities string that did not comply with the ACCESS.bus 3.0, DDC/CI 1.1, or MCCS 2 Revision 1 specification.
    ERROR_MCA_INVALID_CAPABILITIES_STRING = WindowsError::ErrorCode.new("ERROR_MCA_INVALID_CAPABILITIES_STRING",0x00003B60,"The monitor returned a DDC/CI capabilities string that did not comply with the ACCESS.bus 3.0, DDC/CI 1.1, or MCCS 2 Revision 1 specification.")

    # (0x00003B61) The monitor's VCP version (0xDF) VCP code returned an invalid version value.
    ERROR_MCA_INVALID_VCP_VERSION = WindowsError::ErrorCode.new("ERROR_MCA_INVALID_VCP_VERSION",0x00003B61,"The monitor's VCP version (0xDF) VCP code returned an invalid version value.")

    # (0x00003B62) The monitor does not comply with the MCCS specification it claims to support.
    ERROR_MCA_MONITOR_VIOLATES_MCCS_SPECIFICATION = WindowsError::ErrorCode.new("ERROR_MCA_MONITOR_VIOLATES_MCCS_SPECIFICATION",0x00003B62,"The monitor does not comply with the MCCS specification it claims to support.")

    # (0x00003B63) The MCCS version in a monitor's mccs_ver capability does not match the MCCS version the monitor reports when the VCP version (0xDF) VCP code is used.
    ERROR_MCA_MCCS_VERSION_MISMATCH = WindowsError::ErrorCode.new("ERROR_MCA_MCCS_VERSION_MISMATCH",0x00003B63,"The MCCS version in a monitor's mccs_ver capability does not match the MCCS version the monitor reports when the VCP version (0xDF) VCP code is used.")

    # (0x00003B64) The monitor configuration API works only with monitors that support the MCCS 1.0, MCCS 2.0, or MCCS 2.0 Revision 1 specifications.
    ERROR_MCA_UNSUPPORTED_MCCS_VERSION = WindowsError::ErrorCode.new("ERROR_MCA_UNSUPPORTED_MCCS_VERSION",0x00003B64,"The monitor configuration API works only with monitors that support the MCCS 1.0, MCCS 2.0, or MCCS 2.0 Revision 1 specifications.")

    # (0x00003B65) An internal monitor configuration API error occurred.
    ERROR_MCA_INTERNAL_ERROR = WindowsError::ErrorCode.new("ERROR_MCA_INTERNAL_ERROR",0x00003B65,"An internal monitor configuration API error occurred.")

    # (0x00003B66) The monitor returned an invalid monitor technology type. CRT, plasma, and LCD (TFT) are examples of monitor technology types. This error implies that the monitor violated the MCCS 2.0 or MCCS 2.0 Revision 1 specification.
    ERROR_MCA_INVALID_TECHNOLOGY_TYPE_RETURNED = WindowsError::ErrorCode.new("ERROR_MCA_INVALID_TECHNOLOGY_TYPE_RETURNED",0x00003B66,"The monitor returned an invalid monitor technology type. CRT, plasma, and LCD (TFT) are examples of monitor technology types. This error implies that the monitor violated the MCCS 2.0 or MCCS 2.0 Revision 1 specification.")

    # (0x00003B67) The SetMonitorColorTemperature() caller passed a color temperature to it that the current monitor did not support. CRT, plasma, and LCD (TFT) are examples of monitor technology types. This error implies that the monitor violated the MCCS 2.0 or MCCS 2.0 Revision 1 specification.
    ERROR_MCA_UNSUPPORTED_COLOR_TEMPERATURE = WindowsError::ErrorCode.new("ERROR_MCA_UNSUPPORTED_COLOR_TEMPERATURE",0x00003B67,"The SetMonitorColorTemperature() caller passed a color temperature to it that the current monitor did not support. CRT, plasma, and LCD (TFT) are examples of monitor technology types. This error implies that the monitor violated the MCCS 2.0 or MCCS 2.0 Revision 1 specification.")

    # (0x00003B92) The requested system device cannot be identified due to multiple indistinguishable devices potentially matching the identification criteria.
    ERROR_AMBIGUOUS_SYSTEM_DEVICE = WindowsError::ErrorCode.new("ERROR_AMBIGUOUS_SYSTEM_DEVICE",0x00003B92,"The requested system device cannot be identified due to multiple indistinguishable devices potentially matching the identification criteria.")
  end
end
