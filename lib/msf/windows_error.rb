# -*- coding: binary -*-

#
# Windows system error codes (0-499)
#
# http://msdn.microsoft.com/en-us/library/ms681382%28v=VS.85%29.aspx
#

module Msf

class WindowsError

	#
	# Constants
	#
	SUCCESS = 0
	INVALID_FUNCTION = 1
	FILE_NOT_FOUND = 2
	PATH_NOT_FOUND = 3
	TOO_MANY_OPEN_FILES = 4
	ACCESS_DENIED = 5
	INVALID_HANDLE = 6
	ARENA_TRASHED = 7
	NOT_ENOUGH_MEMORY = 8
	INVALID_BLOCK = 9
	BAD_ENVIRONMENT = 10
	BAD_FORMAT = 11
	INVALID_ACCESS = 12
	INVALID_DATA = 13
	OUTOFMEMORY = 14
	INVALID_DRIVE = 15
	CURRENT_DIRECTORY = 16
	NOT_SAME_DEVICE = 17
	NO_MORE_FILES = 18
	WRITE_PROTECT = 19
	BAD_UNIT = 20
	NOT_READY = 21
	BAD_COMMAND = 22
	CRC = 23
	BAD_LENGTH = 24
	SEEK = 25
	NOT_DOS_DISK = 26
	SECTOR_NOT_FOUND = 27
	OUT_OF_PAPER = 28
	WRITE_FAULT = 29
	READ_FAULT = 30
	GEN_FAILURE = 31
	SHARING_VIOLATION = 32
	LOCK_VIOLATION = 33
	WRONG_DISK = 34
	SHARING_BUFFER_EXCEEDED = 36
	HANDLE_EOF = 38
	HANDLE_DISK_FULL = 39
	NOT_SUPPORTED = 50
	REM_NOT_LIST = 51
	DUP_NAME = 52
	BAD_NETPATH = 53
	NETWORK_BUSY = 54
	DEV_NOT_EXIST = 55
	TOO_MANY_CMDS = 56
	ADAP_HDW_ERR = 57
	BAD_NET_RESP = 58
	UNEXP_NET_ERR = 59
	BAD_REM_ADAP = 60
	PRINTQ_FULL = 61
	NO_SPOOL_SPACE = 62
	PRINT_CANCELLED = 63
	NETNAME_DELETED = 64
	NETWORK_ACCESS_DENIED = 65
	BAD_DEV_TYPE = 66
	BAD_NET_NAME = 67
	TOO_MANY_NAMES = 68
	TOO_MANY_SESS = 69
	SHARING_PAUSED = 70
	REQ_NOT_ACCEP = 71
	REDIR_PAUSED = 72
	FILE_EXISTS = 80
	CANNOT_MAKE = 82
	FAIL_I24 = 83
	OUT_OF_STRUCTURES = 84
	ALREADY_ASSIGNED = 85
	INVALID_PASSWORD = 86
	INVALID_PARAMETER = 87
	NET_WRITE_FAULT = 88
	NO_PROC_SLOTS = 89

	TOO_MANY_SEMAPHORES = 100
	EXCL_SEM_ALREADY_OWNED = 101
	SEM_IS_SET = 102
	TOO_MANY_SEM_REQUESTS = 103
	INVALID_AT_INTERRUPT_TIME = 104
	SEM_OWNER_DIED = 105
	SEM_USER_LIMIT = 106
	DISK_CHANGE = 107
	DRIVE_LOCKED = 108
	BROKEN_PIPE = 109
	OPEN_FAILED = 110
	BUFFER_OVERFLOW = 111
	DISK_FULL = 112
	NO_MORE_SEARCH_HANDLES = 113
	INVALID_TARGET_HANDLE = 114
	INVALID_CATEGORY = 117
	INVALID_VERIFY_SWITCH = 118
	BAD_DRIVER_LEVEL = 119
	CALL_NOT_IMPLEMENTED = 120
	SEM_TIMEOUT = 121
	INSUFFICIENT_BUFFER = 122
	INVALID_NAME = 123
	INVALID_LEVEL = 124
	NO_VOLUME_LABEL = 125
	MOD_NOT_FOUND = 126
	PROC_NOT_FOUND = 127
	WAIT_NO_CHILDREN = 128
	CHILD_NOT_COMPLETE = 129
	DIRECT_ACCESS_HANDLE = 130
	NEGATIVE_SEEK = 131
	SEEK_ON_DEVICE = 132
	IS_JOIN_TARGET = 133
	IS_JOINED = 134
	IS_SUBSTED = 135
	NOT_JOINED = 136
	NOT_SUBSTED = 137
	JOIN_TO_JOIN = 138
	SUBST_TO_SUBST = 139
	JOIN_TO_SUBST = 140
	SUBST_TO_JOIN = 141
	BUSY_DRIVE = 142
	SAME_DRIVE = 143
	DIR_NOT_ROOT = 144
	DIR_NOT_EMPTY = 145
	IS_SUBST_PATH = 146
	IS_JOIN_PATH = 147
	PATH_BUSY = 148
	IS_SUBST_TARGET = 149
	SYSTEM_TRACE = 150
	INVALID_EVENT_COUNT = 151
	TOO_MANY_MUXWAITERS = 152
	INVALID_LIST_FORMAT = 153
	LABEL_TOO_LONG = 154
	TOO_MANY_TCBS = 155
	SIGNAL_REFUSED = 156
	DISCARDED = 157
	NOT_LOCKED = 158
	BAD_THREADID_ADDR = 159
	BAD_ARGUMENTS = 160
	BAD_PATHNAME = 161
	SIGNAL_PENDING = 162
	MAX_THRDS_REACHED = 164
	LOCK_FAILED = 167
	BUSY = 170
	CANCEL_VIOLATION = 173
	ATOMIC_LOCKS_NOT_SUPPORTED = 174
	INVALID_SEGMENT_NUMBER = 180
	INVALID_ORDINAL = 182
	ALREADY_EXISTS = 183
	INVALID_FLAG_NUMBER = 186
	SEM_NOT_FOUND = 187
	INVALID_STARTING_CODESEG = 188
	INVALID_STACKSEG = 189
	INVALID_MODULETYPE = 190
	INVALID_EXE_SIGNATURE = 191
	EXE_MARKED_INVALID = 192
	BAD_EXE_FORMAT = 193
	ITERATED_DATA_EXCEEDS_64k = 194
	INVALID_MINALLOCSIZE = 195
	DYNLINK_FROM_INVALID_RING = 196
	IOPL_NOT_ENABLED = 197
	INVALID_SEGDPL = 198
	AUTODATASEG_EXCEEDS_64k = 199

	RING2SEG_MUST_BE_MOVABLE = 200
	RELOC_CHAIN_XEEDS_SEGLIM = 201
	INFLOOP_IN_RELOC_CHAIN = 202
	ENVVAR_NOT_FOUND = 203
	NO_SIGNAL_SENT = 205
	FILENAME_EXCED_RANGE = 206
	RING2_STACK_IN_USE = 207
	META_EXPANSION_TOO_LONG = 208
	INVALID_SIGNAL_NUMBER = 209
	THREAD_1_INACTIVE = 210
	LOCKED = 212
	TOO_MANY_MODULES = 214
	NESTING_NOT_ALLOWED = 215
	EXE_MACHINE_TYPE_MISMATCH = 216
	EXE_CANNOT_MODIFY_SIGNED_BINARY = 217
	EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY = 218
	FILE_CHECKED_OUT = 220
	CHECKOUT_REQUIRED = 221
	BAD_FILE_TYPE = 222
	FILE_TOO_LARGE = 223
	FORMS_AUTH_REQUIRED = 224
	VIRUS_INFECTED = 225
	VIRUS_DELETED = 226
	PIPE_LOCAL = 229
	BAD_PIPE = 230
	PIPE_BUSY = 231
	NO_DATA = 232
	PIPE_NOT_CONNECTED = 233
	MORE_DATA = 234
	VC_DISCONNECTED = 240
	INVALID_EA_NAME = 254
	EA_LIST_INCONSISTENT = 255
	WAIT_TIMEOUT = 258
	NO_MORE_ITEMS = 259
	CANNOT_COPY = 266
	DIRECTORY = 267
	EAS_DIDNT_FIT = 275
	EA_FILE_CORRUPT = 276
	EA_TABLE_FULL = 277
	INVALID_EA_HANDLE = 278
	EAS_NOT_SUPPORTED = 282
	NOT_OWNER = 288
	TOO_MANY_POSTS = 298
	PARTIAL_COPY = 299

	OPLOCK_NOT_GRANTED = 300
	INVALID_OPLOCK_PROTOCOL = 301
	DISK_TOO_FRAGMENTED = 302
	DELETE_PENDING = 303
	INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING = 304
	SHORT_NAMES_NOT_ENABLED_ON_VOLUME = 305
	SECURITY_STREAM_IS_INCONSISTENT = 306
	INVALID_LOCK_RANGE = 307
	IMAGE_SUBSYSTEM_NOT_PRESENT = 308
	NOTIFICATION_GUID_ALREADY_DEFINED = 309
	MR_MID_NOT_FOUND = 317
	SCOPE_NOT_FOUND = 318
	FAIL_NOACTION_REBOOT = 350
	FAIL_SHUTDOWN = 351
	FAIL_RESTART = 352
	MAX_SESSIONS_REACHED = 353

	THREAD_MODE_ALREADY_BACKGROUND = 400
	THREAD_MODE_NOT_BACKGROUND = 401
	PROCESS_MODE_ALREADY_BACKGROUND = 402
	PROCESS_MODE_NOT_BACKGROUND = 403
	INVALID_ADDRESS = 487

	#
	# Return a string representation of the constant for a number
	#
	def self.const_name(code)
		self.constants.each { |c|
			return c.to_s if self.const_get(c) == code
		}
		return nil
	end

	#
	# Return the description of an error code
	def self.description(code)

		case code
		when SUCCESS
			"The operation completed successfully."
		when INVALID_FUNCTION
			"Incorrect function."
		when FILE_NOT_FOUND
			"The system cannot find the file specified."
		when PATH_NOT_FOUND
			"The system cannot find the path specified."
		when TOO_MANY_OPEN_FILES
			"The system cannot open the file."
		when ACCESS_DENIED
			"Access is denied."
		when INVALID_HANDLE
			"The handle is invalid."
		when ARENA_TRASHED
			"The storage control blocks were destroyed."
		when NOT_ENOUGH_MEMORY
			"Not enough storage is available to process this command."
		when INVALID_BLOCK
			"The storage control block address is invalid."
		when BAD_ENVIRONMENT
			"The environment is incorrect."
		when BAD_FORMAT
			"An attempt was made to load a program with an incorrect format."
		when INVALID_ACCESS
			"The access code is invalid."
		when INVALID_DATA
			"The data is invalid."
		when OUTOFMEMORY
			"Not enough storage is available to complete this operation."
		when INVALID_DRIVE
			"The system cannot find the drive specified."
		when CURRENT_DIRECTORY
			"The directory cannot be removed."
		when NOT_SAME_DEVICE
			"The system cannot move the file to a different disk drive."
		when NO_MORE_FILES
			"There are no more files."
		when WRITE_PROTECT
			"The media is write protected."
		when BAD_UNIT
			"The system cannot find the device specified."
		when NOT_READY
			"The device is not ready."
		when BAD_COMMAND
			"The device does not recognize the command."
		when CRC
			"Data error ;."
		when BAD_LENGTH
			"The program issued a command but the command length is incorrect."
		when SEEK
			"The drive cannot locate a specific area or track on the disk."
		when NOT_DOS_DISK
			"The specified disk or diskette cannot be accessed."
		when SECTOR_NOT_FOUND
			"The drive cannot find the sector requested."
		when OUT_OF_PAPER
			"The printer is out of paper."
		when WRITE_FAULT
			"The system cannot write to the specified device."
		when READ_FAULT
			"The system cannot read from the specified device."
		when GEN_FAILURE
			"A device attached to the system is not functioning."
		when SHARING_VIOLATION
			"The process cannot access the file because it is being used by another process."
		when LOCK_VIOLATION
			"The process cannot access the file because another process has locked a portion of the file."
		when WRONG_DISK
			"The wrong diskette is in the drive. Insert %2 ; into drive %1."
		when SHARING_BUFFER_EXCEEDED
			"Too many files opened for sharing."
		when HANDLE_EOF
			"Reached the end of the file."
		when HANDLE_DISK_FULL
			"The disk is full."
		when NOT_SUPPORTED
			"The request is not supported."
		when REM_NOT_LIST
			"Windows cannot find the network path. Verify that the network path is correct and the destination computer is not busy or turned off. If Windows still cannot find the network path, contact your network administrator."
		when DUP_NAME
			"You were not connected because a duplicate name exists on the network. If joining a domain, go to System in Control Panel to change the computer name and try again. If joining a workgroup, choose another workgroup name."
		when BAD_NETPATH
			"The network path was not found."
		when NETWORK_BUSY
			"The network is busy."
		when DEV_NOT_EXIST
			"The specified network resource or device is no longer available."
		when TOO_MANY_CMDS
			"The network BIOS command limit has been reached."
		when ADAP_HDW_ERR
			"A network adapter hardware error occurred."
		when BAD_NET_RESP
			"The specified server cannot perform the requested operation."
		when UNEXP_NET_ERR
			"An unexpected network error occurred."
		when BAD_REM_ADAP
			"The remote adapter is not compatible."
		when PRINTQ_FULL
			"The printer queue is full."
		when NO_SPOOL_SPACE
			"Space to store the file waiting to be printed is not available on the server."
		when PRINT_CANCELLED
			"Your file waiting to be printed was deleted."
		when NETNAME_DELETED
			"The specified network name is no longer available."
		when NETWORK_ACCESS_DENIED
			"Network access is denied."
		when BAD_DEV_TYPE
			"The network resource type is not correct."
		when BAD_NET_NAME
			"The network name cannot be found."
		when TOO_MANY_NAMES
			"The name limit for the local computer network adapter card was exceeded."
		when TOO_MANY_SESS
			"The network BIOS session limit was exceeded."
		when SHARING_PAUSED
			"The remote server has been paused or is in the process of being started."
		when REQ_NOT_ACCEP
			"No more connections can be made to this remote computer at this time because there are already as many connections as the computer can accept."
		when REDIR_PAUSED
			"The specified printer or disk device has been paused."
		when FILE_EXISTS
			"The file exists."
		when CANNOT_MAKE
			"The directory or file cannot be created."
		when FAIL_I24
			"Fail on INT 24."
		when OUT_OF_STRUCTURES
			"Storage to process this request is not available."
		when ALREADY_ASSIGNED
			"The local device name is already in use."
		when INVALID_PASSWORD
			"The specified network password is not correct."
		when INVALID_PARAMETER
			"The parameter is incorrect."
		when NET_WRITE_FAULT
			"A write fault occurred on the network."
		when NO_PROC_SLOTS
			"The system cannot start another process at this time."
		when TOO_MANY_SEMAPHORES
			"Cannot create another system semaphore."
		when EXCL_SEM_ALREADY_OWNED
			"The exclusive semaphore is owned by another process."
		when SEM_IS_SET
			"The semaphore is set and cannot be closed."
		when TOO_MANY_SEM_REQUESTS
			"The semaphore cannot be set again."
		when INVALID_AT_INTERRUPT_TIME
			"Cannot request exclusive semaphores at interrupt time."
		when SEM_OWNER_DIED
			"The previous ownership of this semaphore has ended."
		when SEM_USER_LIMIT
			"Insert the diskette for drive %1."
		when DISK_CHANGE
			"The program stopped because an alternate diskette was not inserted."
		when DRIVE_LOCKED
			"The disk is in use or locked by another process."
		when BROKEN_PIPE
			"The pipe has been ended."
		when OPEN_FAILED
			"The system cannot open the device or file specified."
		when BUFFER_OVERFLOW
			"The file name is too long."
		when DISK_FULL
			"There is not enough space on the disk."
		when NO_MORE_SEARCH_HANDLES
			"No more internal file identifiers available."
		when INVALID_TARGET_HANDLE
			"The target internal file identifier is incorrect."
		when INVALID_CATEGORY
			"The IOCTL call made by the application program is not correct."
		when INVALID_VERIFY_SWITCH
			"The verify-on-write switch parameter value is not correct."
		when BAD_DRIVER_LEVEL
			"The system does not support the command requested."
		when CALL_NOT_IMPLEMENTED
			"This function is not supported on this system."
		when SEM_TIMEOUT
			"The semaphore timeout period has expired."
		when INSUFFICIENT_BUFFER
			"The data area passed to a system call is too small."
		when INVALID_NAME
			"The filename, directory name, or volume label syntax is incorrect."
		when INVALID_LEVEL
			"The system call level is not correct."
		when NO_VOLUME_LABEL
			"The disk has no volume label."
		when MOD_NOT_FOUND
			"The specified module could not be found."
		when PROC_NOT_FOUND
			"The specified procedure could not be found."
		when WAIT_NO_CHILDREN
			"There are no child processes to wait for."
		when CHILD_NOT_COMPLETE
			"The %1 application cannot be run in Win32 mode."
		when DIRECT_ACCESS_HANDLE
			"Attempt to use a file handle to an open disk partition for an operation other than raw disk I/O."
		when NEGATIVE_SEEK
			"An attempt was made to move the file pointer before the beginning of the file."
		when SEEK_ON_DEVICE
			"The file pointer cannot be set on the specified device or file."
		when IS_JOIN_TARGET
			"A JOIN or SUBST command cannot be used for a drive that contains previously joined drives."
		when IS_JOINED
			"An attempt was made to use a JOIN or SUBST command on a drive that has already been joined."
		when IS_SUBSTED
			"An attempt was made to use a JOIN or SUBST command on a drive that has already been substituted."
		when NOT_JOINED
			"The system tried to delete the JOIN of a drive that is not joined."
		when NOT_SUBSTED
			"The system tried to delete the substitution of a drive that is not substituted."
		when JOIN_TO_JOIN
			"The system tried to join a drive to a directory on a joined drive."
		when SUBST_TO_SUBST
			"The system tried to substitute a drive to a directory on a substituted drive."
		when JOIN_TO_SUBST
			"The system tried to join a drive to a directory on a substituted drive."
		when SUBST_TO_JOIN
			"The system tried to SUBST a drive to a directory on a joined drive."
		when BUSY_DRIVE
			"The system cannot perform a JOIN or SUBST at this time."
		when SAME_DRIVE
			"The system cannot join or substitute a drive to or for a directory on the same drive."
		when DIR_NOT_ROOT
			"The directory is not a subdirectory of the root directory."
		when DIR_NOT_EMPTY
			"The directory is not empty."
		when IS_SUBST_PATH
			"The path specified is being used in a substitute."
		when IS_JOIN_PATH
			"Not enough resources are available to process this command."
		when PATH_BUSY
			"The path specified cannot be used at this time."
		when IS_SUBST_TARGET
			"An attempt was made to join or substitute a drive for which a directory on the drive is the target of a previous substitute."
		when SYSTEM_TRACE
			"System trace information was not specified in your CONFIG.SYS file, or tracing is disallowed."
		when INVALID_EVENT_COUNT
			"The number of specified semaphore events for DosMuxSemWait is not correct."
		when TOO_MANY_MUXWAITERS
			"DosMuxSemWait did not execute; too many semaphores are already set."
		when INVALID_LIST_FORMAT
			"The DosMuxSemWait list is not correct."
		when LABEL_TOO_LONG
			"The volume label you entered exceeds the label character limit of the target file system."
		when TOO_MANY_TCBS
			"Cannot create another thread."
		when SIGNAL_REFUSED
			"The recipient process has refused the signal."
		when DISCARDED
			"The segment is already discarded and cannot be locked."
		when NOT_LOCKED
			"The segment is already unlocked."
		when BAD_THREADID_ADDR
			"The address for the thread ID is not correct."
		when BAD_ARGUMENTS
			"One or more arguments are not correct."
		when BAD_PATHNAME
			"The specified path is invalid."
		when SIGNAL_PENDING
			"A signal is already pending."
		when MAX_THRDS_REACHED
			"No more threads can be created in the system."
		when LOCK_FAILED
			"Unable to lock a region of a file."
		when BUSY
			"The requested resource is in use."
		when CANCEL_VIOLATION
			"A lock request was not outstanding for the supplied cancel region."
		when ATOMIC_LOCKS_NOT_SUPPORTED
			"The file system does not support atomic changes to the lock type."
		when INVALID_SEGMENT_NUMBER
			"The system detected a segment number that was not correct."
		when INVALID_ORDINAL
			"The operating system cannot run %1."
		when ALREADY_EXISTS
			"Cannot create a file when that file already exists."
		when INVALID_FLAG_NUMBER
			"The flag passed is not correct."
		when SEM_NOT_FOUND
			"The specified system semaphore name was not found."
		when INVALID_STARTING_CODESEG
			"The operating system cannot run %1."
		when INVALID_STACKSEG
			"The operating system cannot run %1."
		when INVALID_MODULETYPE
			"The operating system cannot run %1."
		when INVALID_EXE_SIGNATURE
			"Cannot run %1 in Win32 mode."
		when EXE_MARKED_INVALID
			"The operating system cannot run %1."
		when BAD_EXE_FORMAT
			"is not a valid Win32 application."
		when ITERATED_DATA_EXCEEDS_64k
			"The operating system cannot run %1."
		when INVALID_MINALLOCSIZE
			"The operating system cannot run %1."
		when DYNLINK_FROM_INVALID_RING
			"The operating system cannot run this application program."
		when IOPL_NOT_ENABLED
			"The operating system is not presently configured to run this application."
		when INVALID_SEGDPL
			"The operating system cannot run %1."
		when AUTODATASEG_EXCEEDS_64k
			"The operating system cannot run this application program."
		when RING2SEG_MUST_BE_MOVABLE
			"The code segment cannot be greater than or equal to 64K."
		when RELOC_CHAIN_XEEDS_SEGLIM
			"The operating system cannot run %1."
		when INFLOOP_IN_RELOC_CHAIN
			"The operating system cannot run %1."
		when ENVVAR_NOT_FOUND
			"The system could not find the environment option that was entered."
		when NO_SIGNAL_SENT
			"No process in the command subtree has a signal handler."
		when FILENAME_EXCED_RANGE
			"The filename or extension is too long."
		when RING2_STACK_IN_USE
			"The ring 2 stack is in use."
		when META_EXPANSION_TOO_LONG
			"The global filename characters, * or ?, are entered incorrectly or too many global filename characters are specified."
		when INVALID_SIGNAL_NUMBER
			"The signal being posted is not correct."
		when THREAD_1_INACTIVE
			"The signal handler cannot be set."
		when LOCKED
			"The segment is locked and cannot be reallocated."
		when TOO_MANY_MODULES
			"Too many dynamic-link modules are attached to this program or dynamic-link module."
		when NESTING_NOT_ALLOWED
			"Cannot nest calls to LoadModule."
		when EXE_MACHINE_TYPE_MISMATCH
			"The version of %1 is not compatible with the version you're running. Check your computer's system information to see whether you need a x86 ; or x64 ; version of the program, and then contact the software publisher."
		when EXE_CANNOT_MODIFY_SIGNED_BINARY
			"The image file %1 is signed, unable to modify."
		when EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY
			"The image file %1 is strong signed, unable to modify."
		when FILE_CHECKED_OUT
			"This file is checked out or locked for editing by another user."
		when CHECKOUT_REQUIRED
			"The file must be checked out before saving changes."
		when BAD_FILE_TYPE
			"The file type being saved or retrieved has been blocked."
		when FILE_TOO_LARGE
			"The file size exceeds the limit allowed and cannot be saved."
		when FORMS_AUTH_REQUIRED
			"Access Denied. Before opening files in this location, you must first add the web site to your trusted sites list, browse to the web site, and select the option to login automatically."
		when VIRUS_INFECTED
			"Operation did not complete successfully because the file contains a virus."
		when VIRUS_DELETED
			"This file contains a virus and cannot be opened. Due to the nature of this virus, the file has been removed from this location."
		when PIPE_LOCAL
			"The pipe is local."
		when BAD_PIPE
			"The pipe state is invalid."
		when PIPE_BUSY
			"All pipe instances are busy."
		when NO_DATA
			"The pipe is being closed."
		when PIPE_NOT_CONNECTED
			"No process is on the other end of the pipe."
		when MORE_DATA
			"More data is available."
		when VC_DISCONNECTED
			"The session was canceled."
		when INVALID_EA_NAME
			"The specified extended attribute name was invalid."
		when EA_LIST_INCONSISTENT
			"The extended attributes are inconsistent."
		when WAIT_TIMEOUT
			"The wait operation timed out."
		when NO_MORE_ITEMS
			"No more data is available."
		when CANNOT_COPY
			"The copy functions cannot be used."
		when DIRECTORY
			"The directory name is invalid."
		when EAS_DIDNT_FIT
			"The extended attributes did not fit in the buffer."
		when EA_FILE_CORRUPT
			"The extended attribute file on the mounted file system is corrupt."
		when EA_TABLE_FULL
			"The extended attribute table file is full."
		when INVALID_EA_HANDLE
			"The specified extended attribute handle is invalid."
		when EAS_NOT_SUPPORTED
			"The mounted file system does not support extended attributes."
		when NOT_OWNER
			"Attempt to release mutex not owned by caller."
		when TOO_MANY_POSTS
			"Too many posts were made to a semaphore."
		when PARTIAL_COPY
			"Only part of a ReadProcessMemory or WriteProcessMemory request was completed."
		when OPLOCK_NOT_GRANTED
			"The oplock request is denied."
		when INVALID_OPLOCK_PROTOCOL
			"An invalid oplock acknowledgment was received by the system."
		when DISK_TOO_FRAGMENTED
			"The volume is too fragmented to complete this operation."
		when DELETE_PENDING
			"The file cannot be opened because it is in the process of being deleted."
		when INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING
			"Short name settings may not be changed on this volume due to the global registry setting."
		when SHORT_NAMES_NOT_ENABLED_ON_VOLUME
			"Short names are not enabled on this volume."
		when SECURITY_STREAM_IS_INCONSISTENT
			"The security stream for the given volume is in an inconsistent state. Please run CHKDSK on the volume."
		when INVALID_LOCK_RANGE
			"A requested file lock operation cannot be processed due to an invalid byte range."
		when IMAGE_SUBSYSTEM_NOT_PRESENT
			"The subsystem needed to support the image type is not present."
		when NOTIFICATION_GUID_ALREADY_DEFINED
			"The specified file already has a notification GUID associated with it."
		when MR_MID_NOT_FOUND
			"The system cannot find message text for message number 0x%1 in the message file for %2."
		when SCOPE_NOT_FOUND
			"The scope specified was not found."
		when FAIL_NOACTION_REBOOT
			"No action was taken as a system reboot is required."
		when FAIL_SHUTDOWN
			"The shutdown operation failed."
		when FAIL_RESTART
			"The restart operation failed."
		when MAX_SESSIONS_REACHED
			"The maximum number of sessions has been reached."
		when THREAD_MODE_ALREADY_BACKGROUND
			"The thread is already in background processing mode."
		when THREAD_MODE_NOT_BACKGROUND
			"The thread is not in background processing mode."
		when PROCESS_MODE_ALREADY_BACKGROUND
			"The process is already in background processing mode."
		when PROCESS_MODE_NOT_BACKGROUND
			"The process is not in background processing mode."
		when INVALID_ADDRESS
			"Attempt to access invalid address."
		else
			"#{code}"
		end
	end

end

end
