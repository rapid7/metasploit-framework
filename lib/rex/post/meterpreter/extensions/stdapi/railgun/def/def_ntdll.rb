module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_ntdll

	def self.add_imports(railgun)
		
		railgun.add_dll('ntdll')

		railgun.add_function( 'ntdll', 'NtClose', 'DWORD',[
			["DWORD","Handle","in"],
			])

		railgun.add_function( 'ntdll', 'NtCreateFile', 'DWORD',[
			["PDWORD","FileHandle","inout"],
			["DWORD","DesiredAccess","in"],
			["PBLOB","ObjectAttributes","in"],
			["PBLOB","IoStatusBlock","inout"],
			["PBLOB","AllocationSize","in"],
			["DWORD","FileAttributes","in"],
			["DWORD","ShareAccess","in"],
			["DWORD","CreateDisposition","in"],
			["DWORD","CreateOptions","in"],
			["PBLOB","EaBuffer","in"],
			["DWORD","EaLength","in"],
			])

		railgun.add_function( 'ntdll', 'NtDeviceIoControlFile', 'DWORD',[
			["DWORD","FileHandle","in"],
			["DWORD","Event","in"],
			["PBLOB","ApcRoutine","in"],
			["PBLOB","ApcContext","in"],
			["PBLOB","IoStatusBlock","inout"],
			["DWORD","IoControlCode","in"],
			["PBLOB","InputBuffer","in"],
			["DWORD","InputBufferLength","in"],
			["PBLOB","OutputBuffer","inout"],
			["DWORD","OutputBufferLength","in"],
			])

		railgun.add_function( 'ntdll', 'NtOpenFile', 'DWORD',[
			["PDWORD","FileHandle","inout"],
			["DWORD","DesiredAccess","in"],
			["PBLOB","ObjectAttributes","in"],
			["PBLOB","IoStatusBlock","inout"],
			["DWORD","ShareAccess","in"],
			["DWORD","OpenOptions","in"],
			])

		railgun.add_function( 'ntdll', 'NtQueryInformationProcess', 'DWORD',[
			["DWORD","ProcessHandle","in"],
			["DWORD","ProcessInformationClass","in"],
			["PBLOB","ProcessInformation","inout"],
			["DWORD","ProcessInformationLength","in"],
			["PDWORD","ReturnLength","inout"],
			])

		railgun.add_function( 'ntdll', 'NtQueryInformationThread', 'DWORD',[
			["DWORD","ThreadHandle","in"],
			["DWORD","ThreadInformationClass","in"],
			["PBLOB","ThreadInformation","inout"],
			["DWORD","ThreadInformationLength","in"],
			["PDWORD","ReturnLength","inout"],
			])

		railgun.add_function( 'ntdll', 'NtQuerySystemInformation', 'DWORD',[
			["DWORD","SystemInformationClass","in"],
			["PBLOB","SystemInformation","inout"],
			["DWORD","SystemInformationLength","in"],
			["PDWORD","ReturnLength","inout"],
			])

		railgun.add_function( 'ntdll', 'NtQuerySystemTime', 'DWORD',[
			["PBLOB","SystemTime","inout"],
			])

		railgun.add_function( 'ntdll', 'NtWaitForSingleObject', 'DWORD',[
			["DWORD","Handle","in"],
			["BOOL","Alertable","in"],
			["PBLOB","Timeout","in"],
			])

		railgun.add_function( 'ntdll', 'RtlCharToInteger', 'DWORD',[
			["PBLOB","String","inout"],
			["DWORD","Base","in"],
			["PDWORD","Value","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlConvertSidToUnicodeString', 'DWORD',[
			["PBLOB","UnicodeString","inout"],
			["PBLOB","Sid","inout"],
			["BOOL","AllocateDestinationString","in"],
			])

		railgun.add_function( 'ntdll', 'RtlFreeAnsiString', 'VOID',[
			["PBLOB","AnsiString","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlFreeOemString', 'VOID',[
			["PBLOB","OemString","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlFreeUnicodeString', 'VOID',[
			["PBLOB","UnicodeString","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlInitAnsiString', 'VOID',[
			["PBLOB","DestinationString","inout"],
			["PBLOB","SourceString","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlInitString', 'VOID',[
			["PBLOB","DestinationString","inout"],
			["PBLOB","SourceString","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlLocalTimeToSystemTime', 'DWORD',[
			["PBLOB","LocalTime","in"],
			["PBLOB","SystemTime","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlNtStatusToDosError', 'DWORD',[
			["DWORD","Status","in"],
			])

		railgun.add_function( 'ntdll', 'RtlTimeToSecondsSince1970', 'BOOL',[
			["PBLOB","Time","inout"],
			["PDWORD","ElapsedSeconds","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlUniform', 'DWORD',[
			["PDWORD","Seed","inout"],
			])

		railgun.add_function( 'ntdll', 'RtlUnwind', 'VOID',[
			["PBLOB","TargetFrame","in"],
			["PBLOB","TargetIp","in"],
			["PBLOB","ExceptionRecord","in"],
			["PBLOB","ReturnValue","in"],
			])

	end
	
end

end; end; end; end; end; end; end


