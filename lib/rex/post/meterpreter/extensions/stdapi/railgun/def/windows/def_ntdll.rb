# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_windows_ntdll

  def self.create_library(constant_manager, library_path = 'ntdll')
    dll = Library.new(library_path, constant_manager)

    dll.add_function('NtAllocateVirtualMemory', 'DWORD',[
      ["DWORD","ProcessHandle","in"],
      ["PBLOB","BaseAddress","inout"],
      ["PDWORD","ZeroBits","in"],
      ["PBLOB","RegionSize","inout"],
      ["DWORD","AllocationType","in"],
      ["DWORD","Protect","in"]
      ])

    dll.add_function('NtClose', 'DWORD',[
      ["DWORD","Handle","in"],
      ])

    dll.add_function('NtCreateFile', 'DWORD',[
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

    dll.add_function('NtDeviceIoControlFile', 'DWORD',[
      ["DWORD","FileHandle","in"],
      ["DWORD","Event","in"],
      ["LPVOID","ApcRoutine","in"],
      ["LPVOID","ApcContext","in"],
      ["PDWORD","IoStatusBlock","out"],
      ["DWORD","IoControlCode","in"],
      ["LPVOID","InputBuffer","in"],
      ["DWORD","InputBufferLength","in"],
      ["LPVOID","OutputBuffer","in"],
      ["DWORD","OutputBufferLength","in"],
      ])

    dll.add_function('NtOpenFile', 'DWORD',[
      ["PDWORD","FileHandle","inout"],
      ["DWORD","DesiredAccess","in"],
      ["PBLOB","ObjectAttributes","in"],
      ["PBLOB","IoStatusBlock","inout"],
      ["DWORD","ShareAccess","in"],
      ["DWORD","OpenOptions","in"],
      ])

    dll.add_function('NtQueryInformationProcess', 'DWORD',[
      ["DWORD","ProcessHandle","in"],
      ["DWORD","ProcessInformationClass","in"],
      ["PBLOB","ProcessInformation","inout"],
      ["DWORD","ProcessInformationLength","in"],
      ["PDWORD","ReturnLength","inout"],
      ])

    dll.add_function('NtQueryInformationThread', 'DWORD',[
      ["DWORD","ThreadHandle","in"],
      ["DWORD","ThreadInformationClass","in"],
      ["PBLOB","ThreadInformation","inout"],
      ["DWORD","ThreadInformationLength","in"],
      ["PDWORD","ReturnLength","inout"],
      ])

    dll.add_function('NtQueryIntervalProfile', 'DWORD',[
      ["DWORD","ProfileSource","in"],
      ["PDWORD","Interval","out"],
      ])

    dll.add_function('NtQuerySystemInformation', 'DWORD',[
      ["DWORD","SystemInformationClass","in"],
      ["PBLOB","SystemInformation","inout"],
      ["DWORD","SystemInformationLength","in"],
      ["PDWORD","ReturnLength","inout"],
      ])

    dll.add_function('NtQuerySystemTime', 'DWORD',[
      ["PBLOB","SystemTime","inout"],
      ])

    dll.add_function('NtWaitForSingleObject', 'DWORD',[
      ["DWORD","Handle","in"],
      ["BOOL","Alertable","in"],
      ["PBLOB","Timeout","in"],
      ])

    dll.add_function('RtlCharToInteger', 'DWORD',[
      ["PBLOB","String","inout"],
      ["DWORD","Base","in"],
      ["PDWORD","Value","inout"],
      ])

    dll.add_function('RtlConvertSidToUnicodeString', 'DWORD',[
      ["PBLOB","UnicodeString","inout"],
      ["PBLOB","Sid","inout"],
      ["BOOL","AllocateDestinationString","in"],
      ])

    dll.add_function('RtlFreeAnsiString', 'VOID',[
      ["PBLOB","AnsiString","inout"],
      ])

    dll.add_function('RtlFreeOemString', 'VOID',[
      ["PBLOB","OemString","inout"],
      ])

    dll.add_function('RtlFreeUnicodeString', 'VOID',[
      ["PBLOB","UnicodeString","inout"],
      ])

    dll.add_function('RtlInitAnsiString', 'VOID',[
      ["PBLOB","DestinationString","inout"],
      ["PBLOB","SourceString","inout"],
      ])

    dll.add_function('RtlInitString', 'VOID',[
      ["PBLOB","DestinationString","inout"],
      ["PBLOB","SourceString","inout"],
      ])

    dll.add_function('RtlLocalTimeToSystemTime', 'DWORD',[
      ["PBLOB","LocalTime","in"],
      ["PBLOB","SystemTime","inout"],
      ])

    dll.add_function('RtlNtStatusToDosError', 'DWORD',[
      ["DWORD","Status","in"],
      ])

    dll.add_function('RtlTimeToSecondsSince1970', 'BOOL',[
      ["PBLOB","Time","inout"],
      ["PDWORD","ElapsedSeconds","inout"],
      ])

    dll.add_function('RtlUniform', 'DWORD',[
      ["PDWORD","Seed","inout"],
      ])

    dll.add_function('RtlUnwind', 'VOID',[
      ["PBLOB","TargetFrame","in"],
      ["PBLOB","TargetIp","in"],
      ["PBLOB","ExceptionRecord","in"],
      ["PBLOB","ReturnValue","in"],
      ])

    return dll
  end

end

end; end; end; end; end; end; end


