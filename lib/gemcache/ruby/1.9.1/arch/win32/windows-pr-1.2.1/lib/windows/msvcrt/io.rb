require 'windows/api'

# This module includes stream I/O, low level I/O, etc.
module Windows
  module MSVCRT
    module IO
      API.auto_namespace = 'Windows::MSVCRT::IO'
      API.auto_constant  = true
      API.auto_method    = true
      API.auto_unicode   = false

      private

      S_IFMT   = 0170000 # file type mask
      S_IFDIR  = 0040000 # directory
      S_IFCHR  = 0020000 # character special
      S_IFIFO  = 0010000 # pipe
      S_IFREG  = 0100000 # regular
      S_IREAD  = 0000400 # read permission, owner
      S_IWRITE = 0000200 # write permission, owner
      S_IEXEC  = 0000100 # execute/search permission, owner
       
      SH_DENYNO = 0x40     # deny none mode
      SHORT_LIVED = 0x1000 # temporary file storage

      API.new('clearerr', 'I', 'V', MSVCRT_DLL)
      API.new('_close', 'I', 'V', MSVCRT_DLL)
      API.new('fclose', 'I', 'I', MSVCRT_DLL)
      API.new('_fcloseall', 'V', 'I', MSVCRT_DLL)
      API.new('_fdopen', 'IP', 'I', MSVCRT_DLL)
      API.new('feof', 'I', 'I', MSVCRT_DLL)
      API.new('ferror', 'L', 'I', MSVCRT_DLL)
      API.new('fflush', 'I', 'I', MSVCRT_DLL)
      API.new('fgetc', 'L', 'I', MSVCRT_DLL)
      API.new('fgetpos', 'LP', 'I', MSVCRT_DLL)
      API.new('fgetwc', 'L', 'I', MSVCRT_DLL)
      API.new('fgets', 'PIL', 'P', MSVCRT_DLL)
      API.new('fgetws', 'PIL', 'P', MSVCRT_DLL)
      API.new('_fileno', 'I', 'I', MSVCRT_DLL)
      API.new('_flushall', 'V', 'I', MSVCRT_DLL)
      API.new('fopen', 'PP', 'I', MSVCRT_DLL)
      API.new('fputs', 'PL', 'I', MSVCRT_DLL)
      API.new('fputws', 'PL', 'I', MSVCRT_DLL)
      API.new('getc', 'L', 'I', MSVCRT_DLL)
      API.new('getwc', 'L', 'L', MSVCRT_DLL)
      API.new('_open', 'PII', 'I', MSVCRT_DLL)
      API.new('_rmtmp', 'V', 'I', MSVCRT_DLL)
      API.new('_setmode', 'II', 'I', MSVCRT_DLL)
      API.new('_sopen', 'PIII', 'I', MSVCRT_DLL)
      API.new('_tempnam', 'PP', 'P', MSVCRT_DLL)
      API.new('tmpfile', 'V', 'L', MSVCRT_DLL)
      API.new('tmpnam', 'P', 'P', MSVCRT_DLL)

      # Wide character versions

      API.new('_wopen', 'PII', 'I', MSVCRT_DLL)
      API.new('_wfdopen', 'IP', 'I', MSVCRT_DLL)
      API.new('_wfopen', 'PPI', 'I', MSVCRT_DLL)
      API.new('_wsopen', 'PIII', 'I', MSVCRT_DLL)
      API.new('_wtempnam', 'PP', 'P', MSVCRT_DLL)
      API.new('_wtmpnam', 'P', 'P', MSVCRT_DLL)

      # VC++ 8.0 or later
      begin
        API.new('_sopen_s', 'PPIII', 'L', MSVCRT_DLL)
        API.new('_tmpfile_s', 'P', 'L', MSVCRT_DLL)
        API.new('_wsopen_s', 'PPIII', 'L', MSVCRT_DLL)
      rescue Win32::API::LoadLibraryError
        # Ignore - you must check for it via 'defined?'
      end
    end
  end
end
