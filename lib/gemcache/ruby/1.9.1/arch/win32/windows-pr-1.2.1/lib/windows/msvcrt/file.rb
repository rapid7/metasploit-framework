require 'windows/api'

module Windows
  module MSVCRT
    module File
      API.auto_namespace = 'Windows::MSVCRT::File'
      API.auto_method    = true
      API.auto_constant  = true
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

      API.new('_chmod', 'PI', 'I', MSVCRT_DLL)
      API.new('_chsize', 'IL', 'I', MSVCRT_DLL)
      API.new('_mktemp', 'P', 'P', MSVCRT_DLL)
      API.new('_stat', 'PP', 'I', 'msvcrt')
      API.new('_stat64', 'PP', 'I', MSVCRT_DLL)
      API.new('_umask', 'I', 'I', MSVCRT_DLL)

      # Wide character variants

      API.new('_wchmod', 'PI', 'I', MSVCRT_DLL)
      API.new('_wmktemp', 'P', 'P', MSVCRT_DLL)
      API.new('_wstat', 'PP', 'I', 'msvcrt')
      API.new('_wstat64', 'PP', 'I', MSVCRT_DLL)

      # VC++ 8.0 or later
      begin
        API.new('_chsize_s', 'IL', 'I', MSVCRT_DLL)
        API.new('_mktemp_s', 'PL', 'L', MSVCRT_DLL)
        API.new('_umask_s', 'IP', 'L', MSVCRT_DLL)
        API.new('_wmktemp_s', 'PL', 'L', MSVCRT_DLL)
      rescue Win32::API::LoadLibraryError
        # Ignore - you must check for it via 'defined?'
      end
    end
  end
end
