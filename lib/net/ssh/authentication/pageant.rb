require 'dl/import'
require 'dl/struct'

require 'net/ssh/errors'

module Net; module SSH; module Authentication

  # This module encapsulates the implementation of a socket factory that
  # uses the PuTTY "pageant" utility to obtain information about SSH
  # identities.
  #
  # This code is a slightly modified version of the original implementation
  # by Guillaume Marçais (guillaume.marcais@free.fr). It is used and
  # relicensed by permission.
  module Pageant

    # From Putty pageant.c
    AGENT_MAX_MSGLEN = 8192
    AGENT_COPYDATA_ID = 0x804e50ba
    
    # The definition of the Windows methods and data structures used in
    # communicating with the pageant process.
    module Win
      extend DL::Importable
      
      dlload 'user32'
      dlload 'kernel32'
      
      typealias("LPCTSTR", "char *")         # From winnt.h
      typealias("LPVOID", "void *")          # From winnt.h
      typealias("LPCVOID", "const void *")   # From windef.h
      typealias("LRESULT", "long")           # From windef.h
      typealias("WPARAM", "unsigned int *")  # From windef.h
      typealias("LPARAM", "long *")          # From windef.h
      typealias("PDWORD_PTR", "long *")      # From basetsd.h

      # From winbase.h, winnt.h
      INVALID_HANDLE_VALUE = -1
      NULL = nil
      PAGE_READWRITE = 0x0004
      FILE_MAP_WRITE = 2
      WM_COPYDATA = 74

      SMTO_NORMAL = 0   # From winuser.h

      # args: lpClassName, lpWindowName
      extern 'HWND FindWindow(LPCTSTR, LPCTSTR)'

      # args: none
      extern 'DWORD GetCurrentThreadId()'

      # args: hFile, (ignored), flProtect, dwMaximumSizeHigh,
      #           dwMaximumSizeLow, lpName
      extern 'HANDLE CreateFileMapping(HANDLE, void *, DWORD, DWORD, ' +
                                      'DWORD, LPCTSTR)'

      # args: hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, 
      #           dwfileOffsetLow, dwNumberOfBytesToMap
      extern 'LPVOID MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, DWORD)'

      # args: lpBaseAddress
      extern 'BOOL UnmapViewOfFile(LPCVOID)'

      # args: hObject
      extern 'BOOL CloseHandle(HANDLE)'

      # args: hWnd, Msg, wParam, lParam, fuFlags, uTimeout, lpdwResult
      extern 'LRESULT SendMessageTimeout(HWND, UINT, WPARAM, LPARAM, ' +
                                        'UINT, UINT, PDWORD_PTR)'
    end

    # This is the pseudo-socket implementation that mimics the interface of
    # a socket, translating each request into a Windows messaging call to
    # the pageant daemon. This allows pageant support to be implemented
    # simply by replacing the socket factory used by the Agent class.
    class Socket

      private_class_method :new

      # The factory method for creating a new Socket instance. The location
      # parameter is ignored, and is only needed for compatibility with
      # the general Socket interface.
      def self.open(location=nil)
        new
      end

      # Create a new instance that communicates with the running pageant 
      # instance. If no such instance is running, this will cause an error.
      def initialize
        @win = Win.findWindow("Pageant", "Pageant")

        if @win == 0
          raise Net::SSH::Exception,
            "pageant process not running"
        end

        @res = nil
        @pos = 0
      end
      
      # Forwards the data to #send_query, ignoring any arguments after
      # the first. Returns 0.
      def send(data, *args)
        @res = send_query(data)
        @pos = 0
      end

      # Packages the given query string and sends it to the pageant
      # process via the Windows messaging subsystem. The result is
      # cached, to be returned piece-wise when #read is called.
      def send_query(query)
        res = nil
        filemap = 0
        ptr = nil
        id = DL::PtrData.malloc(DL.sizeof("L"))

        mapname = "PageantRequest%08x\000" % Win.getCurrentThreadId()
        filemap = Win.createFileMapping(Win::INVALID_HANDLE_VALUE, 
                                        Win::NULL,
                                        Win::PAGE_READWRITE, 0, 
                                        AGENT_MAX_MSGLEN, mapname)
        if filemap == 0
          raise Net::SSH::Exception,
            "Creation of file mapping failed"
        end

        ptr = Win.mapViewOfFile(filemap, Win::FILE_MAP_WRITE, 0, 0, 
                                AGENT_MAX_MSGLEN)

        if ptr.nil? || ptr.null?
          raise Net::SSH::Exception, "Mapping of file failed"
        end

        ptr[0] = query
        
        cds = [AGENT_COPYDATA_ID, mapname.size + 1, mapname].
          pack("LLp").to_ptr
        succ = Win.sendMessageTimeout(@win, Win::WM_COPYDATA, Win::NULL,
          cds, Win::SMTO_NORMAL, 5000, id)

        if succ > 0
          retlen = 4 + ptr.to_s(4).unpack("N")[0]
          res = ptr.to_s(retlen)
        end        

        return res
      ensure
        Win.unmapViewOfFile(ptr) unless ptr.nil? || ptr.null?
        Win.closeHandle(filemap) if filemap != 0
      end

      # Conceptually close the socket. This doesn't really do anthing
      # significant, but merely complies with the Socket interface.
      def close
        @res = nil
        @pos = 0
      end

      # Conceptually asks if the socket is closed. As with #close,
      # this doesn't really do anything significant, but merely
      # complies with the Socket interface.
      def closed?
        @res.nil? && @pos.zero?
      end

      # Reads +n+ bytes from the cached result of the last query. If +n+
      # is +nil+, returns all remaining data from the last query.
      def read(n = nil)
        return nil unless @res
        if n.nil?
          start, @pos = @pos, @res.size
          return @res[start..-1]
        else
          start, @pos = @pos, @pos + n
          return @res[start, n]
        end
      end

    end

  end

end; end; end
