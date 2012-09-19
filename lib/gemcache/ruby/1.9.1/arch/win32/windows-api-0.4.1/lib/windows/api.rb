require 'win32/api'
require 'rbconfig'
require 'forwardable'
include RbConfig

# The Windows module serves as a namespace only
module Windows

  # With Microsoft Visual C++ 8 and later users should use the associated
  # DLL instead of msvcrt directly, if possible.
  if CONFIG['host_os'].split('_')[1]
    if CONFIG['host_os'].split('_')[1].to_i >= 80 &&
      File.exists?(File.join(CONFIG['bindir'], 'ruby.exe.manifest'))
    then
      MSVCRT_DLL = 'msvcr' + CONFIG['host_os'].split('_')[1]
    else
      MSVCRT_DLL = 'msvcrt'
    end
  else
    MSVCRT_DLL = 'msvcrt'
  end

  # Wrapper around the Win32::API class
  class API
    extend Forwardable

    # The version of the windows-api library
    VERSION = '0.4.1'

    # The methods from Win32::API are delegated to the appropriate object
    def_delegators(:@api, :function_name, :dll_name, :prototype)
    def_delegators(:@api, :return_type, :effective_function_name)

    private

    # Verbose data types that can be used instead of single letters
    DATA_TYPES = {
      'ATOM'         => 'I',
      'BOOL'         => 'B',
      'BOOLEAN'      => 'B',
      'BYTE'         => 'I',
      'CALLBACK'     => 'K',
      'CHAR'         => 'I',
      'COLORREF'     => 'L',
      'DWORD'        => 'L',
      'DWORDLONG'    => 'L',
      'DWORD_PTR'    => 'P',
      'DWORD32'      => 'I',
      'DWORD64'      => 'L',
      'HACCEL'       => 'L',
      'HANDLE'       => 'L',
      'HBITMAP'      => 'L',
      'HBRUSH'       => 'L',
      'HCOLORSPACE'  => 'L',
      'HCONV'        => 'L',
      'HDC'          => 'L',
      'HFILE'        => 'I',
      'HKEY'         => 'L',
      'HFONT'        => 'L',
      'HINSTANCE'    => 'L',
      'HKEY'         => 'L',
      'HLOCAL'       => 'L',
      'HMENU'        => 'L',
      'HMODULE'      => 'L',
      'HRESULT'      => 'L',
      'HWND'         => 'L',
      'INT'          => 'I',
      'INT_PTR'      => 'P',
      'INT32'        => 'I',
      'INT64'        => 'L',
      'LANGID'       => 'I',
      'LCID'         => 'L',
      'LCTYPE'       => 'L',
      'LONG'         => 'L',
      'LONGLONG'     => 'L',
      'LONG_PTR'     => 'P',
      'LONG32'       => 'L',
      'LONG64'       => 'L',
      'LPARAM'       => 'P',
      'LPBOOL'       => 'P',
      'LPBYTE'       => 'P',
      'LPCOLORREF'   => 'P',
      'LPCSTR'       => 'P',
      'LPCTSTR'      => 'P',
      'LPCVOID'      => 'L',
      'LPCWSTR'      => 'P',
      'LPDWORD'      => 'P',
      'LPHANDLE'     => 'P',
      'LPINT'        => 'P',
      'LPLONG'       => 'P',
      'LPSTR'        => 'P',
      'LPTSTR'       => 'P',
      'LPVOID'       => 'L',
      'LPWORD'       => 'P',
      'LPWSTR'       => 'P',
      'LRESULT'      => 'P',
      'PBOOL'        => 'P',
      'PBOOLEAN'     => 'P',
      'PBYTE'        => 'P',
      'PHKEY'        => 'P',
      'SC_HANDLE'    => 'L',
      'SC_LOCK'      => 'L',
      'SERVICE_STATUS_HANDLE' => 'L',
      'SHORT'        => 'I',
      'SIZE_T'       => 'P',
      'TCHAR'        => 'L',
      'UINT'         => 'I',
      'UINT_PTR'     => 'P',
      'UINT32'       => 'I',
      'UINT64'       => 'L',
      'ULONG'        => 'L',
      'ULONGLONG'    => 'L',
      'ULONG_PTR'    => 'P',
      'ULONG32'      => 'L',
      'ULONG64'      => 'L',
      'USHORT'       => 'I',
      'USN'          => 'L',
      'WINAPI'       => 'L',
      'WORD'         => 'I'
    }

    public

    @auto_constant  = false
    @auto_method    = false
    @auto_unicode   = false
    @auto_namespace = nil

    # Returns the value of the @auto_constant class instance variable. The
    # default is nil, i.e. none. See the Windows::API.auto_constant=
    # documentation for more information.
    #
    def self.auto_constant
      @auto_constant
    end

    # Automatically sets a constant to match the function name.
    #
    # The standard practice for defining Windows::API objects is to use
    # a constant that matches the function name. For example, this is a
    # typical idiom:
    #
    #    module Windows
    #       module File
    #          GetFileAttributes = API.new('GetFileAttributes', 'P','L')
    #       end
    #    end
    #
    # With the API.auto_constant value set to true you can avoid the
    # assignment step and the matching constant name will be automatically
    # set for you in the namespace defined in API.auto_namespace. In other
    # words, this example is identical to the one above:
    #
    #    module Windows
    #       module File
    #          API.auto_constant  = true
    #          API.auto_namespace = 'Windows::File'
    #          API.new('GetFileAttributes', 'P', 'L')
    #       end
    #    end
    #
    # If the auto_constant class variable is set to true, but no
    # auto_namespace is set, an error will be raised. Note that the
    # namespace must refer to an existing module (not a class).
    #--
    # TODO: If there's a way to automatically grab the namespace internally,
    # nesting and all, I'd love to know the solution.
    #
    def self.auto_constant=(bool)
      @auto_constant = bool
    end

    # Returns the value of the auto_namespace class instance variable. Used
    # in conjunction with API.auto_constant and/or API.auto_method.
    #
    def self.auto_namespace
      @auto_namespace
    end

    # Sets the value of the auto_namespace class nstance variable. The
    # default is nil, i.e. none. Use in conjunction with the auto_constant
    # and/or auto_method class variables, this method will automatically set
    # a constant and/or method in +namespace+ equal to the function name set
    # in the constructor.
    #
    # The +namespace+ must refer to an existing module, not a class.
    #
    def self.auto_namespace=(namespace)
      @auto_namespace = namespace
    end

    # Returns the value of the auto_method class instance variable. Used in
    # conjunction with auto_unicode.  See API.auto_method= for more
    # information.
    #
    def self.auto_method
      @auto_method
    end

    # If this option is set to true then a corresponding method is
    # automatically generated when you create a new Windows::API object.
    #
    # For example, instead of doing this:
    #
    #    module Windows
    #       module File
    #          GetFileAttributes = API.new('GetFileAttributes', 'P', 'L')
    #
    #          def GetFileAttributes(x)
    #             GetFileAttributes.call(x)
    #          end
    #       end
    #    end
    #
    # You can do this, and have the method autogenerated for you.
    #
    #    module Windows
    #       module File
    #          API.auto_namespace = 'Windows::File'
    #          API.auto_constant  = true
    #          API.auto_method    = true
    #          API.new('GetFileAttributes', 'P', 'L')
    #       end
    #    end
    #
    #    include Windows::File
    #    GetFileAttributes('C:/test.txt') # vs. GetFileAttributes.call
    #
    # If the Windows::API object is declared to be a boolean in the
    # constructor, then the method definition automatically includes a
    # '!= 0' clause at the end of the call. That way, you can do
    # 'if SomeMethod(x)' instead of having to do 'if SomeMethod(x) != 0',
    # and it will do the right thing.
    #
    # If the API.auto_unicode option is also set to true, then you will
    # get three method definitions. The standard function name, the explicit
    # ANSI ('A') version and the explicit Unicode/wide version ('W'). The
    # exception to this rule is that the explicit ANSI and Unicode methods
    # will NOT be generated if the function passed to the constructor
    # already ends with 'A' or 'W'.
    #
    def self.auto_method=(bool)
      @auto_method = bool
    end

    # Returns the value of the auto_unicode class instance variable. This
    # is used in conjunction with the auto_method and/or auto_constant class
    # variables. Not significant if neither of those variables are set.
    #
    def self.auto_unicode
      @auto_unicode
    end

    # If set to true, and the auto_constant variable is set, then the
    # automatic constant generation will generate the explicit ANSI ('A')
    # and Unicode/wide ('W') versions of the function passed to the
    # constructor, if such versions exist.  Likewise, if the the
    # auto_method variable is set, then explicit ANSI and Unicode methods
    # are generated.
    #
    # Here's a typical idiom:
    #
    # module Windows
    #    module Path
    #       API.auto_namespace = Windows::Path
    #       API.auto_constant = true
    #       API.new('shlwapi', 'PathAddBackslash', 'P', 'P')
    #       API.new('shlwapi', 'PathAddBackslashA', 'P', 'P')
    #       API.new('shlwapi', 'PathAddBackslashW', 'P', 'P')
    #    end
    # end
    #
    # That can be reduced to this:
    #
    # module Windows
    #    module Path
    #       API.auto_namespace = Windows::Path
    #       API.auto_constant = true
    #       API.auto_unicode  = true
    #       API.new('shlwapi', 'PathAddBackslash', 'P', 'P')
    #    end
    # end
    #
    # This value is ignored if the function passed to the constructor
    # already ends with an 'A' or 'W'.
    #
    def self.auto_unicode=(bool)
      @auto_unicode = bool
    end

    # call-seq:
    #    API.new(func, proto='V', rtype='L', dll='kernel32')
    #
    # Creates and returns a new Windows::API object.  The +func+ is the
    # name of the Windows function.
    #
    # The +proto+ is the function prototype for +func+.  This can be a
    # string or an array of characters.  The possible valid characters
    # are 'I' (integer), 'B' (BOOL), 'L' (long), 'V' (void), or 'P' (pointer).
    # The default is void ('V').
    #
    # The +rtype+ argument is the return type for the function.  The valid
    # characters are the same as for the +proto+. The default is long ('L').
    #
    # The 'B' (BOOL) return type is the same as 'I' (Integer). This is
    # significant only if the API.auto_method option is set to true, in which
    # case it alters the generated method definition slightly. See the
    # API.auto_method= class method for more information.
    #
    # The +dll+ is the name of the DLL file that the function is exported
    # from. The default is 'kernel32'.
    #
    # If the function cannot be found then an API::Error is raised (a subclass
    # of RuntimeError).
    #
    def initialize(func, proto='V', rtype='L', dll='kernel32')
      # Convert literal data types to values that win32-api understands
      if proto.is_a?(Array)
        proto.each_with_index{ |pt, index|
          if pt.length > 1
            proto[index].replace(DATA_TYPES[pt])
          end
        }
      end

      if rtype.length > 1
        rtype.replace(DATA_TYPES[rtype])
      end

      @function_name = func
      @prototype     = proto
      @return_type   = rtype == 'B' ? 'I' : rtype
      @dll_name      = dll
      @boolean       = rtype == 'B' ? true : false

      @api = Win32::API.new(func, proto, rtype, dll)

      api_a = nil
      api_w = nil

      # If the auto_unicode option is set, and the func is not already
      # an explicit ANSI or Wide function name, generate Win32::API
      # objects for those functions as well. Ignore errors because not
      # all functions have explicit ANSI or Wide character implementations.
      #
      # This entire bit of logic is skipped if the DLL is msvcrt, since
      # msvcrt functions never have explicit ANSI or Wide character
      # versions.
      #
      if Windows::API.auto_unicode && dll !~ /msvcr/i
        begin
          unless ['A', 'W'].include?(func[-1].chr)
            api_a = Win32::API.new("#{func}A", proto, rtype, dll)
          end
        rescue RuntimeError
        end

        begin
          unless ['W', 'A'].include?(func[-1].chr)
            api_w = Win32::API.new("#{func}W", proto, rtype, dll)
          end
        rescue RuntimeError
        end
      end

      func_upper = nil

      # Automatically define a constant matching the function name if the
      # auto_constant option is set. Lower case method names will have a
      # capitalized equivalent created, e.g. Memcpy for memcpy, etc.
      #
      if Windows::API.auto_constant && Windows::API.auto_namespace
        if Windows::API.auto_namespace != 'Windows'
          namespace = class_for(Windows::API.auto_namespace)
        else
          namespace = Windows::API.auto_namespace
        end

        # Convert e.g. 'strstr' to 'Strstr' as an equivalent constant
        if ('A'..'Z').include?(func[0].chr)
          namespace.const_set(func, @api)
        else
          func_upper = func.dup
          if func_upper[0].chr == '_'
            func_upper = func_upper[1, func_upper.length]
          end
          func_upper[0, 1] = func_upper[0].chr.capitalize
          namespace.const_set(func_upper, @api)
        end

        # Automatically define the explicit ANSI and Unicode functions
        # as constants as well, if appropriate.
        #
        if Windows::API.auto_unicode
          namespace.const_set("#{func}A", api_a) if api_a
          namespace.const_set("#{func}W", api_w) if api_w
        end
      end

      # Automatically define a method in the auto_namespace if the
      # auto_method option is set. The explicit ANSI and Unicode methods
      # are added as well if the auto_unicode option is set to true.
      #
      if Windows::API.auto_method && Windows::API.auto_namespace
        if proto == 'V'
          proto = ''
        else
          n = 0
          if proto.is_a?(String)
            proto = proto.split('').map{ |e|
              n += 1
              e.downcase + n.to_s
            }.join(', ')
          else
            proto = proto.map{ |e|
              n += 1
              e.downcase + n.to_s
            }.join(', ')
          end
        end

        # Use the upper case function equivalent if defined
        call_func = func_upper || func

        if @boolean
          string = <<-EOC
            module #{Windows::API.auto_namespace}
              def #{func}(#{proto})
                #{call_func}.call(#{proto}) != 0
              end
            EOC

          if api_a
            string << %Q{
              def #{func}A(#{proto})
                #{call_func}A.call(#{proto}) != 0
              end
            }
          end

          if api_w
            string << %Q{
              def #{func}W(#{proto})
                #{call_func}W.call(#{proto}) != 0
              end
            }
          end

          string << 'end'
        else
          string = <<-EOC
            module #{Windows::API.auto_namespace}
              def #{func}(#{proto})
                #{call_func}.call(#{proto})
              end
            EOC

          if api_a
            string << %Q{
              def #{func}A(#{proto})
                #{call_func}A.call(#{proto})
              end
            }
          end

          if api_w
            string << %Q{
              def #{func}W(#{proto})
                #{call_func}W.call(#{proto})
              end
            }
          end

          # Create aliases for methods with an underscore that do not
          # require an underscore, e.g. umask and _umask.
          if func[0].chr == '_'
            func_alias = func[1, func.length]
            string << "alias #{func_alias} #{func}\n"
          end

          string << 'end'
        end

        eval(string)
      end
    end

    # Calls the function name set in the constructor.
    #
    def call(*args)
      @api.call(*args)
    end

    private

    # Get a module's namespace. This is basically the equivalent of
    # the rb_path2class() function from intern.h
    #
    def class_for(class_name)
      names = class_name.split("::")
      result = Object
      names.each{ |n| result = result.const_get(n) }
      result
    end
  end
end
