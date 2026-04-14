require 'erb'
require 'metasploit/framework/compiler/windows'
require 'metasploit/framework/compiler/mingw'
require 'pry'
require 'pry-byebug'

# -*- coding: binary -*-
module Msf::Util::EXE::Windows::X64
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::Windows::Common
  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    
    # @param framework [Msf::Framework] The Metasploit framework instance.
    # @param code [String] The shellcode to embed in the executable.
    # @param opts [Hash] Additional options.
    # @return [String] The constructed PE executable as a binary string.

    def to_win64pe(framework, code, opts = {})
      # Use the standard template if not specified by the user.
      # This helper finds the full path and stores it in opts[:template].
      set_template_default(opts, 'template_x64_windows.exe')
      
      # -----------------------------
      payload_length = code.bytesize
      payload = code.bytes.map { |b| "\\x%02x" % b }.join
      template_path = File.join(Msf::Config.data_directory, 'templates','template_x64_windows.erb')
      erb = ERB.new(File.read(template_path))
      c_source = erb.result(binding)
      comp_obj = Metasploit::Framework::Compiler::Mingw::X64.new(opts)
      compiler_out = comp_obj.compile_c(c_source)
      bin = Metasploit::Framework::Compiler::Windows.compile_c(c_source, :exe,Metasm::X86_64.new)
      # -----------------------------
      # Try to inject code into executable by adding a section without affecting executable behavior
      if opts[:inject]
        injector = Msf::Exe::SegmentInjector.new({
           :payload  => code,
           :template => opts[:template],
           :arch     => :x64,
           :secname  => opts[:secname]
        })
        return injector.generate_pe
      end

      # Append a new section instead
      appender = Msf::Exe::SegmentAppender.new({
        :payload  => code,
        :template => opts[:template],
        :arch     => :x64,
        :secname	=> opts[:secname]
      })
      return appender.generate_pe
    end

    # to_win64pe_service
    #
    # @param framework  [Msf::Framework]  The framework of you want to use
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :exe_type
    # @option           [String] :service_exe
    # @option           [String] :dll
    # @option           [String] :inject
    # @return           [String]
    def to_win64pe_service(framework, code, opts = {})
      # Allow the user to specify their own service EXE template
      set_template_default(opts, "template_x64_windows_svc.exe")
      opts[:exe_type] = :service_exe
      exe_sub_method(code,opts)
    end

    # to_win64pe_dll
    #
    # @param framework  [Msf::Framework]  The framework of you want to use
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :exe_type
    # @option           [String] :dll
    # @option           [String] :inject
    # @return           [String]
    def to_win64pe_dll(framework, code, opts = {})
      flavor = opts.fetch(:mixed_mode, false) ? 'mixed_mode' : nil
      set_template_default_winpe_dll(opts, ARCH_X64, code.size, flavor: flavor)

      opts[:exe_type] = :dll

      if opts[:inject]
        raise RuntimeError, 'Template injection unsupported for x64 DLLs'
      else
        exe_sub_method(code,opts)
      end
    end
    
    # to_win64pe_dccw_gdiplus_dll
    #
    # @param framework  [Msf::Framework]  The framework of you want to use
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :exe_type
    # @option           [String] :dll
    # @option           [String] :inject
    # @return           [String]
    def to_win64pe_dccw_gdiplus_dll(framework, code, opts = {})
      set_template_default_winpe_dll(opts, ARCH_X64, code.size, flavor: 'dccw_gdiplus')
      to_win64pe_dll(framework, code, opts)
    end
  end
  class << self
    include ClassMethods
  end
end
