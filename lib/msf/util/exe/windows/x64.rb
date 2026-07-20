# -*- coding: binary -*-
module Msf::Util::EXE::Windows::X64
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::Windows::Common
  
  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    # to_win64pe
    #
    # Construct a Windows x64 PE executable with the given shellcode.
    #
    # @param framework  [Msf::Framework]  The framework of you want to use
    # @param code       [String]
    # @param opts       [Hash]
    # @return           [String]
    def to_win64pe(framework, code, opts = {})
      # Allow the user to specify their own EXE template
      set_template_default(opts, "template_x64_windows.exe")

      # Try to inject code into executable by adding a section without affecting executable behavior
      if opts[:inject]
        injector = Msf::Exe::SegmentInjector.new({
          :payload      => code,
          :template     => opts[:template],
          :arch         => :x64,
          :section_name => opts[:section_name] || opts[:secname]
        })
        return injector.generate_pe
      end

      # Append a new section instead
      hijacker = Msf::Exe::SegmentHijacker.new({
        :payload      => code,
        :template     => opts[:template],
        :arch         => :x64,
        :section_name => opts[:section_name] || opts[:secname]
      })
      return hijacker.generate_pe
    end

    # to_win64pe_service
    #
    # Embeds the payload into a Windows service EXE template as a dedicated PE
    # section, which the service template locates at runtime.
    #
    # @param framework  [Msf::Framework]  The framework of you want to use
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :servicename name of the service
    # @option           [String] :section_name name of the appended payload section
    # @return           [String]
    def to_win64pe_service(framework, code, opts = {})
      # Allow the user to specify their own service EXE template
      set_template_default(opts, "template_x64_windows_svc.exe")
      to_winpe_service(code, :x64, opts)
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
