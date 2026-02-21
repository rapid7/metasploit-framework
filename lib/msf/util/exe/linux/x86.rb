module Msf::Util::EXE::Linux::X86
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::Linux::Common


  def self.included(base)
    base.extend(ClassMethods)
  end
  
  module ClassMethods

    # Create a 32-bit Linux ELF containing the payload provided in +code+
    # to_linux_x86_elf
    #
    # @param framework  [Msf::Framework]  The framework of you want to use
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String] Returns an elf
    def to_linux_x86_elf(framework, code, opts = {})
      default = true unless opts[:template]

      return to_exe_elf(framework, opts, "template_x86_linux.bin", code) if default
      return to_linux_x86_custom_elf(framework, code, opts)
    end

    # Create a 32-bit Linux ELF containing the payload provided in +code+ with custom template
    # to_linux_x86_custom_elf
    #
    # @param framework [Msf::Framework]
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String] Returns an elf
    def to_linux_x86_custom_elf(framework, code, opts = {})
      # Use set_template_default to normalize the :template key. It will just end up doing
      # opts[:template] = File.join(opts[:template_path], opts[:template])
      # for us, check if the file exists.
      set_template_default(opts, 'template_x86_linux.bin')

      # If this isn't our normal template, we have to do some fancy
      # header patching to mark the .text section rwx before putting our
      # payload into the entry point.

      # read in the template and parse it
      e = Metasm::ELF.decode_file(opts[:template])

      # This will become a modified copy of the template's original phdr
      new_phdr = Metasm::EncodedData.new
      e.segments.each { |s|
        # Be lazy and mark any executable segment as writable.  Doing
        # it this way means we don't have to care about which one
        # contains .text
        s.flags += [ "W" ] if s.flags.include? "X"
        new_phdr << s.encode(e)
      }

      # Copy the original file
      elf = get_file_contents(opts[:template], "rb")

      # Replace the header with our rwx modified version
      elf[e.header.phoff, new_phdr.data.length] = new_phdr.data

      # Replace code at the entrypoint with our payload
      entry_off = e.addr_to_off(e.label_addr('entrypoint'))
      elf[entry_off, code.length] = code
    end


    # Create a 32-bit Linux ELF_DYN containing the payload provided in +code+
    # to_linux_x86_elf_dll
    #
    # @param framework [Msf::Framework]
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String] Returns an elf
    def to_linux_x86_elf_dll(framework, code, opts = {})
      to_exe_elf(framework, opts, "template_x86_linux_dll.bin", code)
    end
  end

  class << self
    include ClassMethods
  end

end
