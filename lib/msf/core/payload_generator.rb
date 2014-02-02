module Msf

  class IncompatiblePlatform < StandardError
  end

  class PayloadGenerator


    attr_accessor :add_code
    attr_accessor :arch
    attr_accessor :badchars
    attr_accessor :datastore
    attr_accessor :encoder
    attr_accessor :format
    attr_accessor :framework
    attr_accessor :iterations
    attr_accessor :keep
    attr_accessor :nops
    attr_accessor :payload
    attr_accessor :platform
    attr_accessor :space
    attr_accessor :template


    # @param [Hash] opts The options hash
    # @option opts [String] :payload The refname of the payload to generate
    # @option opts [String] :format The format you want the payload returned in
    # @option opts [String] :encoder The encoder you want applied to the payload
    # @option opts [Fixnum] :iterations The number of iterations to run the encoder
    # @option opts [String] :arch The CPU architecture to build the payload for
    # @option opts [String] :platform The platform to build the payload for
    # @option opts [String] :badchars The bad characters that can't be in the payload
    # @option opts [String] :template The path to the template file to use
    # @option opts [Fixnum] :space The maximum size in bytes of the payload
    # @option opts [Fixnum] :nops The size in bytes of NOP sled to prepend the payload with
    # @option opts [String] :add_code The path to a shellcode file to execute in a seperate thread
    # @option opts [Boolean] :keep Whether or not to preserve the original functionality of the template
    # @option opts [Hash] :datastore The datastore to apply to the payload module
    # @option opts [Msf::Framework] :framework The framework instance to use for generation
    def initialize(opts={})
      @add_code   = opts.fetch(:add_code, false)
      @arch       = opts.fetch(:arch, '')
      @badchars   = opts.fetch(:badchars, '')
      @datastore  = opts.fetch(:datastore, {})
      @encoder    = opts.fetch(:encoder, '')
      @format     = opts.fetch(:format, 'raw')
      @iterations = opts.fetch(:iterations, 1)
      @keep       = opts.fetch(:keep, false)
      @nops       = opts.fetch(:nops, 0)
      @payload    = opts.fetch(:payload, '')
      @platform   = opts.fetch(:platform, '')
      @space      = opts.fetch(:size, 1073741824)
      @template   = opts.fetch(:template, '')

      @framework  = opts.fetch(:framework)

      raise ArgumentError, "Invalid Payload Selected" unless payload_is_valid?
      raise ArgumentError, "Invalid Format Selected" unless format_is_valid?
    end


    def generate_raw_payload
      payload_module = framework.payloads.create(payload)

      chosen_platform = choose_platform(payload_module)
      if chosen_platform.platforms.empty?
        raise IncompatiblePlatform, "The selected platform is Incompatible with the Payload"
      end

    end

    # @return [Msf::Module::PlatformList] It will be empty if no valid platforms found
    def platform_list
      begin
        list = ::Msf::Module::PlatformList.transform(platform)
      rescue
        list = Msf::Module::PlatformList.new
      end
      return list
    end

    private

    def choose_platform(mod)
      chosen_platform = platform_list
      if chosen_platform.platforms.empty?
        chosen_platform = mod.platform
      elsif (chosen_platform & mod.platform).empty?
        chosen_platform = Msf::Module::PlatformList.new
      end
      chosen_platform
    end

    # @return [True] if the payload is a valid Metasploit Payload
    # @return [False] if the payload is not a valid Metasploit Payload
    def payload_is_valid?
      framework.payloads.keys.include? payload
    end

    # @return [True] if the format is valid
    # @return [False] if the format is not valid
    def format_is_valid?
      formats = (::Msf::Util::EXE.to_executable_fmt_formats + ::Msf::Simple::Buffer.transform_formats).uniq
      formats.include? format
    end



  end
end
