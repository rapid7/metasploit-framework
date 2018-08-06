require 'msf/core/module'

module Msf
  class Evasion < Msf::Module

    include Msf::Auxiliary::Report

    class Complete < RuntimeError ; end

    class Failed < RuntimeError ; end

    def initialize(info={})
      if (info['Payload'] and info['Payload']['Compat'])
        info['Compat'] = Hash.new if (info['Compat'] == nil)
        info['Compat']['Payload'] = Hash.new if (info['Compat']['Payload'] == nil)
        info['Compat']['Payload'].update(info['Payload']['Compat'])
      end

      super(info)

      self.payload_info = info['Payload'] || {}

      if (info['Payload'] and info['Payload']['ActiveTimeout'])
        self.active_timeout = info['Payload']['ActiveTimeout'].to_i
      end
    end

    def self.type
      Msf::MODULE_EVASION
    end

    def type
      Msf::MODULE_EVASION
    end

    def setup
    end

    def file_format_filename
      datastore['FILENAME']
    end

    def file_create(data)
      fname = file_format_filename
      ltype = "evasion.fileformat.#{self.shortname}"
      full_path = store_local(ltype, nil, data, fname)
      print_good "#{fname} stored at #{full_path}"
    end

    def is_payload_compatible?(name)
      p = framework.payloads[name]

      pi = p.new

      # Are we compatible in terms of conventions and connections and
      # what not?
      return false if !compatible?(pi)

      # If the payload is privileged but the exploit does not give
      # privileged access, then fail it.
      return false if !self.privileged && pi.privileged

      return true
    end

    def compatible_payloads
      payloads = []

      framework.payloads.each_module(
        'Arch' => arch, 'Platform' => platform) { |name, mod|
        payloads << [ name, mod ] if is_payload_compatible?(name)
      }

      return payloads
    end

    def run
      raise NotImplementedError
    end

    def cleanup
    end

    def fail_with(reason, msg=nil)
      raise Msf::Evasion::Failed, "#{reason}: #{msg}"
    end

    def evasion_commands
      {}
    end

    def generate_payload(pinst = nil)
      # Set the encoded payload to the result of the encoding process
      self.payload = generate_single_payload(pinst)

      # Save the payload instance
      self.payload_instance = (pinst) ? pinst : self.payload_instance

      return self.payload
    end

    def generate_single_payload(pinst = nil, platform = nil, arch = nil)
      # If a payload instance was supplied, use it, otherwise
      # use the active payload instance
      real_payload = (pinst) ? pinst : self.payload_instance

      if (real_payload == nil)
        raise MissingPayloadError, "No payload has been selected.",
          caller
      end

      # If this is a generic payload, then we should specify the platform
      # and architecture so that it knows how to pass things on.
      if real_payload.kind_of?(Msf::Payload::Generic)
        # Convert the architecture specified into an array.
        if arch and arch.kind_of?(String)
          arch = [ arch ]
        end

        # Define the explicit platform and architecture information only if
        # it's been specified.
        if platform
          real_payload.explicit_platform = Msf::Module::PlatformList.transform(platform)
        end

        if arch
          real_payload.explicit_arch = arch
        end

        # Force it to reset so that it will find updated information.
        real_payload.reset
      end

      # Duplicate the exploit payload requirements
      reqs = self.payload_info.dup

      # Pass save register requirements to the NOP generator
      reqs['Space']           = payload_info['Space'].to_i
      reqs['SaveRegisters']   = module_info['SaveRegisters']
      reqs['Prepend']         = payload_info['Prepend']
      reqs['PrependEncoder']  = payload_info['PrependEncoder']
      reqs['BadChars']        = payload_info['BadChars']
      reqs['Append']          = payload_info['Append']
      reqs['AppendEncoder']   = payload_info['AppendEncoder']
      reqs['MaxNops']         = payload_info['MaxNops']
      reqs['MinNops']         = payload_info['MinNops']
      reqs['Encoder']         = datastore['ENCODER'] || payload_info['Encoder']
      reqs['Nop']             = datastore['NOP'] || payload_info['Nop']
      reqs['EncoderType']     = payload_info['EncoderType']
      reqs['EncoderOptions']  = payload_info['EncoderOptions']
      reqs['ExtendedOptions'] = payload_info['ExtendedOptions']
      reqs['Exploit']         = self

      # Pass along the encoder don't fall through flag
      reqs['EncoderDontFallThrough'] = datastore['EncoderDontFallThrough']

      # Incorporate any context encoding requirements that are needed
      define_context_encoding_reqs(reqs)

      # Call the encode begin routine.
      encode_begin(real_payload, reqs)

      # Generate the encoded payload.
      encoded = EncodedPayload.create(real_payload, reqs)

      # Call the encode end routine which is expected to return the actual
      # encoded payload instance.
      return encode_end(real_payload, reqs, encoded)
    end

    def define_context_encoding_reqs(reqs)
      return unless datastore['EnableContextEncoding']

      # At present, we don't support any automatic methods of obtaining
      # context information.  In the future, we might support obtaining
      # temporal information remotely.

      # Pass along the information specified in our exploit datastore as
      # encoder options
      reqs['EncoderOptions'] = {} if reqs['EncoderOptions'].nil?
      reqs['EncoderOptions']['EnableContextEncoding']  = datastore['EnableContextEncoding']
      reqs['EncoderOptions']['ContextInformationFile'] = datastore['ContextInformationFile']
    end

    def encode_begin(real_payload, reqs)
    end

    def encode_end(real_payload, reqs, encoded)
      encoded
    end

    attr_reader :payload_info

    attr_accessor :payload_info

    attr_accessor :payload_instance

    attr_accessor :payload
  end
end