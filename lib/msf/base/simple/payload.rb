# -*- coding: binary -*-

require 'msf/base'

module Msf
module Simple

###
#
# Simple payload wrapper class for performing generation.
#
###
module Payload

  include Module

  #
  # Generate a payload with the mad skillz.  The payload can be generated in
  # a number of ways.
  #
  # opts can have:
  #
  #   Encoder     => A encoder module name.
  #   BadChars    => A string of bad characters.
  #   Format      => The format to represent the data as: ruby, perl, c, raw
  #   Options     => A hash of options to set.
  #   OptionStr   => A string of options in VAR=VAL form separated by
  #                  whitespace.
  #   NoComment   => Disables prepention of a comment
  #   NopSledSize => The number of NOPs to use
  #   MaxSize     => The maximum size of the payload.
  #   Iterations  => Number of times to encode.
  #   Force       => Force encoding.
  #
  # raises:
  #
  #   BadcharError => If the supplied encoder fails to encode the payload
  #   NoKeyError => No valid encoder key could be found
  #   ArgumentParseError => Options were supplied improperly
  #
  def self.generate_simple(payload, opts, &block)

    # Clone the module to prevent changes to the original instance
    payload = payload.replicant
    Msf::Simple::Framework.simplify_module(payload)
    yield(payload) if block_given?

    # Import any options we may need
    payload._import_extra_options(opts)
    framework = payload.framework

    # Generate the payload
    e = EncodedPayload.create(payload,
        'BadChars' => opts['BadChars'],
        'MinNops'  => opts['NopSledSize'],
        'Encoder'  => opts['Encoder'],
        'Iterations'  => opts['Iterations'],
        'ForceEncode' => opts['ForceEncode'],
        'Space'    => opts['MaxSize'])

    fmt = opts['Format'] || 'raw'

    exeopts = {
      :inject => opts['KeepTemplateWorking'],
      :template => opts['Template'],
      :template_path => opts['ExeDir']
    }

    arch = payload.arch
    plat = opts['Platform'] || payload.platform

    # Save off the original payload length
    len = e.encoded.length


    if arch.index(ARCH_JAVA) and fmt == 'war'
      return e.encoded_war.pack
    end

    output = Msf::Util::EXE.to_executable_fmt(framework, arch, plat, e.encoded, fmt, exeopts)

    if not output
      # Generate jar if necessary
      if fmt == 'jar'
        return e.encoded_jar.pack
      end

      # Serialize the generated payload to some sort of format
      fmt ||= "ruby"
      output = Buffer.transform(e.encoded, fmt)

      # Prepend a comment
      if (fmt != 'raw' and opts['NoComment'] != true)
        ((ou = payload.options.options_used_to_s(payload.datastore)) and ou.length > 0) ? ou += "\n" : ou = ''
        output =
          Buffer.comment(
            "#{payload.refname} - #{len} bytes#{payload.staged? ? " (stage 1)" : ""}\n" +
            "http://www.metasploit.com\n" +
            ((e.encoder) ? "Encoder: #{e.encoder.refname}\n" : '') +
            ((e.nop) ?     "NOP gen: #{e.nop.refname}\n" : '') +
            "#{ou}",
            fmt) +
          output

        # If it's multistage, include the second stage too
        if payload.staged?
          stage = payload.generate_stage

          # If a stage was generated, then display it
          if stage and stage.length > 0
            output +=
              "\n" +
              Buffer.comment(
                "#{payload.refname} - #{stage.length} bytes (stage 2)\n" +
                "http://www.metasploit.com\n",
                fmt) +
              Buffer.transform(stage, fmt)
          end
        end

      end

    end

    # How to warn?
    #if exeopts[:fellback]
    #	$stderr.puts(OutError + "Warning: Falling back to default template: #{exeopts[:fellback]}")
    #end

    return output
  end

  #
  # Calls the class method.
  #
  def generate_simple(opts, &block)
    Msf::Simple::Payload.generate_simple(self, opts, &block)
  end

end

end
end
