# -*- coding: binary -*-

require 'rex'
require 'forwardable'

module Rex
module Exploitation
module Powershell
  class Script
    attr_accessor :code
    attr_reader :functions, :rig

    include Output
    include Parser
    include Obfu
    # Pretend we are actually a string
    extend ::Forwardable
    # In case someone messes with String we delegate based on its instance methods
    # eval %Q|def_delegators :@code, :#{::String.instance_methods[0..(String.instance_methods.index(:class)-1)].join(', :')}|
    def_delegators :@code, :each_line, :strip, :chars, :intern, :chr, :casecmp, :ascii_only?, :<, :tr_s,
                   :!=, :capitalize!, :ljust, :to_r, :sum, :private_methods, :gsub, :dump, :match, :to_sym,
                   :enum_for, :display, :tr_s!, :freeze, :gsub, :split, :rindex, :<<, :<=>, :+, :lstrip!,
                   :encoding, :start_with?, :swapcase, :lstrip!, :encoding, :start_with?, :swapcase,
                   :each_byte, :lstrip, :codepoints, :insert, :getbyte, :swapcase!, :delete, :rjust, :>=,
                   :!, :count, :slice, :clone, :chop!, :prepend, :succ!, :upcase, :include?, :frozen?,
                   :delete!, :chop, :lines, :replace, :next, :=~, :==, :rstrip!, :%, :upcase!, :each_char,
                   :hash, :rstrip, :length, :reverse, :setbyte, :bytesize, :squeeze, :>, :center, :[],
                   :<=, :to_c, :slice!, :chomp!, :next!, :downcase, :unpack, :crypt, :partition,
                   :between?, :squeeze!, :to_s, :chomp, :bytes, :clear, :!~, :to_i, :valid_encoding?, :===,
                   :tr, :downcase!, :scan, :sub!, :each_codepoint, :reverse!, :class, :size, :empty?, :byteslice,
                   :initialize_clone, :to_str, :to_enum, :tap, :tr!, :trust, :encode!, :sub, :oct, :succ, :index,
                   :[]=, :encode, :*, :hex, :to_f, :strip!, :rpartition, :ord, :capitalize, :upto, :force_encoding,
                   :end_with?

    def initialize(code)
      @code = ''
      @rig = Rex::RandomIdentifierGenerator.new

      begin
        # Open code file for reading
        fd = ::File.new(code, 'rb')
        while (line = fd.gets)
          @code << line
        end

        # Close open file
        fd.close
      rescue Errno::ENAMETOOLONG, Errno::ENOENT
        # Treat code as a... code
        @code = code.to_s.dup # in case we're eating another script
      end
      @functions = get_func_names.map { |f| get_func(f) }
    end

    ##
    # Class methods
    ##

    #
    # Convert binary to byte array, read from file if able
    #
    # @param input_data [String] Path to powershell file or powershell
    #   code string
    # @param var_name [String] Byte array variable name
    #
    # @return [String] input_data as a powershell byte array
    def self.to_byte_array(input_data, var_name = Rex::Text.rand_text_alpha(rand(3) + 3))
      # File will raise an exception if the path contains null byte
      if input_data.include? "\x00"
        code = input_data
      else
        code = ::File.file?(input_data) ? ::File.read(input_data) : input_data
      end

      code = code.unpack('C*')
      psh = "[Byte[]] $#{var_name} = 0x#{code[0].to_s(16)}"
      lines = []
      1.upto(code.length - 1) do |byte|
        if (byte % 10 == 0)
          lines.push "\r\n$#{var_name} += 0x#{code[byte].to_s(16)}"
        else
          lines.push ",0x#{code[byte].to_s(16)}"
        end
      end

      psh << lines.join('') + "\r\n"
    end

    #
    # Return list of code modifier methods
    #
    # @return [Array] Code modifiers
    def self.code_modifiers
      instance_methods.select { |m| m =~ /^(strip|sub)/ }
    end
  end # class Script
end
end
end
