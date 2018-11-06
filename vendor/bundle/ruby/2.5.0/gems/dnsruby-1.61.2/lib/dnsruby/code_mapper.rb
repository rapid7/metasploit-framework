# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++
module Dnsruby
  #  CodeMapper superclass looks after String to code mappings (e.g. OpCode, RCode, etc.)
  # 
  #  Subclasses simply define a mapping of codes to variable names, and CodeMapper provides utility methods.
  # 
  #  All strings will come out as upper case
  # 
  #  Example :
  #    Types::AAAA or Types.AAAA
  #    rcode.string or rcode.code
  class CodeMapper # :nodoc: all
    include Comparable

    @@arrays = {}

    attr_accessor :string, :code
    alias to_code code
    alias to_i code
    alias to_string string
    alias to_s string

    class Arrays
      attr_accessor :strings, :stringsdown, :values, :maxcode
      def initialize
        @strings = {}
        @stringsdown = {}
        @values = {}
        @maxcode = 0
      end
    end

    def CodeMapper.strings
      strings = []
      @@arrays[self].strings.keys.each {|s| strings.push(s)}
      return strings
    end

    #  Creates the CodeMapper from the defined constants
    def CodeMapper.update

      @@arrays[self] = Arrays.new

      constants = self.constants - CodeMapper.constants
      constants.each do |i|
        @@arrays[self].strings.store(i.to_s, const_get(i))
      end
      @@arrays[self].maxcode = constants.length
      @@arrays[self].values = @@arrays[self].strings.invert
      @@arrays[self].stringsdown = Hash.new
      @@arrays[self].strings.keys.each do |s|
        @@arrays[self].stringsdown.store(s.downcase, @@arrays[self].strings[s])
      end
    end

    #  Add new a code to the CodeMapper
    def CodeMapper.add_pair(string, code)
      array = @@arrays[self]
      array.strings.store(string, code)
      array.values=array.strings.invert
      array.stringsdown.store(string.downcase, code)
      array.maxcode+=1
    end

    def unknown_string(arg) #:nodoc: all
      raise ArgumentError.new("String #{arg} not a member of #{self.class}")
    end

    def unknown_code(arg) #:nodoc: all
      #  Be liberal in what you accept...
      #       raise ArgumentError.new("Code #{arg} not a member of #{self.class}")
      Classes.add_pair(arg.to_s, arg)
      set_code(arg)
    end

    def self.method_missing(methId) #:nodoc: all
      str = methId.id2name
      return self.new(str)
    end

    def initialize(arg) #:nodoc: all
      array = @@arrays[self.class]
      if (arg.kind_of?String)
        arg = arg.gsub("_", "-")
        code = array.stringsdown[arg.downcase]
        if (code != nil)
          @code = code
          @string = array.values[@code]
        else
          unknown_string(arg)
        end
      elsif arg.kind_of?(Integer)
        if (array.values[arg] != nil)
          @code = arg
          @string = array.values[@code]
        else
          unknown_code(arg)
        end
      elsif (arg.kind_of?self.class)
        @code = arg.code
        @string = array.values[@code]
      else
        raise ArgumentError.new("Unknown argument of type #{arg.class}: #{arg} for #{self.class}")
      end
    end

    def set_string(arg)
      array = @@arrays[self.class]
      @code = array.stringsdown[arg.downcase]
      @string = array.values[@code]
    end

    def set_code(arg)
      @code = arg
      @string = @@arrays[self.class].values[@code]
    end

    def hash
      @code
    end

    def inspect
      return @string
    end

    def CodeMapper.to_string(arg)
      if (arg.kind_of?String)
        return arg
      else
        return @@arrays[self].values[arg]
      end
    end

    def CodeMapper.to_code(arg)
      if arg.kind_of?(Integer)
        return arg
      else
        return @@arrays[self].stringsdown[arg.downcase]
      end
    end

    def <=>(other)
      if other.is_a?(Integer)
        self.code <=> other
      else
        self.code <=> other.code
      end
    end

    def ==(other)
      return true if [@code, @string].include?other
      if (CodeMapper === other)
        return true if ((other.code == @code) || (other.string == @string))
      end
      return false
    end
    alias eql? == # :nodoc:

    #  Return a regular expression which matches any codes or strings from the CodeMapper.
    def self.regexp
      #  Longest ones go first, so the regex engine will match AAAA before A, etc.
      return @@arrays[self].strings.keys.sort { |a, b| b.length <=> a.length }.join('|')
    end

  end
end