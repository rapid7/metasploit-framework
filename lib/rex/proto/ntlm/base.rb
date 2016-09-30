# -*- coding: binary -*-
#
# An NTLM Authentication Library for Ruby
#
# This code is a derivative of "dbf2.rb" written by yrock
# and Minero Aoki. You can find original code here:
# http://jp.rubyist.net/magazine/?0013-CodeReview
# -------------------------------------------------------------
# Copyright (c) 2005,2006 yrock
#
# This program is free software.
# You can distribute/modify this program under the terms of the
# Ruby License.
#
# 2011-02-23 refactored by Alexandre Maloteaux for Metasploit Project
# -------------------------------------------------------------
#
# 2006-02-11 refactored by Minero Aoki
# -------------------------------------------------------------
#
# All protocol information used to write this code stems from
# "The NTLM Authentication Protocol" by Eric Glass. The author
# would thank to him for this tremendous work and making it
# available on the net.
# http://davenport.sourceforge.net/ntlm.html
# -------------------------------------------------------------
# Copyright (c) 2003 Eric Glass
#
# Permission to use, copy, modify, and distribute this document
# for any purpose and without any fee is hereby granted,
# provided that the above copyright notice and this list of
# conditions appear in all copies.
# -------------------------------------------------------------
#
# The author also looked Mozilla-Firefox-1.0.7 source code,
# namely, security/manager/ssl/src/nsNTLMAuthModule.cpp and
# Jonathan Bastien-Filiatrault's libntlm-ruby.
# "http://x2a.org/websvn/filedetails.php?
# repname=libntlm-ruby&path=%2Ftrunk%2Fntlm.rb&sc=1"
# The latter has a minor bug in its separate_keys function.
# The third key has to begin from the 14th character of the
# input string instead of 13th:)

require 'rex/proto/ntlm/constants'

module Rex
module Proto
module NTLM
# The base type needed for other modules like message and crypt
class Base

CONST = Rex::Proto::NTLM::Constants

  # base classes for primitives
  class Field
    attr_accessor :active, :value

    def initialize(opts)
      @value  = opts[:value]
      @active = opts[:active].nil? ? true : opts[:active]
    end

    def size
      @active ? @size : 0
    end
  end

  class String < Field
    def initialize(opts)
      super(opts)
      @size = opts[:size]
    end

    def parse(str, offset=0)
      if @active and str.size >= offset + @size
        @value = str[offset, @size]
        @size
      else
        0
      end
    end

    def serialize
      if @active
        @value
      else
        ""
      end
    end

    def value=(val)
      @value = val
      @size = @value.nil? ? 0 : @value.size
      @active = (@size > 0)
    end
  end

  class Int16LE < Field
    def initialize(opt)
      super(opt)
      @size = 2
    end

    def parse(str, offset=0)
      if @active and str.size >= offset + @size
        @value = str[offset, @size].unpack("v")[0]
        @size
      else
        0
      end
    end

    def serialize
      [@value].pack("v")
    end
  end

  class Int32LE < Field
    def initialize(opt)
      super(opt)
      @size = 4
    end

    def parse(str, offset=0)
      if @active and str.size >= offset + @size
        @value = str.slice(offset, @size).unpack("V")[0]
        @size
      else
        0
      end
    end

    def serialize
      [@value].pack("V") if @active
    end
  end

  class Int64LE < Field
    def initialize(opt)
      super(opt)
      @size = 8
    end

    def parse(str, offset=0)
      if @active and str.size >= offset + @size
        d, u = str.slice(offset, @size).unpack("V2")
        @value = (u * 0x100000000 + d)
        @size
      else
        0
      end
    end

    def serialize
      [@value & 0x00000000ffffffff, @value >> 32].pack("V2") if @active
    end
  end

  # base class of data structure
  class FieldSet
    class << FieldSet
    def define(&block)
      klass = Class.new(self) do
        def self.inherited(subclass)
          proto = @proto

          subclass.instance_eval do
            @proto = proto
          end
        end
      end

      klass.module_eval(&block)

      klass
    end

    def string(name, opts)
      add_field(name, String, opts)
    end

    def int16LE(name, opts)
      add_field(name, Int16LE, opts)
    end

    def int32LE(name, opts)
      add_field(name, Int32LE, opts)
    end

    def int64LE(name, opts)
      add_field(name, Int64LE, opts)
    end

    def security_buffer(name, opts)
      add_field(name, SecurityBuffer, opts)
    end

    def prototypes
      @proto
    end

    def names
      @proto.map{|n, t, o| n}
    end

    def types
      @proto.map{|n, t, o| t}
    end

    def opts
      @proto.map{|n, t, o| o}
    end

    private

    def add_field(name, type, opts)
      (@proto ||= []).push [name, type, opts]
      define_accessor name
    end

    def define_accessor(name)
      module_eval(<<-End, __FILE__, __LINE__ + 1)
      def #{name}
        self['#{name}'].value
      end

      def #{name}=(val)
        self['#{name}'].value = val
      end
      End
    end
    end #self

    def initialize
      @alist = self.class.prototypes.map{ |n, t, o| [n, t.new(o)] }
    end

    def serialize
      @alist.map{|n, f| f.serialize }.join
    end

    def parse(str, offset=0)
      @alist.inject(offset){|cur, a|  cur += a[1].parse(str, cur)}
    end

    def size
      @alist.inject(0){|sum, a| sum += a[1].size}
    end

    def [](name)
      a = @alist.assoc(name.to_s.intern)
      raise ArgumentError, "no such field: #{name}" unless a
      a[1]
    end

    def []=(name, val)
      a = @alist.assoc(name.to_s.intern)
      raise ArgumentError, "no such field: #{name}" unless a
      a[1] = val
    end

    def enable(name)
      self[name].active = true
    end

    def disable(name)
      self[name].active = false
    end
  end

  Blob = FieldSet.define {
    int32LE    :blob_signature,   {:value => CONST::BLOB_SIGN}
    int32LE    :reserved,         {:value => 0}
    int64LE    :timestamp,      {:value => 0}
    string     :challenge,      {:value => "", :size => 8}
    int32LE    :unknown1,     {:value => 0}
    string     :target_info,      {:value => "", :size => 0}
    int32LE    :unknown2,         {:value => 0}
  }

  SecurityBuffer = FieldSet.define {
    int16LE   :length,        {:value => 0}
    int16LE   :allocated,     {:value => 0}
    int32LE   :offset,        {:value => 0}
  }


  class SecurityBuffer
    attr_accessor :active
    def initialize(opts)
      super()
      @value  = opts[:value]
      @active = opts[:active].nil? ? true : opts[:active]
      @size = 8
    end

    def parse(str, offset=0)
      if @active and str.size >= offset + @size
        super(str, offset)
        @value = str[self.offset, self.length]
        @size
      else
        0
      end
    end

    def serialize
      super if @active
    end

    def value
      @value
    end

    def value=(val)
      @value = val
      self.length = self.allocated = val.size
    end

    def data_size
      @active ? @value.size : 0
    end
  end
end
end
end
end
