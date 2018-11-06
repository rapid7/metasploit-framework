module Zip
  class ExtraField < Hash
    ID_MAP = {}

    def initialize(binstr = nil)
      merge(binstr) if binstr
    end

    def extra_field_type_exist(binstr, id, len, i)
      field_name = ID_MAP[id].name
      if member?(field_name)
        self[field_name].merge(binstr[i, len + 4])
      else
        field_obj        = ID_MAP[id].new(binstr[i, len + 4])
        self[field_name] = field_obj
      end
    end

    def extra_field_type_unknown(binstr, len, i)
      create_unknown_item unless self['Unknown']
      if !len || len + 4 > binstr[i..-1].bytesize
        self['Unknown'] << binstr[i..-1]
        return
      end
      self['Unknown'] << binstr[i, len + 4]
    end

    def create_unknown_item
      s = ''
      class << s
        alias_method :to_c_dir_bin, :to_s
        alias_method :to_local_bin, :to_s
      end
      self['Unknown'] = s
    end

    def merge(binstr)
      return if binstr.empty?
      i = 0
      while i < binstr.bytesize
        id  = binstr[i, 2]
        len = binstr[i + 2, 2].to_s.unpack('v').first
        if id && ID_MAP.member?(id)
          extra_field_type_exist(binstr, id, len, i)
        elsif id
          create_unknown_item unless self['Unknown']
          break unless extra_field_type_unknown(binstr, len, i)
        end
        i += len + 4
      end
    end

    def create(name)
      unless (field_class = ID_MAP.values.find { |k| k.name == name })
        raise Error, "Unknown extra field '#{name}'"
      end
      self[name] = field_class.new
    end

    # place Unknown last, so "extra" data that is missing the proper signature/size
    # does not prevent known fields from being read back in
    def ordered_values
      result = []
      each { |k, v| k == 'Unknown' ? result.push(v) : result.unshift(v) }
      result
    end

    def to_local_bin
      ordered_values.map! { |v| v.to_local_bin.force_encoding('BINARY') }.join
    end

    alias to_s to_local_bin

    def to_c_dir_bin
      ordered_values.map! { |v| v.to_c_dir_bin.force_encoding('BINARY') }.join
    end

    def c_dir_size
      to_c_dir_bin.bytesize
    end

    def local_size
      to_local_bin.bytesize
    end

    alias length local_size
    alias size local_size
  end
end

require 'zip/extra_field/generic'
require 'zip/extra_field/universal_time'
require 'zip/extra_field/old_unix'
require 'zip/extra_field/unix'
require 'zip/extra_field/zip64'
require 'zip/extra_field/zip64_placeholder'
require 'zip/extra_field/ntfs'

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
