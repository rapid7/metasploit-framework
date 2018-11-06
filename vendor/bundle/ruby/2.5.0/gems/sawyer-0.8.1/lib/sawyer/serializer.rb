require 'date'
require 'time'

module Sawyer
  class Serializer
    def self.any_json
      yajl || multi_json || json
    end

    def self.yajl
      require 'yajl'
      new(Yajl)
    rescue LoadError
    end

    def self.json
      require 'json'
      new(JSON)
    rescue LoadError
    end

    def self.multi_json
      require 'multi_json'
      new(MultiJson)
    rescue LoadError
    end

    def self.message_pack
      require 'msgpack'
      new(MessagePack, :pack, :unpack)
    rescue LoadError
    end

    # Public: Wraps a serialization format for Sawyer.  Nested objects are
    # prepared for serialization (such as changing Times to ISO 8601 Strings).
    # Any serialization format that responds to #dump and #load will work.
    def initialize(format, dump_method_name = nil, load_method_name = nil)
      @format = format
      @dump = @format.method(dump_method_name || :dump)
      @load = @format.method(load_method_name || :load)
    end

    # Public: Encodes an Object (usually a Hash or Array of Hashes).
    #
    # data - Object to be encoded.
    #
    # Returns an encoded String.
    def encode(data)
      @dump.call(encode_object(data))
    end

    alias dump encode

    # Public: Decodes a String into an Object (usually a Hash or Array of
    # Hashes).
    #
    # data - An encoded String.
    #
    # Returns a decoded Object.
    def decode(data)
      return nil if data.nil? || data.strip.empty?
      decode_object(@load.call(data))
    end

    alias load decode

    def encode_object(data)
      case data
      when Hash then encode_hash(data)
      when Array then data.map { |o| encode_object(o) }
      else data
      end
    end

    def encode_hash(hash)
      hash.keys.each do |key|
        case value = hash[key]
        when Date then hash[key] = value.to_time.utc.xmlschema
        when Time then hash[key] = value.utc.xmlschema
        when Hash then hash[key] = encode_hash(value)
        end
      end
      hash
    end

    def decode_object(data)
      case data
      when Hash then decode_hash(data)
      when Array then data.map { |o| decode_object(o) }
      else data
      end
    end

    def decode_hash(hash)
      hash.keys.each do |key|
        hash[key.to_sym] = decode_hash_value(key, hash.delete(key))
      end
      hash
    end

    def decode_hash_value(key, value)
      if time_field?(key, value)
        if value.is_a?(String)
          begin
            Time.parse(value)
          rescue ArgumentError
            value
          end
        elsif value.is_a?(Integer) || value.is_a?(Float)
          Time.at(value)
        else
          value
        end
      elsif value.is_a?(Hash)
        decode_hash(value)
      elsif value.is_a?(Array)
        value.map { |o| decode_hash_value(key, o) }
      else
        value
      end
    end

    def time_field?(key, value)
      value && (key =~ /_(at|on)\z/ || key =~ /(\A|_)date\z/)
    end
  end
end
