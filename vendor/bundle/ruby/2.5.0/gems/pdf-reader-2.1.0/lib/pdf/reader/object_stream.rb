# coding: utf-8

class PDF::Reader

  # provides a wrapper around a PDF stream object that contains other objects in it.
  # This is done for added compression and is described as an "Object Stream" in the spec.
  #
  class ObjectStream # :nodoc:
    def initialize(stream)
      @dict = stream.hash
      @data = stream.unfiltered_data
    end

    def [](objid)
      if offsets[objid].nil?
        nil
      else
        buf = PDF::Reader::Buffer.new(StringIO.new(@data), :seek => offsets[objid])
        parser = PDF::Reader::Parser.new(buf)
        parser.parse_token
      end
    end

    def size
      @dict[:N]
    end

    private

    def offsets
      @offsets ||= {}
      return @offsets if @offsets.keys.size > 0

      size.times do
        @offsets[buffer.token.to_i] = first + buffer.token.to_i
      end
      @offsets
    end

    def first
      @dict[:First]
    end

    def buffer
      @buffer ||= PDF::Reader::Buffer.new(StringIO.new(@data))
    end

  end

end

