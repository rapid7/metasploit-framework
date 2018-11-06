# coding: utf-8

################################################################################
#
# Copyright (C) 2006 Peter J Jones (pjones@pmade.com)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
################################################################################

class PDF::Reader
  ################################################################################
  # An internal PDF::Reader class that represents the XRef table in a PDF file as a
  # hash-like object.
  #
  # An Xref table is a map of object identifiers and byte offsets. Any time a particular
  # object needs to be found, the Xref table is used to find where it is stored in the
  # file.
  #
  # Hash keys are object ids, values are either:
  #
  # * a byte offset where the object starts (regular PDF objects)
  # * a PDF::Reader::Reference instance that points to a stream that contains the
  #   desired object (PDF objects embedded in an object stream)
  #
  # The class behaves much like a standard Ruby hash, including the use of
  # the Enumerable mixin. The key difference is no []= method - the hash
  # is read only.
  #
  class XRef
    include Enumerable
    attr_reader :trailer

    ################################################################################
    # create a new Xref table based on the contents of the supplied io object
    #
    # io - must be an IO object, generally either a file or a StringIO
    #
    def initialize(io)
      @io = io
      @junk_offset = calc_junk_offset(io) || 0
      @xref = {}
      @trailer = load_offsets
    end

    ################################################################################
    # return the number of objects in this file. Objects with multiple generations are
    # only counter once.
    def size
      @xref.size
    end
    ################################################################################
    # returns the byte offset for the specified PDF object.
    #
    # ref - a PDF::Reader::Reference object containing an object ID and revision number
    def [](ref)
      @xref[ref.id][ref.gen]
    rescue
      raise InvalidObjectError, "Object #{ref.id}, Generation #{ref.gen} is invalid"
    end
    ################################################################################
    # iterate over each object in the xref table
    def each(&block)
      ids = @xref.keys.sort
      ids.each do |id|
        gen = @xref[id].keys.sort[-1]
        yield PDF::Reader::Reference.new(id, gen)
      end
    end
    ################################################################################
    private
    ################################################################################
    # Read a xref table from the underlying buffer.
    #
    # If offset is specified the table will be loaded from there, otherwise the
    # default offset will be located and used.
    #
    # After seeking to the offset, processing is handed of to either load_xref_table()
    # or load_xref_stream() based on what we find there.
    #
    def load_offsets(offset = nil)
      offset ||= new_buffer.find_first_xref_offset
      offset += @junk_offset

      buf = new_buffer(offset)
      tok_one = buf.token

      return load_xref_table(buf) if tok_one == "xref" || tok_one == "ref"

      tok_two   = buf.token
      tok_three = buf.token

      if tok_one.to_i >= 0 && tok_two.to_i >= 0 && tok_three == "obj"
        buf = new_buffer(offset)
        stream = PDF::Reader::Parser.new(buf).object(tok_one.to_i, tok_two.to_i)
        return load_xref_stream(stream)
      end

      raise PDF::Reader::MalformedPDFError,
        "xref table not found at offset #{offset} (#{tok_one} != xref)"
    end
    ################################################################################
    # Assumes the underlying buffer is positioned at the start of a traditional
    # Xref table and processes it into memory.
    def load_xref_table(buf)
      params = []

      while !params.include?("trailer") && !params.include?(nil)
        if params.size == 2
          objid, count = params[0].to_i, params[1].to_i
          count.times do
            offset = buf.token.to_i
            generation = buf.token.to_i
            state = buf.token

            store(objid, generation, offset + @junk_offset) if state == "n" && offset > 0
            objid += 1
            params.clear
          end
        end
        params << buf.token
      end

      trailer = Parser.new(buf, self).parse_token

      unless trailer.kind_of?(Hash)
        raise MalformedPDFError, "PDF malformed, trailer should be a dictionary"
      end

      load_offsets(trailer[:XRefStm])   if trailer.has_key?(:XRefStm)
      load_offsets(trailer[:Prev].to_i) if trailer.has_key?(:Prev)

      trailer
    end

    ################################################################################
    # Read an XRef stream from the underlying buffer instead of a traditional xref table.
    #
    def load_xref_stream(stream)
      unless stream.is_a?(PDF::Reader::Stream) && stream.hash[:Type] == :XRef
        raise PDF::Reader::MalformedPDFError, "xref stream not found when expected"
      end
      trailer = Hash[stream.hash.select { |key, value|
        [:Size, :Prev, :Root, :Encrypt, :Info, :ID].include?(key)
      }]

      widths       = stream.hash[:W]
      entry_length = widths.inject(0) { |s, w| s + w }
      raw_data     = StringIO.new(stream.unfiltered_data)
      if stream.hash[:Index]
        index = stream.hash[:Index]
      else
        index = [0, stream.hash[:Size]]
      end
      index.each_slice(2) do |start_id, size|
        obj_ids = (start_id..(start_id+(size-1)))
        obj_ids.each do |objid|
          entry = raw_data.read(entry_length) || ""
          f1    = unpack_bytes(entry[0,widths[0]])
          f2    = unpack_bytes(entry[widths[0],widths[1]])
          f3    = unpack_bytes(entry[widths[0]+widths[1],widths[2]])
          if f1 == 1 && f2 > 0
            store(objid, f3, f2 + @junk_offset)
          elsif f1 == 2 && f2 > 0
            store(objid, 0, PDF::Reader::Reference.new(f2, 0))
          end
        end
      end

      load_offsets(trailer[:Prev].to_i) if trailer.has_key?(:Prev)

      trailer
    end
    ################################################################################
    # XRef streams pack info into integers 1-N bytes wide. Depending on the number of
    # bytes they need to be converted to an int in different ways.
    #
    def unpack_bytes(bytes)
      if bytes.to_s.size == 0
        0
      elsif bytes.size == 1
        bytes.unpack("C")[0]
      elsif bytes.size == 2
        bytes.unpack("n")[0]
      elsif bytes.size == 3
        ("\x00" + bytes).unpack("N")[0]
      elsif bytes.size == 4
        bytes.unpack("N")[0]
      else
        raise UnsupportedFeatureError, "Unable to unpack xref stream entries with more than 4 bytes"
      end
    end
    ################################################################################
    # Wrap the io stream we're working with in a buffer that can tokenise it for us.
    #
    # We create multiple buffers so we can be tokenising multiple sections of the file
    # at the same time without worrying about clearing the buffers contents.
    #
    def new_buffer(offset = 0)
      PDF::Reader::Buffer.new(@io, :seek => offset)
    end
    ################################################################################
    # Stores an offset value for a particular PDF object ID and revision number
    #
    def store(id, gen, offset)
      (@xref[id] ||= {})[gen] ||= offset
    end
    ################################################################################
    # Returns the offset of the PDF document in the +stream+. In theory this
    # should always be 0, but all sort of crazy junk is prefixed to PDF files
    # in the real world.
    #
    # Checks up to 50 chars into the file, returns nil if no PDF data detected.
    #
    def calc_junk_offset(io)
      io.rewind
      offset = io.pos
      until (c = io.readchar) == '%' || c == 37 || offset > 50
        offset += 1
      end
      io.rewind
      offset < 50 ? offset : nil
    rescue EOFError
      return nil
    end
  end
  ################################################################################
end
################################################################################
