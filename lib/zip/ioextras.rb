module IOExtras  #:nodoc:

  CHUNK_SIZE = 32768

  RANGE_ALL = 0..-1

  def self.copy_stream(ostream, istream)
    s = ''
    ostream.write(istream.read(CHUNK_SIZE, s)) until istream.eof? 
  end


  # Implements kind_of? in order to pretend to be an IO object
  module FakeIO
    def kind_of?(object)
      object == IO || super
    end
  end

  # Implements many of the convenience methods of IO
  # such as gets, getc, readline and readlines 
  # depends on: input_finished?, produce_input and read
  module AbstractInputStream  
    include Enumerable
    include FakeIO

    def initialize
      super
      @lineno = 0
      @outputBuffer = ""
    end

    attr_accessor :lineno

    def read(numberOfBytes = nil, buf = nil)
      tbuf = nil

      if @outputBuffer.length > 0
        if numberOfBytes <= @outputBuffer.length
          tbuf = @outputBuffer.slice!(0, numberOfBytes)
        else
          numberOfBytes -= @outputBuffer.length if (numberOfBytes)
          rbuf = sysread(numberOfBytes, buf)
          tbuf = @outputBuffer
          tbuf << rbuf if (rbuf)
          @outputBuffer = ""
        end
      else
        tbuf = sysread(numberOfBytes, buf)
      end

      return nil unless (tbuf)

      if buf
        buf.replace(tbuf)
      else
        buf = tbuf
      end

      buf
    end

    def readlines(aSepString = $/)
      retVal = []
      each_line(aSepString) { |line| retVal << line }
      return retVal
    end
    
    def gets(aSepString=$/)
      @lineno = @lineno.next
      return read if aSepString == nil
      aSepString="#{$/}#{$/}" if aSepString == ""
      
      bufferIndex=0
      while ((matchIndex = @outputBuffer.index(aSepString, bufferIndex)) == nil)
	bufferIndex=@outputBuffer.length
	if input_finished?
	  return @outputBuffer.empty? ? nil : flush 
	end
	@outputBuffer << produce_input
      end
      sepIndex=matchIndex + aSepString.length
      return @outputBuffer.slice!(0...sepIndex)
    end
    
    def flush
      retVal=@outputBuffer
      @outputBuffer=""
      return retVal
    end
    
    def readline(aSepString = $/)
      retVal = gets(aSepString)
      raise EOFError if retVal == nil
      return retVal
    end
    
    def each_line(aSepString = $/)
      while true
	yield readline(aSepString)
      end
    rescue EOFError
    end
    
    alias_method :each, :each_line
  end


  # Implements many of the output convenience methods of IO.
  # relies on <<
  module AbstractOutputStream 
    include FakeIO

    def write(data)
      self << data
      data.to_s.length
    end


    def print(*params)
      self << params.to_s << $\.to_s
    end

    def printf(aFormatString, *params)
      self << sprintf(aFormatString, *params)
    end

    def putc(anObject)
      self << case anObject
	      when Fixnum then anObject.chr
	      when String then anObject
	      else raise TypeError, "putc: Only Fixnum and String supported"
	      end
      anObject
    end
    
    def puts(*params)
      params << "\n" if params.empty?
      params.flatten.each {
	|element|
	val = element.to_s
	self << val
	self << "\n" unless val[-1,1] == "\n"
      }
    end

  end

end # IOExtras namespace module



# Copyright (C) 2002-2004 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
