unless Enumerable.method_defined?(:inject)
  module Enumerable  #:nodoc:all
    def inject(n = 0)
      each { |value| n = yield(n, value) }
      n
    end
  end
end

module Enumerable #:nodoc:all
  # returns a new array of all the return values not equal to nil
  # This implementation could be faster
  def select_map(&aProc)
    map(&aProc).reject { |e| e.nil? }
  end
end

unless Object.method_defined?(:object_id)
  class Object  #:nodoc:all
    # Using object_id which is the new thing, so we need
    # to make that work in versions prior to 1.8.0
    alias object_id id
  end
end

unless File.respond_to?(:read)
  class File # :nodoc:all
    # singleton method read does not exist in 1.6.x
    def self.read(fileName)
      open(fileName) { |f| f.read }
    end
  end
end

class String  #:nodoc:all
  def starts_with(aString)
    rindex(aString, 0) == 0
  end

  def ends_with(aString)
    index(aString, -aString.size)
  end

  def ensure_end(aString)
    ends_with(aString) ? self : self + aString
  end

  def lchop
    slice(1, length)
  end
end

class Time  #:nodoc:all
  
  #MS-DOS File Date and Time format as used in Interrupt 21H Function 57H:
  # 
  # Register CX, the Time:
  # Bits 0-4  2 second increments (0-29)
  # Bits 5-10 minutes (0-59)
  # bits 11-15 hours (0-24)
  # 
  # Register DX, the Date:
  # Bits 0-4 day (1-31)
  # bits 5-8 month (1-12)
  # bits 9-15 year (four digit year minus 1980)
  
  
  def to_binary_dos_time
    (sec/2) +
      (min  << 5) +
      (hour << 11)
  end

  def to_binary_dos_date
    (day) +
      (month << 5) +
      ((year - 1980) << 9)
  end

  # Dos time is only stored with two seconds accuracy
  def dos_equals(other)
    to_i/2 == other.to_i/2
  end

  def self.parse_binary_dos_format(binaryDosDate, binaryDosTime)
    second = 2 * (       0b11111 & binaryDosTime)
    minute = (     0b11111100000 & binaryDosTime) >> 5 
    hour   = (0b1111100000000000 & binaryDosTime) >> 11
    day    = (           0b11111 & binaryDosDate) 
    month  = (       0b111100000 & binaryDosDate) >> 5
    year   = ((0b1111111000000000 & binaryDosDate) >> 9) + 1980
    begin
      return Time.local(year, month, day, hour, minute, second)
    end
  end
end

class Module  #:nodoc:all
  def forward_message(forwarder, *messagesToForward)
    methodDefs = messagesToForward.map { 
      |msg| 
      "def #{msg}; #{forwarder}(:#{msg}); end"
    }
    module_eval(methodDefs.join("\n"))
  end
end


# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
