module Zip
  class NullCompressor < Compressor #:nodoc:all
    include Singleton

    def <<(_data)
      raise IOError, 'closed stream'
    end

    attr_reader :size, :compressed_size
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
