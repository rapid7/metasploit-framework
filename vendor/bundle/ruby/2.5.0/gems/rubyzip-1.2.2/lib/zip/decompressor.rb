module Zip
  class Decompressor #:nodoc:all
    CHUNK_SIZE = 32_768
    def initialize(input_stream)
      super()
      @input_stream = input_stream
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
