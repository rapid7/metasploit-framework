module Zip
  module NullDecompressor #:nodoc:all
    module_function

    def sysread(_numberOfBytes = nil, _buf = nil)
      nil
    end

    def produce_input
      nil
    end

    def input_finished?
      true
    end

    def eof
      true
    end

    alias eof? eof
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
