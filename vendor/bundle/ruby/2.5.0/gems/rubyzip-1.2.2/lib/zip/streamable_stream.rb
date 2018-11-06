module Zip
  class StreamableStream < DelegateClass(Entry) # nodoc:all
    def initialize(entry)
      super(entry)
      dirname = if zipfile.is_a?(::String)
                  ::File.dirname(zipfile)
                else
                  nil
                end
      @temp_file = Tempfile.new(::File.basename(name), dirname)
      @temp_file.binmode
    end

    def get_output_stream
      if block_given?
        begin
          yield(@temp_file)
        ensure
          @temp_file.close
        end
      else
        @temp_file
      end
    end

    def get_input_stream
      unless @temp_file.closed?
        raise StandardError, "cannot open entry for reading while its open for writing - #{name}"
      end
      @temp_file.open # reopens tempfile from top
      @temp_file.binmode
      if block_given?
        begin
          yield(@temp_file)
        ensure
          @temp_file.close
        end
      else
        @temp_file
      end
    end

    def write_to_zip_output_stream(aZipOutputStream)
      aZipOutputStream.put_next_entry(self)
      get_input_stream { |is| ::Zip::IOExtras.copy_stream(aZipOutputStream, is) }
    end

    def clean_up
      @temp_file.unlink
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
