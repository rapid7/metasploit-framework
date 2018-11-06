require_relative 'reader'

module TTFunk
  class Table
    include Reader

    attr_reader :file
    attr_reader :offset
    attr_reader :length

    def initialize(file)
      @file = file

      info = file.directory_info(tag)

      if info
        @offset = info[:offset]
        @length = info[:length]

        parse_from(@offset) { parse! }
      end
    end

    def exists?
      !@offset.nil?
    end

    def raw
      if exists?
        parse_from(offset) { io.read(length) }
      end
    end

    def tag
      self.class.name.split(/::/).last.downcase
    end

    private

    def parse!
      # do nothing, by default
    end
  end
end
