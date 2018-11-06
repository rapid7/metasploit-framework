require_relative '../table'

module TTFunk
  class Table
    class Simple < Table
      attr_reader :tag

      def initialize(file, tag)
        @tag = tag
        super(file)
      end
    end
  end
end
