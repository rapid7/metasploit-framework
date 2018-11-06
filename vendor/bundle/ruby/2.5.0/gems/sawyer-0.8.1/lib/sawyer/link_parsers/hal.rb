module Sawyer
  module LinkParsers

    class Hal

      def parse(data)
        links = data.delete(:_links)

        return data, links
      end

    end

  end
end
