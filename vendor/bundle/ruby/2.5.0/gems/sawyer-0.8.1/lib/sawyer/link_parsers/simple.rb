module Sawyer
  module LinkParsers

    class Simple

      LINK_REGEX = /_?url$/


      # Public: Parses simple *_url style links on resources
      #
      # data   - Hash of resource data
      #
      # Returns a Hash of data with separate links Hash
      def parse(data)

        links = {}
        inline_links = data.keys.select {|k| k.to_s[LINK_REGEX] }
        inline_links.each do |key|
          rel_name = key.to_s == 'url' ? 'self' : key.to_s.gsub(LINK_REGEX, '')
          links[rel_name.to_sym] = data[key]
        end

        return data, links
      end

    end

  end
end
