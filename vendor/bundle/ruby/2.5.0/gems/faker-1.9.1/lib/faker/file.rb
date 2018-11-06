module Faker
  class File < Base
    class << self
      def extension
        fetch('file.extension')
      end

      def mime_type
        fetch('file.mime_type')
      end

      def file_name(dir = nil, name = nil, ext = nil, directory_separator = '/')
        dir ||= Faker::Internet.slug
        name ||= Faker::Lorem.word.downcase
        ext ||= extension

        [dir, name].join(directory_separator) + ".#{ext}"
      end
    end
  end
end
