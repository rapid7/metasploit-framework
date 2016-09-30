module Metasploit
  module Framework
    # This is a ActiveModel custom validator that assumes the attribute
    # is supposed to be the path to a regular file. It checks whether the
    # file exists and whether or not it is a regular file.
    class FilePathValidator < ActiveModel::EachValidator

      def validate_each(record, attribute, value)
        unless ::File.file? value
          record.errors[attribute] << (options[:message] || "is not a valid path to a regular file")
        end
      end
    end
  end
end

