# frozen_string_literal: true

module Rex
  module Ntpath

    # @param [String] path The path to convert into a valid ntpath format
    def self.as_ntpath(path)
      Pathname.new(path)
              .cleanpath
              .each_filename
              .drop_while { |file| file == '.' }
              .join('\\')
    end
  end
end
