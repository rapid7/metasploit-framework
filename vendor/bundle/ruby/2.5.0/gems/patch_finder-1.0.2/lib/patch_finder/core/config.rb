module PatchFinder
  module Config

    # Returns the doc directory.
    # 
    # @return [String]
    def self.doc_directory
      @doc_directory ||= File.expand_path(File.join(root_directory, '..', 'docs', 'bin'))
    end

    # Returns the root directory.
    #
    # @return [String]
    def self.root_directory
      @root_directory ||= File.expand_path(File.join(File.dirname(__FILE__), '..'))
    end

  end
end
