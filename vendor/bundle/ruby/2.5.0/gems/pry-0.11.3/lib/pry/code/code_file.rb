class Pry
  class CodeFile
    DEFAULT_EXT = '.rb'

    # List of all supported languages.
    # @return [Hash]
    EXTENSIONS = {
      %w(.py)        => :python,
      %w(.js)        => :javascript,
      %w(.css)       => :css,
      %w(.xml)       => :xml,
      %w(.php)       => :php,
      %w(.html)      => :html,
      %w(.diff)      => :diff,
      %w(.java)      => :java,
      %w(.json)      => :json,
      %w(.c .h)      => :c,
      %w(.rhtml)     => :rhtml,
      %w(.yaml .yml) => :yaml,
      %w(.cpp .hpp .cc .h .cxx) => :cpp,
      %w(.rb .ru .irbrc .gemspec .pryrc .rake) => :ruby,
    }

    FILES = {
      %w(Gemfile Rakefile Guardfile Capfile) => :ruby
    }

    # @return [Symbol] The type of code stored in this wrapper.
    attr_reader :code_type

    # @param [String] filename The name of a file with code to be detected
    # @param [Symbol] code_type The type of code the `filename` contains
    def initialize(filename, code_type = type_from_filename(filename))
      @filename = filename
      @code_type = code_type
    end

    # @return [String] The code contained in the current `@filename`.
    def code
      if @filename == Pry.eval_path
        Pry.line_buffer.drop(1)
      elsif Pry::Method::Patcher.code_for(@filename)
        Pry::Method::Patcher.code_for(@filename)
      elsif RbxPath.is_core_path?(@filename)
        File.read(RbxPath.convert_path_to_full(@filename))
      else
        path = abs_path
        @code_type = type_from_filename(path)
        File.read(path)
      end
    end

    private

    # @raise [MethodSource::SourceNotFoundError] if the `filename` is not
    #   readable for some reason.
    # @return [String] absolute path for the given `filename`.
    def abs_path
      code_path.detect { |path| readable?(path) } or
        raise MethodSource::SourceNotFoundError,
              "Cannot open #{ @filename.inspect } for reading."
    end

    # @param [String] path
    # @return [Boolean] if the path, with or without the default ext,
    #   is a readable file then `true`, otherwise `false`.
    def readable?(path)
      File.readable?(path) && !File.directory?(path) or
        File.readable?(path << DEFAULT_EXT)
    end

    # @return [Array] All the paths that contain code that Pry can use for its
    #   API's. Skips directories.
    def code_path
      [from_pwd, from_pry_init_pwd, *from_load_path]
    end

    # @param [String] filename
    # @param [Symbol] default (:unknown) the file type to assume if none could be
    #   detected.
    # @return [Symbol, nil] The CodeRay type of a file from its extension, or
    #   `nil` if `:unknown`.
    def type_from_filename(filename, default = :unknown)
      _, @code_type = EXTENSIONS.find do |k, _|
        k.any? { |ext| ext == File.extname(filename) }
      end || FILES.find do |k, _|
        k.any? { |file_name| file_name == File.basename(filename) }
      end

      code_type || default
    end

    # @return [String]
    def from_pwd
      File.expand_path(@filename, Dir.pwd)
    end

    # @return [String]
    def from_pry_init_pwd
      File.expand_path(@filename, Pry::INITIAL_PWD)
    end

    # @return [String]
    def from_load_path
      $LOAD_PATH.map { |path| File.expand_path(@filename, path) }
    end

  end
end
