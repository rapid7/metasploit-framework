# frozen_string_literal: true
module YARD::CodeObjects
  # An ExtraFileObject represents an extra documentation file (README or other
  # file). It is not strictly a CodeObject (does not inherit from `Base`) although
  # it implements `path`, `name` and `type`, and therefore should be structurally
  # compatible with most CodeObject interfaces.
  class ExtraFileObject
    attr_accessor :filename
    attr_writer :attributes
    attr_accessor :name
    # @since 0.8.3
    attr_reader :locale

    # Creates a new extra file object.
    # @param [String] filename the location on disk of the file
    # @param [String] contents the file contents. If not set, the contents
    #   will be read from disk using the +filename+.
    def initialize(filename, contents = nil)
      self.filename = filename
      self.name = File.basename(filename).gsub(/\.[^.]+$/, '')
      self.attributes = SymbolHash.new(false)
      @original_contents = contents
      @parsed = false
      @locale = nil
      ensure_parsed
    end

    alias path name

    def attributes
      ensure_parsed
      @attributes
    end

    def title
      attributes[:title] || name
    end

    def contents
      ensure_parsed
      @contents
    end

    def contents=(contents)
      @original_contents = contents
      @parsed = false
    end

    # @param [String] locale the locale name to be translated.
    # @return [void]
    # @since 0.8.3
    def locale=(locale)
      @locale = locale
      @parsed = false
    end

    def inspect
      "#<yardoc #{type} #{filename} attrs=#{attributes.inspect}>"
    end
    alias to_s inspect

    def type; :extra_file end

    def ==(other)
      return false unless self.class === other
      other.filename == filename
    end
    alias eql? ==
    alias equal? ==
    def hash; filename.hash end

    private

    def ensure_parsed
      return if @parsed
      @parsed = true
      @contents = parse_contents(@original_contents || File.read(@filename))
    end

    # @param [String] data the file contents
    def parse_contents(data)
      retried = false
      cut_index = 0
      data = translate(data)
      data = data.split("\n")
      data.each_with_index do |line, index|
        case line
        when /^#!(\S+)\s*$/
          if index == 0
            attributes[:markup] = $1
          else
            cut_index = index
            break
          end
        when /^\s*#\s*@(\S+)\s*(.+?)\s*$/
          attributes[$1] = $2
        when /^\s*<!--\s*$/, /^\s*-->\s*$/
          # Ignore HTML comments
        else
          cut_index = index
          break
        end
      end
      data = data[cut_index..-1] if cut_index > 0
      contents = data.join("\n")

      if contents.respond_to?(:force_encoding) && attributes[:encoding]
        begin
          contents.force_encoding(attributes[:encoding])
        rescue ArgumentError
          log.warn "Invalid encoding `#{attributes[:encoding]}' in #{filename}"
        end
      end
      contents
    rescue ArgumentError => e
      if retried && e.message =~ /invalid byte sequence/
        # This should never happen.
        log.warn "Could not read #{filename}, #{e.message}. You probably want to set `--charset`."
        return ''
      end
      data.force_encoding('binary') if data.respond_to?(:force_encoding)
      retried = true
      retry
    end

    def translate(data)
      text = YARD::I18n::Text.new(data, :have_header => true)
      text.translate(YARD::Registry.locale(locale))
    end
  end
end
