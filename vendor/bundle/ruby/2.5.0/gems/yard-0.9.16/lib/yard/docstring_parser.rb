# frozen_string_literal: true
require 'ostruct'

module YARD
  # Parses text and creates a {Docstring} object to represent documentation
  # for a {CodeObjects::Base}. To create a new docstring, you should initialize
  # the parser and call {#parse} followed by {#to_docstring}.
  #
  # == Subclassing Notes
  #
  # The DocstringParser can be subclassed and subtituted during parsing by
  # setting the {Docstring.default_parser} attribute with the name of the
  # subclass. This allows developers to change the way docstrings are
  # parsed, allowing for completely different docstring syntaxes.
  #
  # @example Creating a Docstring with a DocstringParser
  #   DocstringParser.new.parse("text here").to_docstring
  # @example Creating a Custom DocstringParser
  #   # Parses docstrings backwards!
  #   class ReverseDocstringParser
  #     def parse_content(content)
  #       super(content.reverse)
  #     end
  #   end
  #
  #   # Set the parser as default when parsing
  #   YARD::Docstring.default_parser = ReverseDocstringParser
  # @see #parse_content
  # @since 0.8.0
  class DocstringParser
    # @return [String] the parsed text portion of the docstring,
    #   with tags removed.
    attr_accessor :text

    # @return [String] the complete input string to the parser.
    attr_accessor :raw_text

    # @return [Array<Tags::Tag>] the list of meta-data tags identified
    #   by the parser
    attr_accessor :tags

    # @return [Array<Tags::Directive>] a list of directives identified
    #   by the parser. This list will not be passed on to the
    #   Docstring object.
    attr_accessor :directives

    # @return [OpenStruct] any arbitrary state to be passed between
    #   tags during parsing. Mainly used by directives to coordinate
    #   behaviour (so that directives can be aware of other directives
    #   used in a docstring).
    attr_accessor :state

    # @return [CodeObjects::Base, nil] the object associated with
    #   the docstring being parsed. May be nil if the docstring is
    #   not attached to any object.
    attr_accessor :object

    # @return [CodeObjects::Base, nil] the object referenced by
    #   the docstring being parsed. May be nil if the docstring doesn't
    #   refer to any object.
    attr_accessor :reference

    # @return [Handlers::Base, nil] the handler parsing this
    #   docstring. May be nil if this docstring parser is not
    #   initialized through
    attr_accessor :handler

    # @return [Tags::Library] the tag library being used to
    #   identify registered tags in the docstring.
    attr_accessor :library

    # The regular expression to match the tag syntax
    META_MATCH = /^@(!)?((?:\w\.?)+)(?:\s+(.*))?$/i

    # @!group Creation and Conversion Methods

    # Creates a new parser to parse docstring data
    #
    # @param [Tags::Library] library a tag library for recognizing
    #   tags.
    def initialize(library = Tags::Library.instance)
      @text = ""
      @raw_text = ""
      @tags = []
      @directives = []
      @library = library
      @object = nil
      @reference = nil
      @handler = nil
      @state = OpenStruct.new
    end

    # @return [Docstring] translates parsed text into
    #   a Docstring object.
    def to_docstring
      Docstring.new!(text, tags, object, raw_text, reference)
    end

    # @!group Parsing Methods

    # Parses all content and returns itself.
    #
    # @param [String] content the docstring text to parse
    # @param [CodeObjects::Base] object the object that the docstring
    #   is attached to. Will be passed to directives to act on
    #   this object.
    # @param [Handlers::Base, nil] handler the handler object that is
    #   parsing this object. May be nil if this parser is not being
    #   called from a {Parser::SourceParser} context.
    # @return [self] the parser object. To get the docstring,
    #   call {#to_docstring}.
    # @see #to_docstring
    def parse(content, object = nil, handler = nil)
      @object = object
      @handler = handler
      @reference, @raw_text = detect_reference(content)
      text = parse_content(@raw_text)
      @text = text.strip
      call_directives_after_parse
      post_process
      self
    end

    # Parses a given block of text.
    #
    # @param [String] content the content to parse
    # @note Subclasses can override this method to perform custom
    #   parsing of content data.
    def parse_content(content)
      content = content.split(/\r?\n/) if content.is_a?(String)
      return '' if !content || content.empty?
      docstring = String.new("")

      indent = content.first[/^\s*/].length
      last_indent = 0
      orig_indent = 0
      directive = false
      last_line = ""
      tag_name = nil
      tag_buf = []

      (content + ['']).each_with_index do |line, index|
        indent = line[/^\s*/].length
        empty = (line =~ /^\s*$/ ? true : false)
        done = content.size == index

        if tag_name && (((indent < orig_indent && !empty) || done ||
            (indent == 0 && !empty)) || (indent <= last_indent && line =~ META_MATCH))
          buf = tag_buf.join("\n")
          if directive || tag_is_directive?(tag_name)
            directive = create_directive(tag_name, buf)
            if directive
              docstring << parse_content(directive.expanded_text).chomp
            end
          else
            create_tag(tag_name, buf)
          end
          tag_name = nil
          tag_buf = []
          directive = false
          orig_indent = 0
        end

        # Found a meta tag
        if line =~ META_MATCH
          directive = $1
          tag_name = $2
          tag_buf = [($3 || '')]
        elsif tag_name && indent >= orig_indent && !empty
          orig_indent = indent if orig_indent == 0
          # Extra data added to the tag on the next line
          last_empty = last_line =~ /^[ \t]*$/ ? true : false

          tag_buf << '' if last_empty
          tag_buf << line.gsub(/^[ \t]{#{orig_indent}}/, '')
        elsif !tag_name
          # Regular docstring text
          docstring << line
          docstring << "\n"
        end

        last_indent = indent
        last_line = line
      end

      docstring
    end

    # @!group Parser Callback Methods

    # Call post processing callbacks on parser.
    # This is called implicitly by parser. Use this when
    # manually configuring a {Docstring} object.
    #
    # @return [void]
    def post_process
      call_after_parse_callbacks
    end

    # @!group Tag Manipulation Methods

    # Creates a tag from the {Tags::DefaultFactory tag factory}.
    #
    # To add an already created tag object, append it to {#tags}.
    #
    # @param [String] tag_name the tag name
    # @param [String] tag_buf the text attached to the tag with newlines removed.
    # @return [Tags::Tag, Tags::RefTag] a tag
    def create_tag(tag_name, tag_buf = '')
      if tag_buf =~ /\A\s*(?:(\S+)\s+)?\(\s*see\s+(\S+)\s*\)\s*\Z/
        return create_ref_tag(tag_name, $1, $2)
      end

      if library.has_tag?(tag_name)
        @tags += [library.tag_create(tag_name, tag_buf)].flatten
      else
        log.warn "Unknown tag @#{tag_name}" +
                 (object ? " in file `#{object.file}` near line #{object.line}" : "")
      end
    rescue Tags::TagFormatError
      log.warn "Invalid tag format for @#{tag_name}" +
               (object ? " in file `#{object.file}` near line #{object.line}" : "")
    end

    # Creates a {Tags::RefTag}
    def create_ref_tag(tag_name, name, object_name)
      @tags << Tags::RefTagList.new(tag_name, P(object, object_name), name)
    end

    # Creates a new directive using the registered {#library}
    # @return [Tags::Directive] the directive object that is created
    def create_directive(tag_name, tag_buf)
      if library.has_directive?(tag_name)
        dir = library.directive_create(tag_name, tag_buf, self)
        if dir.is_a?(Tags::Directive)
          @directives << dir
          dir
        end
      else
        log.warn "Unknown directive @!#{tag_name}" +
                 (object ? " in file `#{object.file}` near line #{object.line}" : "")
        nil
      end
    rescue Tags::TagFormatError
      log.warn "Invalid directive format for @!#{tag_name}" +
               (object ? " in file `#{object.file}` near line #{object.line}" : "")
      nil
    end

    # Backward compatibility to detect old tags that should be specified
    # as directives in 0.8 and onward.
    def tag_is_directive?(tag_name)
      list = %w(attribute endgroup group macro method scope visibility)
      list.include?(tag_name)
    end

    # Creates a callback that is called after a docstring is successfully
    # parsed. Use this method to perform sanity checks on a docstring's
    # tag data, or add any extra tags automatically to a docstring.
    #
    # @yield [parser] a block to be called after a docstring is parsed
    # @yieldparam [DocstringParser] parser the docstring parser object
    #   with all directives and tags created.
    # @yieldreturn [void]
    # @return [void]
    def self.after_parse(&block)
      after_parse_callbacks << block
    end

    # @return [Array<Proc>] the {after_parse} callback proc objects
    def self.after_parse_callbacks
      @after_parse_callbacks ||= []
    end

    # Define a callback to check that @param tags are properly named
    after_parse do |parser|
      next unless parser.object
      next unless parser.object.is_a?(CodeObjects::MethodObject)
      next if parser.object.is_alias?
      names = parser.object.parameters.map {|l| l.first.gsub(/\W/, '') }
      seen_names = []
      infile_info = "\n    in file `#{parser.object.file}' " \
                    "near line #{parser.object.line}"
      parser.tags.each do |tag|
        next if tag.is_a?(Tags::RefTagList) # we don't handle this yet
        next unless tag.tag_name == "param"
        if seen_names.include?(tag.name)
          log.warn "@param tag has duplicate parameter name: " \
                   "#{tag.name} #{infile_info}"
        elsif names.include?(tag.name)
          seen_names << tag.name
        else
          log.warn "@param tag has unknown parameter name: " \
                   "#{tag.name} #{infile_info}"
        end
      end
    end

    private

    def namespace
      object && object.namespace
    end

    def detect_reference(content)
      if content =~ /\A\s*\(see (\S+)\s*\)(?:\s|$)/
        path = $1
        extra = $'
        [CodeObjects::Proxy.new(namespace, path), extra]
      else
        [nil, content]
      end
    end

    # @!group Parser Callback Methods

    # Calls the {Tags::Directive#after_parse} callback on all the
    # created directives.
    def call_directives_after_parse
      directives.each(&:after_parse)
    end

    # Calls all {after_parse} callbacks
    def call_after_parse_callbacks
      self.class.after_parse_callbacks.each do |cb|
        cb.call(self)
      end
    end

    # Define a callback to check that @see tags do not use {}.
    after_parse do |parser|
      next unless parser.object

      parser.tags.each_with_index do |tag, i|
        next if tag.is_a?(Tags::RefTagList) # we don't handle this yet
        next unless tag.tag_name == "see"
        next unless "#{tag.name}#{tag.text}" =~ /\A\{.*\}\Z/
        infile_info = "\n    in file `#{parser.object.file}' " \
                      "near line #{parser.object.line}"
        log.warn "@see tag (##{i + 1}) should not be wrapped in {} " \
                 "(causes rendering issues): #{infile_info}"
      end
    end
  end
end
