# frozen_string_literal: true
module YARD
  # A documentation string, or "docstring" for short, encapsulates the
  # comments and metadata, or "tags", of an object. Meta-data is expressed
  # in the form +@tag VALUE+, where VALUE can span over multiple lines as
  # long as they are indented. The following +@example+ tag shows how tags
  # can be indented:
  #
  #   # @example My example
  #   #   a = "hello world"
  #   #   a.reverse
  #   # @version 1.0
  #
  # Tags can be nested in a documentation string, though the {Tags::Tag}
  # itself is responsible for parsing the inner tags.
  class Docstring < String
    class << self
      # @note Plugin developers should make sure to reset this value
      #   after parsing finishes. This can be done via the
      #   {Parser::SourceParser.after_parse_list} callback. This will
      #   ensure that YARD can properly parse multiple projects in
      #   the same process.
      # @return [Class<DocstringParser>] the parser class used to parse
      #   text and optional meta-data from docstrings. Defaults to
      #   {DocstringParser}.
      # @see DocstringParser
      # @see Parser::SourceParser.after_parse_list
      attr_accessor :default_parser

      # Creates a parser object using the current {default_parser}.
      # Equivalent to:
      #   Docstring.default_parser.new(*args)
      # @param args arguments are passed to the {DocstringParser}
      #   class. See {DocstringParser#initialize} for details on
      #   arguments.
      # @return [DocstringParser] the parser object used to parse a
      #   docstring.
      def parser(*args) default_parser.new(*args) end
    end

    self.default_parser = DocstringParser

    # @return [Array<Tags::RefTag>] the list of reference tags
    attr_reader :ref_tags

    # @return [CodeObjects::Base] the object that owns the docstring.
    attr_accessor :object

    # @return [Range] line range in the {#object}'s file where the docstring was parsed from
    attr_accessor :line_range

    # @return [String] the raw documentation (including raw tag text)
    attr_reader :all

    # @return [Boolean] whether the docstring was started with "##"
    attr_reader :hash_flag
    def hash_flag=(v) @hash_flag = v.nil? ? false : v end

    # Matches a tag at the start of a comment line
    # @deprecated Use {DocstringParser::META_MATCH}
    META_MATCH = DocstringParser::META_MATCH

    # @group Creating a Docstring Object

    # Creates a new docstring without performing any parsing through
    # a {DocstringParser}. This method is called by +DocstringParser+
    # when creating the new docstring object.
    #
    # @param [String] text the textual portion of the docstring
    # @param [Array<Tags::Tag>] tags the list of tag objects in the docstring
    # @param [CodeObjects::Base, nil] object the object associated with the
    #   docstring. May be nil.
    # @param [String] raw_data the complete docstring, including all
    #   original formatting and any unparsed tags/directives.
    # @param [CodeObjects::Base, nil] ref_object a reference object used for
    #   the base set of documentation / tag information.
    def self.new!(text, tags = [], object = nil, raw_data = nil, ref_object = nil)
      docstring = allocate
      docstring.replace(text, false)
      docstring.object = object
      docstring.add_tag(*tags)
      docstring.instance_variable_set("@unresolved_reference", ref_object)
      docstring.instance_variable_set("@all", raw_data) if raw_data
      docstring
    end

    # Creates a new docstring with the raw contents attached to an optional
    # object. Parsing will be done by the {DocstringParser} class.
    #
    # @note To properly parse directives with proper parser context within
    #   handlers, you should not use this method to create a Docstring.
    #   Instead, use the {parser}, which takes a handler object that
    #   can pass parser state onto directives. If a Docstring is created
    #   with this method, directives do not have access to any parser
    #   state, and may not function as expected.
    # @example
    #   Docstring.new("hello world\n@return Object return", someobj)
    #
    # @param [String] content the raw comments to be parsed into a docstring
    #   and associated meta-data.
    # @param [CodeObjects::Base] object an object to associate the docstring
    #   with.
    def initialize(content = '', object = nil)
      @object = object
      @summary = nil
      @hash_flag = false

      self.all = content
    end

    # Adds another {Docstring}, copying over tags.
    #
    # @param [Docstring, String] other the other docstring (or string) to
    #   add.
    # @return [Docstring] a new docstring with both docstrings combines
    def +(other)
      case other
      when Docstring
        Docstring.new([all, other.all].join("\n"), object)
      else
        super
      end
    end

    def to_s
      resolve_reference
      super
    end

    # Replaces the docstring with new raw content. Called by {#all=}.
    # @param [String] content the raw comments to be parsed
    def replace(content, parse = true)
      content = content.join("\n") if content.is_a?(Array)
      @tags = []
      @ref_tags = []
      if parse
        super(parse_comments(content))
      else
        @all = content
        @unresolved_reference = nil
        super(content)
      end
    end
    alias all= replace

    # Deep-copies a docstring
    #
    # @note This method creates a new docstring with new tag lists, but does
    #   not create new individual tags. Modifying the tag objects will still
    #   affect the original tags.
    # @return [Docstring] a new copied docstring
    # @since 0.7.0
    def dup
      resolve_reference
      obj = super
      %w(all summary tags ref_tags).each do |name|
        val = instance_variable_defined?("@#{name}") && instance_variable_get("@#{name}")
        obj.instance_variable_set("@#{name}", val ? val.dup : nil)
      end
      obj
    end

    # @endgroup

    # @return [Fixnum] the first line of the {#line_range}
    # @return [nil] if there is no associated {#line_range}
    def line
      line_range ? line_range.first : nil
    end

    # Gets the first line of a docstring to the period or the first paragraph.
    # @return [String] The first line or paragraph of the docstring; always ends with a period.
    def summary
      resolve_reference
      return @summary if defined?(@summary) && @summary
      stripped = gsub(/[\r\n](?![\r\n])/, ' ').strip
      num_parens = 0
      idx = length.times do |index|
        case stripped[index, 1]
        when "."
          next_char = stripped[index + 1, 1].to_s
          break index - 1 if num_parens <= 0 && next_char =~ /^\s*$/
        when "\r", "\n"
          next_char = stripped[index + 1, 1].to_s
          if next_char =~ /^\s*$/
            break stripped[index - 1, 1] == '.' ? index - 2 : index - 1
          end
        when "{", "(", "["
          num_parens += 1
        when "}", ")", "]"
          num_parens -= 1
        end
      end
      @summary = stripped[0..idx]
      if !@summary.empty? && @summary !~ /\A\s*\{include:.+\}\s*\Z/
        @summary += '.'
      end
      @summary
    end

    # Reformats and returns a raw representation of the tag data using the
    # current tag and docstring data, not the original text.
    #
    # @return [String] the updated raw formatted docstring data
    # @since 0.7.0
    # @todo Add Tags::Tag#to_raw and refactor
    def to_raw
      tag_data = tags.sort_by(&:tag_name).map do |tag|
        case tag
        when Tags::OverloadTag
          tag_text = "@#{tag.tag_name} #{tag.signature}\n"
          unless tag.docstring.blank?
            tag_text += "\n  " + tag.docstring.all.gsub(/\r?\n/, "\n  ")
          end
        when Tags::OptionTag
          tag_text = "@#{tag.tag_name} #{tag.name}"
          tag_text += ' [' + tag.pair.types.join(', ') + ']' if tag.pair.types
          tag_text += ' ' + tag.pair.name.to_s if tag.pair.name
          tag_text += "\n " if tag.name && tag.text
          tag_text += ' (' + tag.pair.defaults.join(', ') + ')' if tag.pair.defaults
          tag_text += " " + tag.pair.text.strip.gsub(/\n/, "\n  ") if tag.pair.text
        else
          tag_text = '@' + tag.tag_name
          tag_text += ' [' + tag.types.join(', ') + ']' if tag.types
          tag_text += ' ' + tag.name.to_s if tag.name
          tag_text += "\n " if tag.name && tag.text
          tag_text += ' ' + tag.text.strip.gsub(/\n/, "\n  ") if tag.text
        end
        tag_text
      end
      [strip, tag_data.join("\n")].reject(&:empty?).compact.join("\n")
    end

    # @group Creating and Accessing Meta-data

    # Adds a tag or reftag object to the tag list. If you want to parse
    # tag data based on the {Tags::DefaultFactory} tag factory, use
    # {DocstringParser} instead.
    #
    # @param [Tags::Tag, Tags::RefTag] tags list of tag objects to add
    # @return [void]
    def add_tag(*tags)
      tags.each_with_index do |tag, i|
        case tag
        when Tags::Tag
          tag.object = object
          @tags << tag
        when Tags::RefTag, Tags::RefTagList
          @ref_tags << tag
        else
          raise ArgumentError, "expected Tag or RefTag, got #{tag.class} (at index #{i})"
        end
      end
    end

    # Convenience method to return the first tag
    # object in the list of tag objects of that name
    #
    # @example
    #   doc = Docstring.new("@return zero when nil")
    #   doc.tag(:return).text  # => "zero when nil"
    #
    # @param [#to_s] name the tag name to return data for
    # @return [Tags::Tag] the first tag in the list of {#tags}
    def tag(name)
      tags.find {|tag| tag.tag_name.to_s == name.to_s }
    end

    # Returns a list of tags specified by +name+ or all tags if +name+ is not specified.
    #
    # @param [#to_s] name the tag name to return data for, or nil for all tags
    # @return [Array<Tags::Tag>] the list of tags by the specified tag name
    def tags(name = nil)
      list = @tags + convert_ref_tags
      return list unless name
      list.select {|tag| tag.tag_name.to_s == name.to_s }
    end

    # Returns true if at least one tag by the name +name+ was declared
    #
    # @param [String] name the tag name to search for
    # @return [Boolean] whether or not the tag +name+ was declared
    def has_tag?(name)
      tags.any? {|tag| tag.tag_name.to_s == name.to_s }
    end

    # Delete all tags with +name+
    # @param [String] name the tag name
    # @return [void]
    # @since 0.7.0
    def delete_tags(name)
      delete_tag_if {|tag| tag.tag_name.to_s == name.to_s }
    end

    # Deletes all tags where the block returns true
    # @yieldparam [Tags::Tag] tag the tag that is being tested
    # @yieldreturn [Boolean] true if the tag should be deleted
    # @return [void]
    # @since 0.7.0
    def delete_tag_if(&block)
      @tags.delete_if(&block)
      @ref_tags.delete_if(&block)
    end

    # Returns true if the docstring has no content that is visible to a template.
    #
    # @param [Boolean] only_visible_tags whether only {Tags::Library.visible_tags}
    #   should be checked, or if all tags should be considered.
    # @return [Boolean] whether or not the docstring has content
    def blank?(only_visible_tags = true)
      if only_visible_tags
        empty? && !tags.any? {|tag| Tags::Library.visible_tags.include?(tag.tag_name.to_sym) }
      else
        empty? && @tags.empty? && @ref_tags.empty?
      end
    end

    # @endgroup

    # Resolves unresolved other docstring reference if there is
    # unresolved reference. Does nothing if there is no unresolved
    # reference.
    #
    # Normally, you don't need to call this method
    # explicitly. Resolving unresolved reference is done implicitly.
    #
    # @return [void]
    def resolve_reference
      loop do
        return if defined?(@unresolved_reference).nil? || @unresolved_reference.nil?
        return if CodeObjects::Proxy === @unresolved_reference

        reference = @unresolved_reference
        @unresolved_reference = nil
        self.all = [reference.docstring.all, @all].join("\n")
      end
    end

    private

    # Maps valid reference tags
    #
    # @return [Array<Tags::RefTag>] the list of valid reference tags
    def convert_ref_tags
      list = @ref_tags.reject {|t| CodeObjects::Proxy === t.owner }

      @ref_tag_recurse_count ||= 0
      @ref_tag_recurse_count += 1
      if @ref_tag_recurse_count > 2
        log.error "#{@object.file}:#{@object.line}: Detected circular reference tag in " \
                  "`#{@object}', ignoring all reference tags for this object " \
                  "(#{@ref_tags.map {|t| "@#{t.tag_name}" }.join(", ")})."
        @ref_tags = []
        return @ref_tags
      end
      list = list.map(&:tags).flatten
      @ref_tag_recurse_count -= 1
      list
    end

    # Parses out comments split by newlines into a new code object
    #
    # @param [String] comments
    #   the newline delimited array of comments. If the comments
    #   are passed as a String, they will be split by newlines.
    #
    # @return [String] the non-metadata portion of the comments to
    #   be used as a docstring
    def parse_comments(comments)
      parser = self.class.parser
      parser.parse(comments, object)
      @all = parser.raw_text
      @unresolved_reference = parser.reference
      add_tag(*parser.tags)
      parser.text
    end
  end
end
