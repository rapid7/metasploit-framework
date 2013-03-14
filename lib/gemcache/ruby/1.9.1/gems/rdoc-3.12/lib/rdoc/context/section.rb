##
# A section of documentation like:
#
#   # :section: The title
#   # The body
#
# Sections can be referenced multiple times and will be collapsed into a
# single section.

class RDoc::Context::Section

  include RDoc::Text

  ##
  # Section comment

  attr_reader :comment

  ##
  # Context this Section lives in

  attr_reader :parent

  ##
  # Section title

  attr_reader :title

  @@sequence = "SEC00000"

  ##
  # Creates a new section with +title+ and +comment+

  def initialize parent, title, comment
    @parent = parent
    @title = title ? title.strip : title

    @@sequence.succ!
    @sequence = @@sequence.dup

    @comment = nil
    @comment = extract_comment comment if comment
  end

  ##
  # Sections are equal when they have the same #title

  def == other
    self.class === other and @title == other.title
  end

  ##
  # Anchor reference for linking to this section

  def aref
    title = @title || '[untitled]'

    CGI.escape(title).gsub('%', '-').sub(/^-/, '')
  end

  ##
  # Appends +comment+ to the current comment separated by a rule.

  def comment= comment
    comment = extract_comment comment

    return if comment.empty?

    if @comment then
      # HACK should section comments get joined?
      @comment.text += "\n# ---\n#{comment.text}"
    else
      @comment = comment
    end
  end

  ##
  # Extracts the comment for this section from the original comment block.
  # If the first line contains :section:, strip it and use the rest.
  # Otherwise remove lines up to the line containing :section:, and look
  # for those lines again at the end and remove them. This lets us write
  #
  #   # :section: The title
  #   # The body

  def extract_comment comment
    if comment.text =~ /^#[ \t]*:section:.*\n/ then
      start = $`
      rest = $'

      comment.text = if start.empty? then
                       rest
                     else
                       rest.sub(/#{start.chomp}\Z/, '')
                     end
    end

    comment
  end

  def inspect # :nodoc:
    "#<%s:0x%x %p>" % [self.class, object_id, title]
  end

  ##
  # The section's title, or 'Top Section' if the title is nil.
  #
  # This is used by the table of contents template so the name is silly.

  def plain_html
    @title || 'Top Section'
  end

  ##
  # Section sequence number (deprecated)

  def sequence
    warn "RDoc::Context::Section#sequence is deprecated, use #aref"
    @sequence
  end

end

