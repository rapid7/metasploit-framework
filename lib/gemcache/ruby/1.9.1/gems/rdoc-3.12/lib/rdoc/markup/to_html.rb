require 'cgi'

##
# Outputs RDoc markup as HTML.

class RDoc::Markup::ToHtml < RDoc::Markup::Formatter

  include RDoc::Text

  # :section: Utilities

  ##
  # Maps RDoc::Markup::Parser::LIST_TOKENS types to HTML tags

  LIST_TYPE_TO_HTML = {
    :BULLET => ['<ul>',                                      '</ul>'],
    :LABEL  => ['<dl class="rdoc-list label-list">',         '</dl>'],
    :LALPHA => ['<ol style="list-style-type: lower-alpha">', '</ol>'],
    :NOTE   => ['<dl class="rdoc-list note-list">',          '</dl>'],
    :NUMBER => ['<ol>',                                      '</ol>'],
    :UALPHA => ['<ol style="list-style-type: upper-alpha">', '</ol>'],
  }

  attr_reader :res # :nodoc:
  attr_reader :in_list_entry # :nodoc:
  attr_reader :list # :nodoc:

  ##
  # The RDoc::CodeObject HTML is being generated for.  This is used to
  # generate namespaced URI fragments

  attr_accessor :code_object

  ##
  # Path to this document for relative links

  attr_accessor :from_path

  ##
  # Converts a target url to one that is relative to a given path

  def self.gen_relative_url(path, target)
    from        = File.dirname path
    to, to_file = File.split target

    from = from.split "/"
    to   = to.split "/"

    from.delete '.'
    to.delete '.'

    while from.size > 0 and to.size > 0 and from[0] == to[0] do
      from.shift
      to.shift
    end

    from.fill ".."
    from.concat to
    from << to_file
    File.join(*from)
  end

  # :section:

  ##
  # Creates a new formatter that will output HTML

  def initialize markup = nil
    super

    @code_object = nil
    @from_path = ''
    @in_list_entry = nil
    @list = nil
    @th = nil

    # external links
    @markup.add_special(/((link:|https?:|mailto:|ftp:|irc:|www\.)\S+\w)/,
                        :HYPERLINK)

    # internal links
    @markup.add_special(/rdoc-[a-z]+:\S+/, :RDOCLINK)

    # and links of the form  <text>[<url>]
    @markup.add_special(/(((\{.*?\})|\b\S+?)\[\S+?\])/, :TIDYLINK)

    init_tags
  end

  # :section: Special Handling
  #
  # These methods handle special markup added by RDoc::Markup#add_special.

  ##
  # +special+ is a potential link.  The following schemes are handled:
  #
  # <tt>mailto:</tt>::
  #   Inserted as-is.
  # <tt>http:</tt>::
  #   Links are checked to see if they reference an image. If so, that image
  #   gets inserted using an <tt><img></tt> tag. Otherwise a conventional
  #   <tt><a href></tt> is used.
  # <tt>link:</tt>::
  #   Reference to a local file relative to the output directory.

  def handle_special_HYPERLINK(special)
    url = special.text

    gen_url url, url
  end

  ##
  # +special+ is an rdoc-schemed link that will be converted into a hyperlink.
  #
  # For the +rdoc-ref+ scheme the named reference will be returned without
  # creating a link.
  #
  # For the +rdoc-label+ scheme the footnote and label prefixes are stripped
  # when creating a link.  All other contents will be linked verbatim.

  def handle_special_RDOCLINK special
    url = special.text

    case url
    when /\Ardoc-ref:/
      $'
    when /\Ardoc-label:/
      text = $'

      text = case text
             when /\Alabel-/    then $'
             when /\Afootmark-/ then "^#{$'}"
             when /\Afoottext-/ then "*#{$'}"
             else                    text
             end

      gen_url url, text
    else
      url =~ /\Ardoc-[a-z]+:/

      $'
    end
  end

  ##
  # This +special+ is a link where the label is different from the URL
  # <tt>label[url]</tt> or <tt>{long label}[url]</tt>

  def handle_special_TIDYLINK(special)
    text = special.text

    return text unless text =~ /\{(.*?)\}\[(.*?)\]/ or text =~ /(\S+)\[(.*?)\]/

    label = $1
    url   = $2
    gen_url url, label
  end

  # :section: Visitor
  #
  # These methods implement the HTML visitor.

  ##
  # Prepares the visitor for HTML generation

  def start_accepting
    @res = []
    @in_list_entry = []
    @list = []
  end

  ##
  # Returns the generated output

  def end_accepting
    @res.join
  end

  ##
  # Adds +paragraph+ to the output

  def accept_paragraph(paragraph)
    @res << "\n<p>"
    @res << wrap(to_html(paragraph.text))
    @res << "</p>\n"
  end

  ##
  # Adds +verbatim+ to the output

  def accept_verbatim verbatim
    text = verbatim.text.rstrip

    @res << if verbatim.ruby? or parseable? text then
              options = RDoc::RDoc.current.options if RDoc::RDoc.current

              begin
                tokens = RDoc::RubyLex.tokenize text, options

                "\n<pre class=\"ruby\">" \
                "#{RDoc::TokenStream.to_html tokens}" \
                "</pre>\n"
              rescue RDoc::RubyLex::Error
                "\n<pre>#{CGI.escapeHTML text}</pre>\n"
              end
            else
              "\n<pre>#{CGI.escapeHTML text}</pre>\n"
            end
  end

  ##
  # Adds +rule+ to the output

  def accept_rule(rule)
    size = rule.weight
    size = 10 if size > 10
    @res << "<hr style=\"height: #{size}px\">\n"
  end

  ##
  # Prepares the visitor for consuming +list+

  def accept_list_start(list)
    @list << list.type
    @res << html_list_name(list.type, true)
    @in_list_entry.push false
  end

  ##
  # Finishes consumption of +list+

  def accept_list_end(list)
    @list.pop
    if tag = @in_list_entry.pop
      @res << tag
    end
    @res << html_list_name(list.type, false) << "\n"
  end

  ##
  # Prepares the visitor for consuming +list_item+

  def accept_list_item_start(list_item)
    if tag = @in_list_entry.last
      @res << tag
    end

    @res << list_item_start(list_item, @list.last)
  end

  ##
  # Finishes consumption of +list_item+

  def accept_list_item_end(list_item)
    @in_list_entry[-1] = list_end_for(@list.last)
  end

  ##
  # Adds +blank_line+ to the output

  def accept_blank_line(blank_line)
    # @res << annotate("<p />") << "\n"
  end

  ##
  # Adds +heading+ to the output.  The headings greater than 6 are trimmed to
  # level 6.

  def accept_heading heading
    level = [6, heading.level].min

    label = heading.aref
    label = [@code_object.aref, label].compact.join '-' if
      @code_object and @code_object.respond_to? :aref

    @res << "\n<h#{level} id=\"#{label}\">"
    @res << to_html(heading.text)
    @res << "</h#{level}>\n"
  end

  ##
  # Adds +raw+ to the output

  def accept_raw raw
    @res << raw.parts.join("\n")
  end

  # :section: Utilities

  ##
  # CGI escapes +text+

  def convert_string(text)
    CGI.escapeHTML text
  end

  ##
  # Generate a link to +url+ with content +text+.  Handles the special cases
  # for img: and link: described under handle_special_HYPERLINK

  def gen_url url, text
    if url =~ /^rdoc-label:([^:]*)(?::(.*))?/ then
      type = "link"
      path = "##{$1}"
      id   = " id=\"#{$2}\"" if $2
    elsif url =~ /([A-Za-z]+):(.*)/ then
      type = $1
      path = $2
    else
      type = "http"
      path = url
      url  = "http://#{url}"
    end

    if type == "link" then
      url = if path[0, 1] == '#' then # is this meaningful?
              path
            else
              self.class.gen_relative_url @from_path, path
            end
    end

    if (type == "http" or type == "https" or type == "link") and
       url =~ /\.(gif|png|jpg|jpeg|bmp)$/ then
      "<img src=\"#{url}\" />"
    else
      "<a#{id} href=\"#{url}\">#{text.sub(%r{^#{type}:/*}, '')}</a>"
    end
  end

  ##
  # Determines the HTML list element for +list_type+ and +open_tag+

  def html_list_name(list_type, open_tag)
    tags = LIST_TYPE_TO_HTML[list_type]
    raise RDoc::Error, "Invalid list type: #{list_type.inspect}" unless tags
    tags[open_tag ? 0 : 1]
  end

  ##
  # Maps attributes to HTML tags

  def init_tags
    add_tag :BOLD, "<strong>", "</strong>"
    add_tag :TT,   "<code>",   "</code>"
    add_tag :EM,   "<em>",     "</em>"
  end

  ##
  # Returns the HTML tag for +list_type+, possible using a label from
  # +list_item+

  def list_item_start(list_item, list_type)
    case list_type
    when :BULLET, :LALPHA, :NUMBER, :UALPHA then
      "<li>"
    when :LABEL, :NOTE then
      "<dt>#{to_html list_item.label}\n<dd>"
    else
      raise RDoc::Error, "Invalid list type: #{list_type.inspect}"
    end
  end

  ##
  # Returns the HTML end-tag for +list_type+

  def list_end_for(list_type)
    case list_type
    when :BULLET, :LALPHA, :NUMBER, :UALPHA then
      "</li>"
    when :LABEL, :NOTE then
      "</dd>"
    else
      raise RDoc::Error, "Invalid list type: #{list_type.inspect}"
    end
  end

  ##
  # Returns true if Ripper is available it can create a sexp from +text+

  def parseable? text
    text =~ /\b(def|class|module|require)\b|=>|\{\s?\||do \|/ and
      text !~ /<%|%>/
  end

  ##
  # Converts +item+ to HTML using RDoc::Text#to_html

  def to_html item
    super convert_flow @am.flow item
  end

end

