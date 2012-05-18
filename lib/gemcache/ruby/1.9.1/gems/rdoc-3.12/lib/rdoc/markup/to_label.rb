require 'cgi'

##
# Creates HTML-safe labels suitable for use in id attributes.  Tidylinks are
# converted to their link part and cross-reference links have the suppression
# marks removed (\\SomeClass is converted to SomeClass).

class RDoc::Markup::ToLabel < RDoc::Markup::Formatter

  ##
  # Creates a new formatter that will output HTML-safe labels

  def initialize markup = nil
    super

    @markup.add_special RDoc::CrossReference::CROSSREF_REGEXP, :CROSSREF
    @markup.add_special(/(((\{.*?\})|\b\S+?)\[\S+?\])/, :TIDYLINK)

    add_tag :BOLD, '', ''
    add_tag :TT,   '', ''
    add_tag :EM,   '', ''
  end

  ##
  # Converts +text+ to an HTML-safe label

  def convert text
    label = convert_flow @am.flow text

    CGI.escape label
  end

  ##
  # Converts the CROSSREF +special+ to plain text, removing the suppression
  # marker, if any

  def handle_special_CROSSREF special
    text = special.text

    text.sub(/^\\/, '')
  end

  ##
  # Converts the TIDYLINK +special+ to just the text part

  def handle_special_TIDYLINK special
    text = special.text

    return text unless text =~ /\{(.*?)\}\[(.*?)\]/ or text =~ /(\S+)\[(.*?)\]/

    $1
  end

end

