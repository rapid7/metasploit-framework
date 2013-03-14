##
# Extracts just the RDoc::Markup::Heading elements from a
# RDoc::Markup::Document to help build a table of contents

class RDoc::Markup::ToTableOfContents < RDoc::Markup::Formatter

  @to_toc = nil

  ##
  # Singleton for ToC generation

  def self.to_toc
    @to_toc ||= new
  end

  ##
  # Output accumulator

  attr_reader :res

  ##
  # Adds +heading+ to the table of contents

  def accept_heading heading
    @res << heading
  end

  ##
  # Returns the table of contents

  def end_accepting
    @res
  end

  ##
  # Prepares the visitor for text generation

  def start_accepting
    @res = []
  end

  # :stopdoc:
  alias accept_raw             ignore
  alias accept_rule            ignore
  alias accept_blank_line      ignore
  alias accept_paragraph       ignore
  alias accept_verbatim        ignore
  alias accept_list_end        ignore
  alias accept_list_item_start ignore
  alias accept_list_item_end   ignore
  alias accept_list_end_bullet ignore
  alias accept_list_start      ignore
  # :startdoc:

end

