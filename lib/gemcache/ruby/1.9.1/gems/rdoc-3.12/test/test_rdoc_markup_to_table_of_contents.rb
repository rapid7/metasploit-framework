require 'rdoc/test_case'

class TestRDocMarkupToTableOfContents < RDoc::Markup::FormatterTestCase

  add_visitor_tests

  def setup
    super

    @to = RDoc::Markup::ToTableOfContents.new
  end

  def end_accepting
    assert_equal %w[hi], @to.res
  end

  def empty
    assert_empty @to.res
  end

  def accept_heading
    assert_equal [@RM::Heading.new(5, 'Hello')], @to.res
  end

  def accept_heading_1
    assert_equal [@RM::Heading.new(1, 'Hello')], @to.res
  end

  def accept_heading_2
    assert_equal [@RM::Heading.new(2, 'Hello')], @to.res
  end

  def accept_heading_3
    assert_equal [@RM::Heading.new(3, 'Hello')], @to.res
  end

  def accept_heading_4
    assert_equal [@RM::Heading.new(4, 'Hello')], @to.res
  end

  def accept_heading_b
    assert_equal [@RM::Heading.new(1, '*Hello*')], @to.res
  end

  def accept_heading_suppressed_crossref
    assert_equal [@RM::Heading.new(1, '\\Hello')], @to.res
  end

  alias accept_blank_line             empty
  alias accept_document               empty
  alias accept_list_end_bullet        empty
  alias accept_list_end_label         empty
  alias accept_list_end_lalpha        empty
  alias accept_list_end_note          empty
  alias accept_list_end_number        empty
  alias accept_list_end_ualpha        empty
  alias accept_list_item_end_bullet   empty
  alias accept_list_item_end_label    empty
  alias accept_list_item_end_lalpha   empty
  alias accept_list_item_end_note     empty
  alias accept_list_item_end_number   empty
  alias accept_list_item_end_ualpha   empty
  alias accept_list_item_start_bullet empty
  alias accept_list_item_start_label  empty
  alias accept_list_item_start_lalpha empty
  alias accept_list_item_start_note   empty
  alias accept_list_item_start_note_2 empty
  alias accept_list_item_start_number empty
  alias accept_list_item_start_ualpha empty
  alias accept_list_start_bullet      empty
  alias accept_list_start_label       empty
  alias accept_list_start_lalpha      empty
  alias accept_list_start_note        empty
  alias accept_list_start_number      empty
  alias accept_list_start_ualpha      empty
  alias accept_paragraph              empty
  alias accept_paragraph_b            empty
  alias accept_paragraph_i            empty
  alias accept_paragraph_plus         empty
  alias accept_paragraph_star         empty
  alias accept_paragraph_underscore   empty
  alias accept_raw                    empty
  alias accept_rule                   empty
  alias accept_verbatim               empty
  alias list_nested                   empty
  alias list_verbatim                 empty
  alias start_accepting               empty

end

