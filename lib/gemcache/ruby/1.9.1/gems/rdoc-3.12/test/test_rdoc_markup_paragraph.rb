require 'rdoc/test_case'

class TestRDocMarkupParagraph < RDoc::TestCase

  def test_accept
    visitor = Object.new
    def visitor.accept_paragraph(obj) @obj = obj end
    def visitor.obj() @obj end

    paragraph = RDoc::Markup::Paragraph.new

    paragraph.accept visitor

    assert_equal paragraph, visitor.obj
  end

end

