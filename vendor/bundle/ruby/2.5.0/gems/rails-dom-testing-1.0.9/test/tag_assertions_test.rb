require 'test_helper'
require 'rails/dom/testing/assertions/tag_assertions'

HTML_TEST_OUTPUT = <<HTML
<html>
  <body>
    <a href="/"><img src="/images/button.png" /></a>
    <div id="foo">
      <ul>
        <li class="item">hello</li>
        <li class="item">goodbye</li>
      </ul>
    </div>
    <div id="bar">
      <form action="/somewhere">
        Name: <input type="text" name="person[name]" id="person_name" />
      </form>
    </div>
  </body>
</html>
HTML

class AssertTagTest < ActiveSupport::TestCase
  include Rails::Dom::Testing::Assertions::TagAssertions

  class FakeResponse
    attr_accessor :content_type, :body

    def initialize(content_type, body)
      @content_type, @body = content_type, body
    end
  end

  setup do
    @response = FakeResponse.new 'html', HTML_TEST_OUTPUT
  end

  def test_assert_tag_tag
    assert_deprecated do
      # there is a 'form' tag
      assert_tag tag: 'form'
      # there is not an 'hr' tag
      assert_no_tag tag: 'hr'
    end
  end

  def test_assert_tag_attributes
    assert_deprecated do
      # there is a tag with an 'id' of 'bar'
      assert_tag attributes: { id: "bar" }
      # there is no tag with a 'name' of 'baz'
      assert_no_tag attributes: { name: "baz" }
    end
  end

  def test_assert_tag_parent
    assert_deprecated do
      # there is a tag with a parent 'form' tag
      assert_tag parent: { tag: "form" }
      # there is no tag with a parent of 'input'
      assert_no_tag parent: { tag: "input" }
    end
  end

  def test_assert_tag_child
    assert_deprecated do
      # there is a tag with a child 'input' tag
      assert_tag child: { tag: "input" }
      # there is no tag with a child 'strong' tag
      assert_no_tag child: { tag: "strong" }
    end
  end

  def test_assert_tag_ancestor
    assert_deprecated do
      # there is a 'li' tag with an ancestor having an id of 'foo'
      assert_tag ancestor: { attributes: { id: "foo" } }, tag: "li"
      # there is no tag of any kind with an ancestor having an href matching 'foo'
      assert_no_tag ancestor: { attributes: { href: /foo/ } }
    end
  end

  def test_assert_tag_descendant
    assert_deprecated do
      # there is a tag with a descendant 'li' tag
      assert_tag descendant: { tag: "li" }
      # there is no tag with a descendant 'html' tag
      assert_no_tag descendant: { tag: "html" }
    end
  end

  def test_assert_tag_sibling
    assert_deprecated do
      # there is a tag with a sibling of class 'item'
      assert_tag sibling: { attributes: { class: "item" } }
      # there is no tag with a sibling 'ul' tag
      assert_no_tag sibling: { tag: "ul" }
    end
  end

  def test_assert_tag_after
    assert_deprecated do
      # there is a tag following a sibling 'div' tag
      assert_tag after: { tag: "div" }
      # there is no tag following a sibling tag with id 'bar'
      assert_no_tag after: { attributes: { id: "bar" } }
    end
  end

  def test_assert_tag_before
    assert_deprecated do
      # there is a tag preceding a tag with id 'bar'
      assert_tag before: { attributes: { id: "bar" } }
      # there is no tag preceding a 'form' tag
      assert_no_tag before: { tag: "form" }
    end
  end

  def test_assert_tag_children_count
    assert_deprecated do
      # there is a tag with 2 children
      assert_tag children: { count: 2 }
      # in particular, there is a <ul> tag with two children (a nameless pair of <li>s)
      assert_tag tag: 'ul', children: { count: 2 }
      # there is no tag with 4 children
      assert_no_tag children: { count: 4 }
    end
  end

  def test_assert_tag_children_less_than
    assert_deprecated do
      # there is a tag with less than 5 children
      assert_tag children: { less_than: 5 }
      # there is no 'ul' tag with less than 2 children
      assert_no_tag children: { less_than: 2 }, tag: "ul"
    end
  end

  def test_assert_tag_children_greater_than
    assert_deprecated do
      # there is a 'body' tag with more than 1 children
      assert_tag children: { greater_than: 1 }, tag: "body"
      # there is no tag with more than 10 children
      assert_no_tag children: { greater_than: 10 }
    end
  end

  def test_assert_tag_children_only
    assert_deprecated do
      # there is a tag containing only one child with an id of 'foo'
      assert_tag children: { count: 1,
                             only: { attributes: { id: "foo" } } }
      # there is no tag containing only one 'li' child
      assert_no_tag children: { count: 1, only: { tag: "li" } }
    end
  end

  def test_assert_tag_content
    assert_deprecated do
      # the output contains the string "Name"
      assert_tag content: /Name/
      # the output does not contain the string "test"
      assert_no_tag content: /test/
    end
  end

  def test_assert_tag_multiple
    assert_deprecated do
      # there is a 'div', id='bar', with an immediate child whose 'action'
      # attribute matches the regexp /somewhere/.
      assert_tag tag: "div", attributes: { id: "bar" },
        child: { attributes: { action: /somewhere/ } }

      # there is no 'div', id='foo', with a 'ul' child with more than
      # 2 "li" children.
      assert_no_tag tag: "div", attributes: { id: "foo" },
        child: { tag: "ul",
                 children: { greater_than: 2, only: { tag: "li" } } }
    end
  end

  def test_assert_tag_children_without_content
    assert_deprecated do
      # there is a form tag with an 'input' child which is a self closing tag
      assert_tag tag: "form",
        children: { count: 1,
                    only: { tag: "input" } }

        # the body tag has an 'a' child which in turn has an 'img' child
        assert_tag tag: "body",
          children: { count: 1,
                      only: { tag: "a",
                              children: { count: 1,
                                          only: { tag: "img" } } } }
    end
  end

  def test_assert_tag_attribute_matching
    assert_deprecated do
      @response.body = '<input type="text" name="my_name">'
      assert_tag tag: 'input',
        attributes: { name: /my/, type: 'text' }
      assert_no_tag tag: 'input',
        attributes: { name: 'my', type: 'text' }
      assert_no_tag tag: 'input',
        attributes: { name: /^my$/, type: 'text' }
    end
  end

  def test_assert_tag_content_matching
    assert_deprecated do
      @response.body = "<p>hello world</p>"
      assert_tag tag: "p", content: "hello world"
      assert_tag tag: "p", content: /hello/
      assert_no_tag tag: "p", content: "hello"
    end
  end
end
