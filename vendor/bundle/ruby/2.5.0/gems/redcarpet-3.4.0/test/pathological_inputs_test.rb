# coding: UTF-8
require 'test_helper'

# Disabled by default
# (these are the easy ones -- the evil ones are not disclosed)
class PathologicalInputsTest # < Redcarpet::TestCase
  def setup
    @markdown = Redcarpet::Markdown.new(Redcarpet::Render::HTML)
  end

  def test_pathological_1
    star = '*'  * 250000
    @markdown.render("#{star}#{star} hi #{star}#{star}")
  end

  def test_pathological_2
    crt = '^' * 255
    str = "#{crt}(\\)"
    @markdown.render("#{str*300}")
  end

  def test_pathological_3
    c = "`t`t`t`t`t`t" * 20000000
    @markdown.render(c)
  end

  def test_pathological_4
    @markdown.render(" [^a]: #{ "A" * 10000 }\n#{ "[^a][]" * 1000000 }\n")
  end

  def test_unbound_recursion
    @markdown.render(("[" * 10000) + "foo" + ("](bar)" * 10000))
  end
end
