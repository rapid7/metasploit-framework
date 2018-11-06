require File.dirname(__FILE__) + "/helper"

class CaseClauseNodeTest < NodeTestCase
  def test_to_sexp
    node = CaseClauseNode.new(ResolveNode.new('foo'))
    assert_sexp([:case, [:resolve, 'foo'], []], node)

    node = CaseClauseNode.new(nil)
    assert_sexp([:case, nil, []], node)

    node = CaseClauseNode.new(  ResolveNode.new('foo'),
                                SourceElementsNode.new([ResolveNode.new('bar')]))
    assert_sexp([:case, [:resolve, 'foo'], [[:resolve, 'bar']]], node)
  end
end
