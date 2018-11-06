require File.dirname(__FILE__) + "/helper"

class CaseBlockNodeTest < NodeTestCase
  def test_to_sexp
    clause = CaseClauseNode.new(  ResolveNode.new('foo'),
                                SourceElementsNode.new([ResolveNode.new('bar')]))
    node = CaseBlockNode.new([clause])
    assert_sexp([:case_block, [[:case, [:resolve, 'foo'], [[:resolve, 'bar']]]]],
                node)
  end
end
