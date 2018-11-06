require File.dirname(__FILE__) + "/helper"

class SwitchNodeTest < NodeTestCase
  def test_to_sexp
    clause = CaseClauseNode.new(  ResolveNode.new('foo'),
                                SourceElementsNode.new([ResolveNode.new('bar')]))
    block = CaseBlockNode.new([clause])
    node = SwitchNode.new(ResolveNode.new('o'), block)
    assert_sexp([:switch, [:resolve, 'o'],[:case_block, [[:case, [:resolve, 'foo'], [[:resolve, 'bar']]]]]],
                node)
  end
end
