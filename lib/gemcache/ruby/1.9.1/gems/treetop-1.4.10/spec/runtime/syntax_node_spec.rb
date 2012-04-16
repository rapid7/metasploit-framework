require 'spec_helper'

module SyntaxNodeSpec
  describe "A new terminal syntax node" do
    attr_reader :node

    before do
      @node = Runtime::SyntaxNode.new("input", 0...3)
    end
  
    it "reports itself as terminal" do
      node.should be_terminal
      node.should_not be_nonterminal
    end
  
    it "has a text value based on the input and the interval" do
      node.text_value.should == "inp"
    end
  
    it "has itself as its only element" do
      node.elements.should be_nil
    end
  end

  describe "A new nonterminal syntax node" do
    attr_reader :node

    before do
      @elements = [Runtime::SyntaxNode.new('input', 0...3)]
      @node = Runtime::SyntaxNode.new('input', 0...3, @elements)
    end

    it "reports itself as nonterminal" do
      node.should be_nonterminal
      node.should_not be_terminal
    end
  
    it "has a text value based on the input and the interval" do
      node.text_value.should == "inp"
    end
  
    it "has the elements with which it was instantiated" do
      node.elements.should == @elements
    end

    it "sets itself as the parent of its elements" do
      node.elements.each do |element|
        element.parent.should == node
      end
    end
  end
  
  describe "A new nonterminal syntax node with all children lazily instantiated" do
    attr_reader :node
    
    it "should lazily instantiate its child nodes" do
      @node = Runtime::SyntaxNode.new('input', 0...3, [true, true, true])
      node.elements.size.should == 3
      node.elements.first.interval.should == (0...1)
      node.elements.first.parent.should == node
    end
    
    it "should lazily replace stand-in child nodes around real ones" do
      @input = "input"
      child1 = Runtime::SyntaxNode.new(@input, 1...2)
      child2 = Runtime::SyntaxNode.new(@input, 3...4)
      @node = Runtime::SyntaxNode.new(@input, 0...5, [true, child1, true, child2, true])
      node.elements.size.should == 5
      
      node.elements[0].interval.should == (0...1)
      node.elements[0].parent.should == node
      0.upto(4) do |index|
        node.elements[index].text_value.should == @input[index, 1]
      end
    end
  end
end
