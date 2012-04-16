require 'spec_helper'

module CharacterClassSpec
  class Foo < Treetop::Runtime::SyntaxNode
  end

  describe "a character class followed by a node class declaration and a block" do

    testing_expression "[A-Z] <CharacterClassSpec::Foo> { def a_method; end }"

    it "matches single characters within that range, returning instances of the declared node class that respond to the method defined in the inline module" do
      result = parse('A')
      result.should be_an_instance_of(Foo)
      result.should respond_to(:a_method)
      result = parse('N')
      result.should be_an_instance_of(Foo)
      result.should respond_to(:a_method)
      result = parse('Z')
      result.should be_an_instance_of(Foo)
      result.should respond_to(:a_method)
    end

    it "does not match single characters outside of that range" do
      parse('8').should be_nil
      parse('a').should be_nil
    end

    it "matches a single character within that range at index 1" do
      parse(' A', :index => 1).should_not be_nil
    end

    it "fails to match a single character out of that range at index 1" do
      parse(' 1', :index => 1).should be_nil
    end
  end

  module ModFoo
  end

  describe "a character class followed by a node module declaration and a block" do

    testing_expression "[A-Z] <CharacterClassSpec::ModFoo> { def a_method; end }"

    it "matches single characters within that range, returning instances of SyntaxNode extended by the specified module" do
      result = parse('A')
      result.should be_an_instance_of(Treetop::Runtime::SyntaxNode)
      result.should be_a_kind_of(ModFoo)
      result.should respond_to(:a_method)
      result = parse('N')
      result.should be_an_instance_of(Treetop::Runtime::SyntaxNode)
      result.should be_a_kind_of(ModFoo)
      result.should respond_to(:a_method)
      result = parse('Z')
      result.should be_an_instance_of(Treetop::Runtime::SyntaxNode)
      result.should be_a_kind_of(ModFoo)
      result.should respond_to(:a_method)
    end

    it "does not match single characters outside of that range" do
      parse('8').should be_nil
      parse('a').should be_nil
    end

    it "matches a single character within that range at index 1" do
      parse(' A', :index => 1).should_not be_nil
    end

    it "fails to match a single character out of that range at index 1" do
      parse(' 1', :index => 1).should be_nil
    end
  end
  
  describe "a character class followed by a node class declaration and a block" do

    testing_expression "[A-Z] <CharacterClassSpec::Foo>"
    
    it "actively generates nodes for the character when it is the primary node" do
      result = parse('A')
      result.should be_a(Treetop::Runtime::SyntaxNode)
      result.elements.should be_nil
    end
    
  end

  describe "A character class containing quotes" do
    testing_expression "[\"']"

    it "matches a quote" do
      parse("'").should_not be_nil
    end

    it "matches a double-quote" do
      parse('"').should_not be_nil
    end
  end

  describe "A character class containing a special character" do
    testing_expression "[\t]"
    it "matches that character only" do
      parse("\t").should_not be_nil
      parse('t').should be_nil
    end
  end

  describe "A character class containing an escaped backslash" do
    slash = "\\"  # Make it explicit that there are *two* backslashes here
    testing_expression "[#{slash}#{slash}]"
    it "matches a backslash only" do
      parse("\\").should_not be_nil
      parse('t').should be_nil
    end
  end

  describe "A character class containing a hex escape" do
    slash = "\\"
    testing_expression "[#{slash}x41]"
    it "matches that character only" do
      parse('A').should_not be_nil
      parse('\\').should be_nil
      parse('x').should be_nil
      parse('4').should be_nil
      parse('1').should be_nil
    end
  end

  describe "A character class containing an octal escape" do
    slash = "\\"
    testing_expression "[#{slash}101]"
    it "matches that character only" do
      parse('A').should_not be_nil
      parse('\\').should be_nil
      parse('1').should be_nil
      parse('0').should be_nil
    end
  end

  describe "A character class containing a \\c control-char escape" do
    slash = "\\"
    testing_expression "[#{slash}cC]"
    it "matches that character only" do
      parse("\003").should_not be_nil
      parse('\\').should be_nil
      parse('c').should be_nil
      parse('C').should be_nil
    end
  end

  describe "A character class containing a \\C- control-char escape" do
    slash = "\\"
    testing_expression "[#{slash}C-C]"
    it "matches that character only" do
      parse("\003").should_not be_nil
      parse('\\').should be_nil
      parse('C').should be_nil
      parse('-').should be_nil
    end
  end

  if RUBY_VERSION =~ /\A1\.8\./
    describe "A character class containing a \\M- meta-char escape" do
      slash = "\\"
      testing_expression "[#{slash}M- ]"
      it "matches that character only" do
        parse("\240").should_not be_nil
        parse('\\').should be_nil
        parse('M').should be_nil
        parse('-').should be_nil
        parse(' ').should be_nil
      end
    end
  end

  describe "A character class containing an escaped non-special character" do
    slash = "\\"
    testing_expression "[#{slash}y]"
    it "matches that character only" do
      parse("y").should_not be_nil
      parse('\\').should be_nil
    end
  end

  describe "A character class containing an \#{...} insertion" do
    testing_expression "[\#{raise 'error'}]"
    it "doesn't evaluate the insertion" do
      x = true
      lambda{
	x = parse("y")
      }.should_not raise_error
      x.should be_nil
      parse('#').should_not be_nil
      parse("'").should_not be_nil
      parse("0").should be_nil
    end
  end
  
  describe "a character class" do
    testing_expression "[A-Z]"
    it "actively generates a node for the character because it is the primary node" do
      result = parse('A')
      result.should be_a(Treetop::Runtime::SyntaxNode)
      result.elements.should be_nil
    end
  end
  
  describe "a character class mixed with other expressions" do
    testing_expression '[A-Z] "a"'
    it "lazily instantiates a node for the character" do
      result = parse('Aa')
      result.instance_variable_get("@elements").should include(true)
      result.elements.should_not include(true)
      result.elements.size.should == 2
    end
  end
  
  describe "a character class with a node class declaration mixed with other expressions" do
    testing_expression '([A-Z] <CharacterClassSpec::Foo>) "a"'
    it "actively generates a node for the character because it has a node class declared" do
      result = parse('Aa')
      result.instance_variable_get("@elements").should_not include(true)
      result.elements.should_not include(true)
      result.elements.size.should == 2
    end
  end
  
  describe "a character class with a node module declaration mixed with other expressions" do
    testing_expression '([A-Z] <CharacterClassSpec::ModFoo>) "a"'
    it "actively generates a node for the character because it has a node module declared" do
      result = parse('Aa')
      result.instance_variable_get("@elements").should_not include(true)
      result.elements.should_not include(true)
      result.elements.size.should == 2
    end
  end
  
  describe "a character class with an inline block mixed with other expressions" do
    testing_expression '([A-Z] { def a_method; end }) "a"'
    it "actively generates a node for the character because it has an inline block" do
      result = parse('Aa')
      result.instance_variable_get("@elements").should_not include(true)
      result.elements.should_not include(true)
      result.elements.size.should == 2
    end
  end
  
  describe "a character class with a label mixed with other expressions" do
    testing_expression 'upper:([A-Z]) "b"'
    it "returns the correct element for the labeled expression" do
      result = parse('Ab')
      result.upper.text_value.should == "A"
      result.elements.size.should == 2
    end
  end
  
  describe "a character class repetition mixed with other expressions" do
    testing_expression '[A-Z]+ "a"'
    it "lazily instantiates a node for the character" do
      result = parse('ABCa')
      result.elements[0].instance_variable_get("@elements").should include(true)
      result.elements[0].elements.should_not include(true)
      result.elements[0].elements.size.should == 3
      result.elements.size.should == 2
      result.elements.inspect.should == %Q{[SyntaxNode offset=0, "ABC":\n  SyntaxNode offset=0, "A"\n  SyntaxNode offset=1, "B"\n  SyntaxNode offset=2, "C", SyntaxNode offset=3, "a"]}
    end
  end
  
  describe "a character class that gets cached because of a choice" do
    testing_expression "[A-Z] 'a' / [A-Z]"
    
    it "generates a node for the lazily-instantiated character when it is the primary node" do
      result = parse('A')
      result.should be_a(Treetop::Runtime::SyntaxNode)
      result.elements.should be_nil
    end
  end

end
