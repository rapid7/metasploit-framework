# frozen_string_literal: true
require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

RSpec.describe "YARD::Handlers::Ruby::#{LEGACY_PARSER ? "Legacy::" : ""}ClassHandler" do
  before(:all) { parse_file :class_handler_001, __FILE__ }

  it "parses a class block with docstring" do
    expect(P("A").docstring).to eq "Docstring"
  end

  it "handles complex class names" do
    expect(P("A::B::C")).not_to eq nil
  end

  it "handles the subclassing syntax" do
    expect(P("A::B::C").superclass).to eq P(:String)
    expect(P("A::X").superclass).to eq Registry.at("A::B::C")
  end

  it "interprets class << self as a class level block" do
    expect(P("A.classmethod1")).not_to eq nil
  end

  it "interprets class << ClassName as a class level block in ClassName's namespace" do
    expect(P("A::B::C.Hello")).to be_instance_of(CodeObjects::MethodObject)
  end

  it "makes visibility public when parsing a block" do
    expect(P("A::B::C#method1").visibility).to eq :public
  end

  it "sets superclass type to :class if it is a Proxy" do
    expect(P("A::B::C").superclass.type).to eq :class
  end

  it "looks for a superclass before creating the class if it shares the same name" do
    expect(P('B::A').superclass).to eq P('A')
  end

  it "handles class definitions in the form ::ClassName" do
    expect(Registry.at("MyRootClass")).not_to be nil
  end

  it "handles superclass as a constant-style method (camping style < R /path/)" do
    expect(P('Test1').superclass).to eq P(:R)
    expect(P('Test2').superclass).to eq P(:R)
    expect(P('Test6').superclass).to eq P(:NotDelegateClass)
  end

  it "handles superclass with OStruct.new or Struct.new syntax (superclass should be OStruct/Struct)" do
    expect(P('Test3').superclass).to eq P(:Struct)
    expect(P('Test4').superclass).to eq P(:OStruct)
  end

  it "handles DelegateClass(CLASSNAME) superclass syntax" do
    expect(P('Test5').superclass).to eq P(:Array)
  end

  it "handles a superclass of the same name in the form ::ClassName" do
    expect(P('Q::Logger').superclass).to eq P(:Logger)
    expect(P('Q::Foo').superclass).not_to eq P('Q::Logger')
  end

  ["CallMethod('test')", "VSD^#}}", 'not.aclass', 'self'].each do |klass|
    it "raises an UndocumentableError for invalid class '#{klass}'" do
      with_parser(:ruby18) { undoc_error "class #{klass}; end" }
    end
  end

  ['@@INVALID', 'hi', '$MYCLASS', 'AnotherClass.new'].each do |klass|
    it "raises an UndocumentableError for invalid superclass '#{klass}' but it should create the class." do
      expect(YARD::CodeObjects::ClassObject).to receive(:new).with(Registry.root, 'A')
      with_parser(:ruby18) { undoc_error "class A < #{klass}; end" }
      expect(Registry.at('A').superclass).to eq P(:Object)
    end
  end

  ['not.aclass', 'self', 'AnotherClass.new'].each do |klass|
    it "raises an UndocumentableError if the constant class reference 'class << SomeConstant' does not point to a valid class name" do
      with_parser(:ruby18) do
        undoc_error <<-eof
          CONST = #{klass}
          class << CONST; end
        eof
      end
      expect(Registry.at(klass)).to be nil
    end
  end

  it "documents 'class << SomeConstant' by using SomeConstant's value as a reference to the real class name" do
    expect(Registry.at('String.classmethod')).not_to be nil
  end

  it "allows class << SomeRubyClass to create the class if it does not exist" do
    expect(Registry.at('Symbol.toString')).not_to be nil
  end

  it "documents 'class Exception' without running into superclass issues" do
    Parser::SourceParser.parse_string <<-eof
      class Exception
      end
    eof
    expect(Registry.at(:Exception)).not_to be nil
  end

  it "documents 'class RT < XX::RT' with proper superclass even if XX::RT is a proxy" do
    expect(Registry.at(:RT)).not_to be nil
    expect(Registry.at(:RT).superclass).to eq P('XX::RT')
  end

  it "does not overwrite docstring with an empty one" do
    expect(Registry.at(:Zebra).docstring).to eq "Docstring 2"
  end

  it "turns 'class Const < Struct.new(:sym)' into class Const with attr :sym" do
    obj = Registry.at("Point")
    expect(obj).to be_kind_of(CodeObjects::ClassObject)
    attrs = obj.attributes[:instance]
    [:x, :y, :z].each do |key|
      expect(attrs).to have_key(key)
      expect(attrs[key][:read]).not_to be nil
      expect(attrs[key][:write]).not_to be nil
    end
  end

  it "turns 'class Const < Struct.new('Name', :sym)' into class Const with attr :sym" do
    obj = Registry.at("AnotherPoint")
    expect(obj).to be_kind_of(CodeObjects::ClassObject)
    attrs = obj.attributes[:instance]
    [:a, :b, :c].each do |key|
      expect(attrs).to have_key(key)
      expect(attrs[key][:read]).not_to be nil
      expect(attrs[key][:write]).not_to be nil
    end

    expect(Registry.at("XPoint")).to be nil
  end

  it "creates a Struct::Name class when class Const < Struct.new('Name', :sym) is found" do
    obj = Registry.at("Struct::XPoint")
    expect(obj).not_to be nil
  end

  it "attaches attribtues to the generated Struct::Name class when Struct.new('Name') is used" do
    obj = Registry.at("Struct::XPoint")
    attrs = obj.attributes[:instance]
    [:a, :b, :c].each do |key|
      expect(attrs).to have_key(key)
      expect(attrs[key][:read]).not_to be nil
      expect(attrs[key][:write]).not_to be nil
    end
  end

  it "uses @attr to set attribute descriptions on Struct subclasses" do
    obj = Registry.at("DoccedStruct#input")
    expect(obj.docstring).to eq "the input stream"
  end

  it "uses @attr to set attribute types on Struct subclasses" do
    obj = Registry.at("DoccedStruct#someproc")
    expect(obj).not_to be nil
    expect(obj.tag(:return)).not_to be nil
    expect(obj.tag(:return).types).to eq ["Proc", "#call"]
  end

  it "defaults types unspecified by @attr to Object on Struct subclasses" do
    obj = Registry.at("DoccedStruct#mode")
    expect(obj).not_to be nil
    expect(obj.tag(:return)).not_to be nil
    expect(obj.tag(:return).types).to eq ["Object"]
  end

  it "creates parameters for writers of Struct subclass's attributes" do
    obj = Registry.at("DoccedStruct#input=")
    expect(obj.tags(:param).size).to eq 1
    expect(obj.tag(:param).types).to eq ["IO"]
  end

  ["SemiDoccedStruct", "NotAStruct"].each do |struct|
    describe("Attributes on a " + (struct == "NotAStruct" ? "class" : "struct")) do
      it "defines both readers and writers when @attr is used on Structs" do
        obj = Registry.at(struct)
        attrs = obj.attributes[:instance]
        expect(attrs[:first][:read]).not_to be nil
        expect(attrs[:first][:write]).not_to be nil
      end

      it "defines only a reader when only @attr_reader is used on Structs" do
        obj = Registry.at(struct)
        attrs = obj.attributes[:instance]
        expect(attrs[:second][:read]).not_to be nil
        expect(attrs[:second][:write]).to be nil
      end

      it "defines only a writer when only @attr_writer is used on Structs" do
        obj = Registry.at(struct)
        attrs = obj.attributes[:instance]
        expect(attrs[:third][:read]).to be nil
        expect(attrs[:third][:write]).not_to be nil
      end

      it "defines a reader with correct return types when @attr_reader is used on Structs" do
        obj = Registry.at("#{struct}#second")
        expect(obj.tag(:return).types).to eq ["Fixnum"]
      end

      it "defines a writer with correct parameter types when @attr_writer is used on Structs" do
        obj = Registry.at("#{struct}#third=")
        expect(obj.tag(:param).types).to eq ["Array"]
      end

      it "defines a reader and a writer when both @attr_reader and @attr_writer are used" do
        obj = Registry.at(struct)
        attrs = obj.attributes[:instance]
        expect(attrs[:fourth][:read]).not_to be nil
        expect(attrs[:fourth][:write]).not_to be nil
      end

      it "uses @attr_reader for the getter when both @attr_reader and @attr_writer are given" do
        obj = Registry.at("#{struct}#fourth")
        expect(obj.tag(:return).types).to eq ["#read"]
      end

      it "uses @attr_writer for the setter when both @attr_reader and @attr_writer are given" do
        obj = Registry.at("#{struct}#fourth=")
        expect(obj.tag(:param).types).to eq ["IO"]
      end

      it "extracts text from @attr_reader" do
        expect(Registry.at("#{struct}#fourth").docstring).to eq "returns a proc that reads"
      end

      it "extracts text from @attr_writer" do
        expect(Registry.at("#{struct}#fourth=").docstring).to eq "sets the proc that writes stuff"
      end
    end
  end

  it "inherits from a regular struct" do
    expect(Registry.at('RegularStruct').superclass).to eq P(:Struct)
    expect(Registry.at('RegularStruct2').superclass).to eq P(:Struct)
  end

  it "handles inheritance from 'self'" do
    expect(Registry.at('Outer1::Inner1').superclass).to eq Registry.at('Outer1')
  end
end
