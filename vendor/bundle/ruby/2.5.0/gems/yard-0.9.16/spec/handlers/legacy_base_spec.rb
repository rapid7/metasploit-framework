# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

include Parser::Ruby::Legacy

RSpec.describe YARD::Handlers::Ruby::Legacy::Base, "#tokval" do
  before { @handler = Handlers::Ruby::Legacy::Base.new(nil, nil) }

  def tokval(code, *types)
    @handler.send(:tokval, TokenList.new(code).first, *types)
  end

  it "returns the String's value without quotes" do
    expect(tokval('"hello"')).to eq "hello"
  end

  it "does not allow interpolated strings with TkSTRING" do
    expect(tokval('"#{c}"', RubyToken::TkSTRING)).to be nil
  end

  it "returns a Symbol's value as a String (as if it was done via :name.to_sym)" do
    expect(tokval(':sym')).to eq :sym
  end

  it "returns nil for any non accepted type" do
    expect(tokval('identifier')).to be nil
    expect(tokval(':sym', RubyToken::TkId)).to be nil
  end

  it "accepts TkVal tokens by default" do
    expect(tokval('2.5')).to eq 2.5
    expect(tokval(':sym')).to eq :sym
  end

  it "accepts any ID type if TkId is set" do
    expect(tokval('variable', RubyToken::TkId)).to eq "variable"
    expect(tokval('CONSTANT', RubyToken::TkId)).to eq "CONSTANT"
  end

  it "allows extra token types to be accepted" do
    expect(tokval('2.5', RubyToken::TkFLOAT)).to eq 2.5
    expect(tokval('2', RubyToken::TkFLOAT)).to be nil
    expect(tokval(':symbol', RubyToken::TkFLOAT)).to be nil
  end

  it "allows :string for any string type" do
    expect(tokval('"hello"', :string)).to eq "hello"
    expect(tokval('"#{c}"', :string)).to eq '#{c}'
  end

  it "does not include interpolated strings when using :attr" do
    expect(tokval('"#{c}"', :attr)).to be nil
  end

  it "allows any number type with :number" do
    expect(tokval('2.5', :number)).to eq 2.5
    expect(tokval('2', :number)).to eq 2
  end

  it "allows method names with :identifier" do
    expect(tokval('methodname?', :identifier)).to eq "methodname?"
  end

  # it "obeys documentation expectations" do docspec end
end

RSpec.describe YARD::Handlers::Base, "#tokval_list" do
  before { @handler = Handlers::Ruby::Legacy::Base.new(nil, nil) }

  def tokval_list(code, *types)
    @handler.send(:tokval_list, TokenList.new(code), *types)
  end

  it "returns the list of tokvalues" do
    expect(tokval_list(":a, :b, \"\#{c}\", 'd'", :attr)).to eq [:a, :b, 'd']
    expect(tokval_list(":a, :b, File.read(\"\#{c}\", ['w']), :d",
      RubyToken::Token)).to eq [:a, :b, 'File.read("#{c}", [\'w\'])', :d]
  end

  it "tries to skip any invalid tokens" do
    expect(tokval_list(":a, :b, \"\#{c}\", :d", :attr)).to eq [:a, :b, :d]
    expect(tokval_list(":a, :b, File.read(\"\#{c}\", 'w', File.open { }), :d", :attr)).to eq [:a, :b, :d]
    expect(tokval_list("CONST1, identifier, File.read(\"\#{c}\", 'w', File.open { }), CONST2",
      RubyToken::TkId)).to eq ['CONST1', 'identifier', 'CONST2']
  end

  it "ignores a token if another invalid token is read before a comma" do
    expect(tokval_list(":a, :b XYZ, :c", RubyToken::TkSYMBOL)).to eq [:a, :c]
  end

  it "stops on most keywords" do
    expect(tokval_list(':a rescue :x == 5', RubyToken::Token)).to eq [:a]
  end

  it "handles ignore parentheses that begin the token list" do
    expect(tokval_list('(:a, :b, :c)', :attr)).to eq [:a, :b, :c]
  end

  it "ends when a closing parenthesis was found" do
    expect(tokval_list(':a, :b, :c), :d', :attr)).to eq [:a, :b, :c]
  end

  it "ignores parentheses around items in a list" do
    expect(tokval_list(':a, (:b), :c, (:d TEST), :e, [:f], :g', :attr)).to eq [:a, :b, :c, :e, :g]
    expect(tokval_list(':a, (((:f)))', :attr)).to eq [:a, :f]
    expect(tokval_list(':a, ([:f]), :c)', RubyToken::Token)).to eq [:a, '[:f]', :c]
  end

  it "does not stop on a true/false/self keyword (cannot handle nil)" do
    expect(tokval_list(':a, true, :b, self, false, :c, nil, File, super, if, XYZ',
      RubyToken::Token)).to eq [:a, true, :b, 'self', false, :c, 'File', 'super']
  end

  it "ignores invalid commas" do
    expect(tokval_list(":a, :b, , :d")).to eq [:a, :b, :d]
  end

  it "returns an empty list if no matches were found" do
    expect(tokval_list('attr_accessor :x')).to eq []
  end

  it "treats {} as a valid value" do
    # FIXME: tokval_list destroys extra spaces surrounding the '=' in
    #        this situation. This is technically a design flaw of the
    #        tokval parser, but this is now the expected behaviour.
    expect(tokval_list("opts = {}", :all)).to eq ["opts={}"]
  end
end
