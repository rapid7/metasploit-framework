require 'spec_helper'
require 'tmpdir'

describe Compiler::GrammarCompiler do
  attr_reader :compiler, :source_path_with_treetop_extension, :source_path_with_tt_extension, :target_path, :alternate_target_path
  before do
    @compiler = Compiler::GrammarCompiler.new

    dir = File.dirname(__FILE__)
    @tmpdir = Dir.tmpdir

    @source_path_with_treetop_extension = "#{dir}/test_grammar.treetop"
    @source_path_with_do = "#{dir}/test_grammar_do.treetop"
    @source_path_with_tt_extension = "#{dir}/test_grammar.tt"
    @target_path = "#{@tmpdir}/test_grammar.rb"
    @target_path_with_do = "#{@tmpdir}/test_grammar_do.rb"
    @alternate_target_path = "#{@tmpdir}/test_grammar_alt.rb"
    delete_target_files
  end

  after do
    delete_target_files
    Object.class_eval do
      remove_const(:Test) if const_defined?(:Test)
    end
  end

  specify "compilation of a single file to a default file name" do
    src_copy = "#{@tmpdir}/test_grammar.treetop"
    File.open(source_path_with_treetop_extension) { |f| File.open(src_copy,'w'){|o|o.write(f.read)} }
    File.exists?(target_path).should be_false
    compiler.compile(src_copy)
    File.exists?(target_path).should be_true
    require target_path
    Test::GrammarParser.new.parse('foo').should_not be_nil
  end

  specify "compilation of a single file to an explicit file name" do
    File.exists?(alternate_target_path).should be_false
    compiler.compile(source_path_with_treetop_extension, alternate_target_path)
    File.exists?(alternate_target_path).should be_true
    require alternate_target_path
    Test::GrammarParser.new.parse('foo').should_not be_nil
  end

  specify "compilation of a single file without writing it to an output file" do
    compiler.ruby_source(source_path_with_treetop_extension).should_not be_nil
  end
  
  specify "ruby_source_from_string compiles a grammar stored in string" do
    compiler.ruby_source_from_string(File.read(source_path_with_treetop_extension)).should_not be_nil
  end

  specify "Treetop.load_from_string compiles and evaluates a source grammar stored in string" do
    Treetop.load_from_string File.read(source_path_with_treetop_extension)
    Test::GrammarParser.new.parse('foo').should_not be_nil
  end

  specify "Treetop.load compiles and evaluates a source grammar with a .treetop extension" do    
    Treetop.load source_path_with_treetop_extension
    Test::GrammarParser.new.parse('foo').should_not be_nil
  end
  
  specify "Treetop.load compiles and evaluates a source grammar with a .tt extension" do
    path_without_extension = source_path_with_tt_extension
    Treetop.load path_without_extension
    Test::GrammarParser.new.parse('foo').should_not be_nil
  end


  specify "Treetop.load compiles and evaluates source grammar with no extension" do
    path_without_extension = source_path_with_treetop_extension.gsub(/\.treetop\Z/, '')
    Treetop.load path_without_extension
    Test::GrammarParser.new.parse('foo').should_not be_nil
  end

  specify "grammars with 'do' compile" do
    src_copy = "#{@tmpdir}/test_grammar_do.treetop"
    File.open(@source_path_with_do) { |f| File.open(src_copy,'w'){|o|o.write(f.read)} }
    compiler.compile(src_copy)
    require @target_path_with_do
    Test::GrammarParser.new.parse('foo').should_not be_nil
  end

  def delete_target_files
    File.delete(target_path) if File.exists?(target_path)
    File.delete(@target_path_with_do) if File.exists?(@target_path_with_do)
    File.delete(alternate_target_path) if File.exists?(alternate_target_path)
  end
end

