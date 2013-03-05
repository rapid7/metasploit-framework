direc = File.dirname(__FILE__)

require 'rubygems'
require 'bacon'
require "#{direc}/../lib/method_source"
require "#{direc}/test_helper"

describe MethodSource do

  describe "source_location (testing 1.8 implementation)" do
    it 'should return correct source_location for a method' do
      method(:hello).source_location.first.should =~ /test_helper/
    end

    it 'should not raise for immediate instance methods' do
      [Symbol, Fixnum, TrueClass, FalseClass, NilClass].each do |immediate_class|
        lambda { immediate_class.instance_method(:to_s).source_location }.should.not.raise
      end
    end

    it 'should not raise for immediate methods' do
      [:a, 1, true, false, nil].each do |immediate|
        lambda { immediate.method(:to_s).source_location }.should.not.raise
      end
    end
  end

  before do
    @hello_module_source = "  def hello; :hello_module; end\n"
    @hello_singleton_source = "def $o.hello; :hello_singleton; end\n"
    @hello_source = "def hello; :hello; end\n"
    @hello_comment = "# A comment for hello\n# It spans two lines and is indented by 2 spaces\n"
    @lambda_comment = "# This is a comment for MyLambda\n"
    @lambda_source = "MyLambda = lambda { :lambda }\n"
    @proc_source = "MyProc = Proc.new { :proc }\n"
  end

  it 'should define methods on Method and UnboundMethod and Proc' do
    Method.method_defined?(:source).should == true
    UnboundMethod.method_defined?(:source).should == true
    Proc.method_defined?(:source).should == true
  end

  describe "Methods" do
    it 'should return source for method' do
      method(:hello).source.should == @hello_source
    end

    it 'should return source for a method defined in a module' do
      M.instance_method(:hello).source.should == @hello_module_source
    end

    it 'should return source for a singleton method as an instance method' do
      class << $o; self; end.instance_method(:hello).source.should == @hello_singleton_source
    end

    it 'should return source for a singleton method' do
      $o.method(:hello).source.should == @hello_singleton_source
    end


    it 'should return a comment for method' do
      method(:hello).comment.should == @hello_comment
    end


    if !is_rbx?
      it 'should raise for C methods' do
        lambda { method(:puts).source }.should.raise RuntimeError
      end
    end
  end

  # if RUBY_VERSION =~ /1.9/ || is_rbx?
  describe "Lambdas and Procs" do
    it 'should return source for proc' do
      MyProc.source.should == @proc_source
    end

    it 'should return an empty string if there is no comment' do
      MyProc.comment.should == ''
    end

    it 'should return source for lambda' do
      MyLambda.source.should == @lambda_source
    end

    it 'should return comment for lambda' do
      MyLambda.comment.should == @lambda_comment
    end
  end
  # end
  describe "Comment tests" do
    before do
      @comment1 = "# a\n# b\n"
      @comment2 = "# a\n# b\n"
      @comment3 = "# a\n#\n# b\n"
      @comment4 = "# a\n# b\n"
      @comment5 = "# a\n# b\n# c\n# d\n"
    end

    it "should correctly extract multi-line comments" do
      method(:comment_test1).comment.should == @comment1
    end

    it "should correctly strip leading whitespace before comments" do
      method(:comment_test2).comment.should == @comment2
    end

    it "should keep empty comment lines" do
      method(:comment_test3).comment.should == @comment3
    end

    it "should ignore blank lines between comments" do
      method(:comment_test4).comment.should == @comment4
    end

    it "should align all comments to same indent level" do
      method(:comment_test5).comment.should == @comment5
    end
  end
end
