# encoding: utf-8
require 'spec_helper'

describe 'Formtastic::Helpers::FormHelper.builder' do

  include FormtasticSpecHelper

  class MyCustomFormBuilder < Formtastic::FormBuilder
  end
  
  # TODO should be a separate spec for custom inputs
  class Formtastic::Inputs::AwesomeInput
    include Formtastic::Inputs::Base
    def to_html
      "Awesome!"
    end
  end

  before do
    @output_buffer = ''
    mock_everything
  end

  it 'is the Formtastic::FormBuilder by default' do
    Formtastic::Helpers::FormHelper.builder.should == Formtastic::FormBuilder
  end

  it 'can be configured to use your own custom form builder' do
    # Set it to a custom builder class
    Formtastic::Helpers::FormHelper.builder = MyCustomFormBuilder
    Formtastic::Helpers::FormHelper.builder.should == MyCustomFormBuilder

    # Reset it to the default
    Formtastic::Helpers::FormHelper.builder = Formtastic::FormBuilder
    Formtastic::Helpers::FormHelper.builder.should == Formtastic::FormBuilder
  end

  it 'should allow custom settings per form builder subclass' do
    with_config(:all_fields_required_by_default, true) do
      MyCustomFormBuilder.all_fields_required_by_default = false

      MyCustomFormBuilder.all_fields_required_by_default.should be_false
      Formtastic::FormBuilder.all_fields_required_by_default.should be_true
    end
  end

  describe "when using a custom builder" do

    before do
      @new_post.stub!(:title)
      Formtastic::Helpers::FormHelper.builder = MyCustomFormBuilder
    end

    after do
      Formtastic::Helpers::FormHelper.builder = Formtastic::FormBuilder
    end

    describe "semantic_form_for" do

      it "should yield an instance of the custom builder" do
        semantic_form_for(@new_post) do |builder|
          builder.class.should.kind_of?(MyCustomFormBuilder)
        end
      end
      
      # TODO should be a separate spec for custom inputs
      it "should allow me to call my custom input" do
        semantic_form_for(@new_post) do |builder|
          concat(builder.input(:title, :as => :awesome))
        end
      end

      # See: https://github.com/justinfrench/formtastic/issues/657
      it "should not conflict with navigasmic" do
        stub!(:builder).and_return('navigasmic')

        lambda { semantic_form_for(@new_post) }.should_not raise_error(NoMethodError)
      end

    end

    describe "fields_for" do

      it "should yield an instance of the parent form builder" do
        @new_post.stub!(:comment).and_return([@fred])
        @new_post.stub!(:comment_attributes=)
        semantic_form_for(@new_post, :builder => MyCustomFormBuilder) do |builder|
          builder.class.should.kind_of?(MyCustomFormBuilder)
          
          builder.fields_for(:comment) do |nested_builder|
            nested_builder.class.should.kind_of?(MyCustomFormBuilder)
          end
        end
      end

    end

  end

  describe "when using a builder passed to form options" do

    describe "fields_for" do

      it "should yield an instance of the parent form builder" do
        @new_post.stub!(:author_attributes=)
        semantic_form_for(@new_post, :builder => MyCustomFormBuilder) do |builder|
          builder.fields_for(:author) do |nested_builder|
            nested_builder.class.should.kind_of?(MyCustomFormBuilder)
          end
        end
      end

    end

  end
end
