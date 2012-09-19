# encoding: utf-8
require 'spec_helper'

describe 'text input' do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything

    concat(semantic_form_for(@new_post) do |builder|
      concat(builder.input(:body, :as => :text))
    end)
  end

  it_should_have_input_wrapper_with_class("text")
  it_should_have_input_wrapper_with_class(:input)
  it_should_have_input_wrapper_with_id("post_body_input")
  it_should_have_label_with_text(/Body/)
  it_should_have_label_for("post_body")
  it_should_have_textarea_with_id("post_body")
  it_should_have_textarea_with_name("post[body]")
  it_should_apply_error_logic_for_input_type(:number)

  it 'should use input_html to style inputs' do
    output_buffer.replace ''
    concat(semantic_form_for(@new_post) do |builder|
      concat(builder.input(:title, :as => :text, :input_html => { :class => 'myclass' }))
    end)
    output_buffer.should have_tag("form li textarea.myclass")
  end

  it "should have a cols attribute when :cols is a number in :input_html" do
    output_buffer.replace ''
    concat(semantic_form_for(@new_post) do |builder|
      concat(builder.input(:title, :as => :text, :input_html => { :cols => 42 }))
    end)
    output_buffer.should have_tag("form li textarea[@cols='42']")
  end

  it "should not have a cols attribute when :cols is nil in :input_html" do
    output_buffer.replace ''
    concat(semantic_form_for(@new_post) do |builder|
      concat(builder.input(:title, :as => :text, :input_html => { :cols => nil }))
    end)
    output_buffer.should_not have_tag("form li textarea[@cols]")
  end

  it "should have a rows attribute when :rows is a number in :input_html" do
    output_buffer.replace ''
    concat(semantic_form_for(@new_post) do |builder|
      concat(builder.input(:title, :as => :text, :input_html => { :rows => 42 }))
    end)
    output_buffer.should have_tag("form li textarea[@rows='42']")

  end

  it "should not have a rows attribute when :rows is nil in :input_html" do
    output_buffer.replace ''
    concat(semantic_form_for(@new_post) do |builder|
      concat(builder.input(:title, :as => :text, :input_html => { :rows => nil }))
    end)
    output_buffer.should_not have_tag("form li textarea[@rows]")
  end

  describe "when namespace is provided" do

    before do
      @output_buffer = ''
      mock_everything

      concat(semantic_form_for(@new_post, :namespace => 'context2') do |builder|
        concat(builder.input(:body, :as => :text))
      end)
    end

    it_should_have_input_wrapper_with_id("context2_post_body_input")
    it_should_have_textarea_with_id("context2_post_body")
    it_should_have_label_for("context2_post_body")

  end
  
  describe "when index is provided" do

    before do
      @output_buffer = ''
      mock_everything

      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.fields_for(:author, :index => 3) do |author|
          concat(author.input(:name, :as => :text))
        end)
      end)
    end
    
    it 'should index the id of the wrapper' do
      output_buffer.should have_tag("li#post_author_attributes_3_name_input")
    end
    
    it 'should index the id of the select tag' do
      output_buffer.should have_tag("textarea#post_author_attributes_3_name")
    end
    
    it 'should index the name of the select tag' do
      output_buffer.should have_tag("textarea[@name='post[author_attributes][3][name]']")
    end
    
  end
  
  context "when required" do
    it "should add the required attribute to the input's html options" do
      with_config :use_required_attribute, true do 
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:title, :as => :text, :required => true))
        end)
        output_buffer.should have_tag("textarea[@required]")
      end
    end
  end

  context "when :autofocus is provided in :input_html" do
    before(:each) do
      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.input(:title, :input_html => {:autofocus => true}))
      end)
    end

    it_should_have_input_wrapper_with_class("autofocus")

    it "should add the autofocus attribute to the input's html options" do
      output_buffer.should have_tag("input[@autofocus]")
    end
  end

  context "when :rows is missing in :input_html" do
    before do
      output_buffer.replace ''
    end

    it "should have a rows attribute matching default_text_area_height if numeric" do
      with_config :default_text_area_height, 12 do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:title, :as => :text))
        end)
        output_buffer.should have_tag("form li textarea[@rows='12']")
      end
    end

    it "should not have a rows attribute if default_text_area_height is nil" do
      with_config :default_text_area_height, nil do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:title, :as => :text))
        end)
        output_buffer.should_not have_tag("form li textarea[@rows]")
      end

    end
  end

  context "when :cols is missing in :input_html" do
    before do
      output_buffer.replace ''
    end

    it "should have a cols attribute matching default_text_area_width if numeric" do
      with_config :default_text_area_width, 10 do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:title, :as => :text))
        end)
        output_buffer.should have_tag("form li textarea[@cols='10']")
      end
    end

    it "should not have a cols attribute if default_text_area_width is nil" do
      with_config :default_text_area_width, nil do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:title, :as => :text))
        end)
        output_buffer.should_not have_tag("form li textarea[@cols]")
      end

    end
  end

end

