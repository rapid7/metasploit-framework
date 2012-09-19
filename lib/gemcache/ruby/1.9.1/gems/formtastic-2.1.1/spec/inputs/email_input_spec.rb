# encoding: utf-8
require 'spec_helper'

describe 'email input' do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything
  end

  describe "when object is provided" do
    before do
      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.input(:email))
      end)
    end

    it_should_have_input_wrapper_with_class(:email)
    it_should_have_input_wrapper_with_class(:input)
    it_should_have_input_wrapper_with_class(:stringish)
    it_should_have_input_wrapper_with_id("post_email_input")
    it_should_have_label_with_text(/Email/)
    it_should_have_label_for("post_email")
    it_should_have_input_with_id("post_email")
    it_should_have_input_with_type(:email)
    it_should_have_input_with_name("post[email]")

  end

  describe "when namespace is provided" do

    before do
      concat(semantic_form_for(@new_post, :namespace => 'context2') do |builder|
        concat(builder.input(:email))
      end)
    end

    it_should_have_input_wrapper_with_id("context2_post_email_input")
    it_should_have_label_and_input_with_id("context2_post_email")

  end
  
  describe "when index is provided" do

    before do
      @output_buffer = ''
      mock_everything

      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.fields_for(:author, :index => 3) do |author|
          concat(author.input(:name, :as => :email))
        end)
      end)
    end
    
    it 'should index the id of the wrapper' do
      output_buffer.should have_tag("li#post_author_attributes_3_name_input")
    end
    
    it 'should index the id of the select tag' do
      output_buffer.should have_tag("input#post_author_attributes_3_name")
    end
    
    it 'should index the name of the select tag' do
      output_buffer.should have_tag("input[@name='post[author_attributes][3][name]']")
    end
    
  end
  
  
  describe "when required" do
    it "should add the required attribute to the input's html options" do
      with_config :use_required_attribute, true do 
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:title, :as => :email, :required => true))
        end)
        output_buffer.should have_tag("input[@required]")
      end
    end
  end
  
end

