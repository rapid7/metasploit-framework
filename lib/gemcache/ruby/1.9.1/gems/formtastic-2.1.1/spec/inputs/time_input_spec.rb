# encoding: utf-8
require 'spec_helper'

describe 'time input' do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything
  end

  describe "general" do
    before do
      ::I18n.backend.reload!
      output_buffer.replace ''
    end

    describe "with :ignore_date => true" do
      before do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:publish_at, :as => :time, :ignore_date => true))
        end)
      end

      it 'should not have hidden inputs for day, month and year' do
        output_buffer.should_not have_tag('input#post_publish_at_1i')
        output_buffer.should_not have_tag('input#post_publish_at_2i')
        output_buffer.should_not have_tag('input#post_publish_at_3i')
      end

      it 'should have an input for hour and minute' do
        output_buffer.should have_tag('select#post_publish_at_4i')
        output_buffer.should have_tag('select#post_publish_at_5i')
      end

    end
    
    describe "with :ignore_date => false" do
      before do
        @new_post.stub(:publish_at).and_return(Time.parse('2010-11-07'))
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:publish_at, :as => :time, :ignore_date => false))
        end)
      end

      it 'should have a hidden input for day, month and year' do
        output_buffer.should have_tag('input#post_publish_at_1i')
        output_buffer.should have_tag('input#post_publish_at_2i')
        output_buffer.should have_tag('input#post_publish_at_3i')
        output_buffer.should have_tag('input#post_publish_at_1i[@value="2010"]')
        output_buffer.should have_tag('input#post_publish_at_2i[@value="11"]')
        output_buffer.should have_tag('input#post_publish_at_3i[@value="7"]')
      end

      it 'should have an select for hour and minute' do
        output_buffer.should have_tag('select#post_publish_at_4i')
        output_buffer.should have_tag('select#post_publish_at_5i')
      end

      it 'should associate the legend label with the hour select' do
        output_buffer.should have_tag('form li.time fieldset legend.label label[@for="post_publish_at_4i"]')
      end

    end

    describe "with :ignore_date => false and no initial Time" do
      before do
        @new_post.stub(:publish_at)
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:publish_at, :as => :time, :ignore_date => false))
        end)
      end

      it 'should have a hidden input for day, month and year' do
        output_buffer.should have_tag('input#post_publish_at_1i')
        output_buffer.should have_tag('input#post_publish_at_2i')
        output_buffer.should have_tag('input#post_publish_at_3i')
      end

      it 'should not have values in hidden inputs for day, month and year' do
        output_buffer.should have_tag('input#post_publish_at_1i[@value=""]')
        output_buffer.should have_tag('input#post_publish_at_2i[@value=""]')
        output_buffer.should have_tag('input#post_publish_at_3i[@value=""]')
      end

      it 'should have an select for hour and minute' do
        output_buffer.should have_tag('select#post_publish_at_4i')
        output_buffer.should have_tag('select#post_publish_at_5i')
      end

    end

    describe "without seconds" do
      before do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:publish_at, :as => :time))
        end)
      end

      it_should_have_input_wrapper_with_class("time")
      it_should_have_input_wrapper_with_class(:input)
      it_should_have_input_wrapper_with_id("post_publish_at_input")
      it_should_have_a_nested_fieldset
      it_should_have_a_nested_fieldset_with_class('fragments')
      it_should_have_a_nested_ordered_list_with_class('fragments-group')
      it_should_apply_error_logic_for_input_type(:time)

      it 'should have a legend and label with the label text inside the fieldset' do
        output_buffer.should have_tag('form li.time fieldset legend.label label', /Publish at/)
      end

      it 'should associate the legend label with the first select' do
        output_buffer.should have_tag('form li.time fieldset legend.label label[@for="post_publish_at_4i"]')
      end

      it 'should have an ordered list of two items inside the fieldset' do
        output_buffer.should have_tag('form li.time fieldset ol.fragments-group')
        output_buffer.should have_tag('form li.time fieldset ol li.fragment', :count => 2)
      end

      it 'should have five labels for hour and minute' do
        output_buffer.should have_tag('form li.time fieldset ol li label', :count => 2)
        output_buffer.should have_tag('form li.time fieldset ol li label', /hour/i)
        output_buffer.should have_tag('form li.time fieldset ol li label', /minute/i)
      end

      it 'should have two selects for hour and minute' do
        output_buffer.should have_tag('form li.time fieldset ol li', :count => 2)
      end
    end

    describe "with seconds" do
      before do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:publish_at, :as => :time, :include_seconds => true))
        end)
      end

      it 'should have five labels for hour and minute' do
        output_buffer.should have_tag('form li.time fieldset ol li label', :count => 3)
        output_buffer.should have_tag('form li.time fieldset ol li label', /hour/i)
        output_buffer.should have_tag('form li.time fieldset ol li label', /minute/i)
        output_buffer.should have_tag('form li.time fieldset ol li label', /second/i)
      end

      it 'should have three selects for hour, minute and seconds' do
        output_buffer.should have_tag('form li.time fieldset ol li', :count => 3)
      end

      it 'should generate a sanitized label and matching ids for attribute' do
        4.upto(6) do |i|
          output_buffer.should have_tag("form li fieldset ol li label[@for='post_publish_at_#{i}i']")
          output_buffer.should have_tag("form li fieldset ol li #post_publish_at_#{i}i")
        end
      end
    end
  end

  describe ':labels option' do
    fields = [:hour, :minute, :second]
    fields.each do |field|
      it "should replace the #{field} label with the specified text if :labels[:#{field}] is set" do
        output_buffer.replace ''
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:created_at, :as => :time, :include_seconds => true, :labels => { field => "another #{field} label" }))
        end)
        output_buffer.should have_tag('form li.time fieldset ol li label', :count => fields.length)
        fields.each do |f|
          output_buffer.should have_tag('form li.time fieldset ol li label', f == field ? /another #{f} label/i : /#{f}/i)
        end
      end

      it "should not display the label for the #{field} field when :labels[:#{field}] is blank" do
        output_buffer.replace ''
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:created_at, :as => :time, :include_seconds => true, :labels => { field => "" }))
        end)
        output_buffer.should have_tag('form li.time fieldset ol li label', :count => fields.length-1)
        fields.each do |f|
          output_buffer.should have_tag('form li.time fieldset ol li label', /#{f}/i) unless field == f
        end
      end
      
      it "should not render the label when :labels[:#{field}] is false" do 
        output_buffer.replace ''
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:created_at, :as => :time, :include_seconds => true, :labels => { field => false }))
        end)
        output_buffer.should have_tag('form li.time fieldset ol li label', :count => fields.length-1)
        fields.each do |f|
          output_buffer.should have_tag('form li.time fieldset ol li label', /#{f}/i) unless field == f
        end
      end
      
      it "should not render unsafe HTML when :labels[:#{field}] is false" do 
        output_buffer.replace ''
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:created_at, :as => :time, :include_seconds => true, :labels => { field => false }))
        end)
        output_buffer.should_not include("&gt;")
      end
      
    end
  end

  describe ':namespace option' do
    before do
      concat(semantic_form_for(@new_post, :namespace => 'form2') do |builder|
        concat(builder.input(:publish_at, :as => :time))
      end)
    end

    it 'should have a tag matching the namespace' do
      output_buffer.should have_tag('#form2_post_publish_at_input')
      output_buffer.should have_tag('#form2_post_publish_at_4i')
      output_buffer.should have_tag('#form2_post_publish_at_5i')
    end
  end
  
  describe "when required" do
    it "should add the required attribute to the input's html options" do
      with_config :use_required_attribute, true do 
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:title, :as => :time, :required => true))
        end)
        output_buffer.should have_tag("select[@required]", :count => 2)
      end
    end
  end
  
  describe "when index is provided" do

    before do
      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.fields_for(:author, :index => 3) do |author|
          concat(author.input(:created_at, :as => :time))
        end)
      end)
    end

    it 'should index the id of the wrapper' do
      output_buffer.should have_tag("li#post_author_attributes_3_created_at_input")
    end

    it 'should index the id of the select tag' do
      output_buffer.should have_tag("input#post_author_attributes_3_created_at_1i")
      output_buffer.should have_tag("input#post_author_attributes_3_created_at_2i")
      output_buffer.should have_tag("input#post_author_attributes_3_created_at_3i")
      output_buffer.should have_tag("select#post_author_attributes_3_created_at_4i")
      output_buffer.should have_tag("select#post_author_attributes_3_created_at_5i")
    end

    it 'should index the name of the select tag' do
      output_buffer.should have_tag("input[@name='post[author_attributes][3][created_at(1i)]']")
      output_buffer.should have_tag("input[@name='post[author_attributes][3][created_at(2i)]']")
      output_buffer.should have_tag("input[@name='post[author_attributes][3][created_at(3i)]']")
      output_buffer.should have_tag("select[@name='post[author_attributes][3][created_at(4i)]']")
      output_buffer.should have_tag("select[@name='post[author_attributes][3][created_at(5i)]']")
    end

  end
  
end



