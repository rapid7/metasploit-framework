# encoding: utf-8
require 'spec_helper'

describe 'check_boxes input' do

  include FormtasticSpecHelper

  describe 'for a has_many association' do
    before do
      @output_buffer = ''
      mock_everything

      concat(semantic_form_for(@fred) do |builder|
        concat(builder.input(:posts, :as => :check_boxes, :value_as_class => true, :required => true))
      end)
    end

    it_should_have_input_wrapper_with_class("check_boxes")
    it_should_have_input_wrapper_with_class(:input)
    it_should_have_input_wrapper_with_id("author_posts_input")
    it_should_have_a_nested_fieldset
    it_should_have_a_nested_fieldset_with_class('choices')
    it_should_have_a_nested_ordered_list_with_class('choices-group')
    it_should_apply_error_logic_for_input_type(:check_boxes)
    it_should_call_find_on_association_class_when_no_collection_is_provided(:check_boxes)
    it_should_use_the_collection_when_provided(:check_boxes, 'input[@type="checkbox"]')

    it 'should generate a legend containing a label with text for the input' do
      output_buffer.should have_tag('form li fieldset legend.label label')
      output_buffer.should have_tag('form li fieldset legend.label label', /Posts/)
    end

    it 'should not link the label within the legend to any input' do
      output_buffer.should_not have_tag('form li fieldset legend label[@for^="author_post_ids_"]')
    end

    it 'should generate an ordered list with an li.choice for each choice' do
      output_buffer.should have_tag('form li fieldset ol')
      output_buffer.should have_tag('form li fieldset ol li.choice input[@type=checkbox]', :count => ::Post.all.size)
    end

    it 'should have one option with a "checked" attribute' do
      output_buffer.should have_tag('form li input[@checked]', :count => 1)
    end

    it 'should not generate hidden inputs with default value blank' do
      output_buffer.should_not have_tag("form li fieldset ol li label input[@type='hidden'][@value='']")
    end

    it 'should not render hidden inputs inside the ol' do
      output_buffer.should_not have_tag("form li fieldset ol li input[@type='hidden']")
    end

    it 'should render one hidden input for each choice outside the ol' do
      output_buffer.should have_tag("form li fieldset > input[@type='hidden']", :count => 1)
    end

    describe "each choice" do
      
      it 'should not give the choice label the .label class' do
        output_buffer.should_not have_tag('li.choice label.label')
      end
      
      it 'should not be marked as required' do
        output_buffer.should_not have_tag('li.choice input[@required]')
      end
      
      it 'should contain a label for the radio input with a nested input and label text' do
        ::Post.all.each do |post|
          output_buffer.should have_tag('form li fieldset ol li label', /#{post.to_label}/)
          output_buffer.should have_tag("form li fieldset ol li label[@for='author_post_ids_#{post.id}']")
        end
      end

      it 'should use values as li.class when value_as_class is true' do
        ::Post.all.each do |post|
          output_buffer.should have_tag("form li fieldset ol li.post_#{post.id} label")
        end
      end
      
      it 'should have a checkbox input but no hidden field for each post' do
        ::Post.all.each do |post|
          output_buffer.should have_tag("form li fieldset ol li label input#author_post_ids_#{post.id}")
          output_buffer.should have_tag("form li fieldset ol li label input[@name='author[post_ids][]']", :count => 1)
        end
      end

      it 'should have a hidden field with an empty array value for the collection to allow clearing of all checkboxes' do
        output_buffer.should have_tag("form li fieldset > input[@type=hidden][@name='author[post_ids][]'][@value='']", :count => 1)
      end

      it 'the hidden field with an empty array value should be followed by the ol' do
        output_buffer.should have_tag("form li fieldset > input[@type=hidden][@name='author[post_ids][]'][@value=''] + ol", :count => 1)
      end

      it 'should not have a hidden field with an empty string value for the collection' do
        output_buffer.should_not have_tag("form li fieldset > input[@type=hidden][@name='author[post_ids]'][@value='']", :count => 1)
      end

      it 'should have a checkbox and a hidden field for each post with :hidden_field => true' do
        output_buffer.replace ''

        concat(semantic_form_for(@fred) do |builder|
          concat(builder.input(:posts, :as => :check_boxes, :hidden_fields => true, :value_as_class => true))
        end)

        ::Post.all.each do |post|
          output_buffer.should have_tag("form li fieldset ol li label input#author_post_ids_#{post.id}")
          output_buffer.should have_tag("form li fieldset ol li label input[@name='author[post_ids][]']", :count => 2)
        end

      end

      it "should mark input as checked if it's the the existing choice" do
        ::Post.all.include?(@fred.posts.first).should be_true
        output_buffer.should have_tag("form li fieldset ol li label input[@checked='checked']")
      end
    end

    describe 'and no object is given' do
      before(:each) do
        output_buffer.replace ''
        concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
          concat(builder.input(:author_id, :as => :check_boxes, :collection => ::Author.all))
        end)
      end

      it 'should generate a fieldset with legend' do
        output_buffer.should have_tag('form li fieldset legend', /Author/)
      end

      it 'shold generate an li tag for each item in the collection' do
        output_buffer.should have_tag('form li fieldset ol li input[@type=checkbox]', :count => ::Author.all.size)
      end

      it 'should generate labels for each item' do
        ::Author.all.each do |author|
          output_buffer.should have_tag('form li fieldset ol li label', /#{author.to_label}/)
          output_buffer.should have_tag("form li fieldset ol li label[@for='project_author_id_#{author.id}']")
        end
      end

      it 'should generate inputs for each item' do
        ::Author.all.each do |author|
          output_buffer.should have_tag("form li fieldset ol li label input#project_author_id_#{author.id}")
          output_buffer.should have_tag("form li fieldset ol li label input[@type='checkbox']")
          output_buffer.should have_tag("form li fieldset ol li label input[@value='#{author.id}']")
          output_buffer.should have_tag("form li fieldset ol li label input[@name='project[author_id][]']")
        end
      end

      it 'should html escape the label string' do
        concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
          concat(builder.input(:author_id, :as => :check_boxes, :collection => [["<b>Item 1</b>", 1], ["<b>Item 2</b>", 2]]))
        end)

        output_buffer.should have_tag('form li fieldset ol li label') do |label|
          label.body.should match /&lt;b&gt;Item [12]&lt;\/b&gt;$/
        end
      end
    end

    describe 'when :hidden_fields is set to false' do
      before do
        @output_buffer = ''
        mock_everything

        concat(semantic_form_for(@fred) do |builder|
          concat(builder.input(:posts, :as => :check_boxes, :value_as_class => true, :hidden_fields => false))
        end)
      end

      it 'should have a checkbox input for each post' do
        ::Post.all.each do |post|
          output_buffer.should have_tag("form li fieldset ol li label input#author_post_ids_#{post.id}")
          output_buffer.should have_tag("form li fieldset ol li label input[@name='author[post_ids][]']", :count => ::Post.all.length)
        end
      end

      it "should mark input as checked if it's the the existing choice" do
        ::Post.all.include?(@fred.posts.first).should be_true
        output_buffer.should have_tag("form li fieldset ol li label input[@checked='checked']")
      end

      it 'should not generate empty hidden inputs' do
        output_buffer.should_not have_tag("form li fieldset ol li label input[@type='hidden'][@value='']", :count => ::Post.all.length)
      end
    end

    describe 'when :disabled is set' do
      before do
        @output_buffer = ''
      end

      describe "no disabled items" do
        before do
          @new_post.stub!(:author_ids).and_return(nil)

          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.input(:authors, :as => :check_boxes, :disabled => nil))
          end)
        end

        it 'should not have any disabled item(s)' do
          output_buffer.should_not have_tag("form li fieldset ol li label input[@disabled='disabled']")
        end
      end

      describe "single disabled item" do
        before do
          @new_post.stub!(:author_ids).and_return(nil)

          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.input(:authors, :as => :check_boxes, :disabled => @fred.id))
          end)
        end

        it "should have one item disabled; the specified one" do
          output_buffer.should have_tag("form li fieldset ol li label input[@disabled='disabled']", :count => 1)
          output_buffer.should have_tag("form li fieldset ol li label[@for='post_author_ids_#{@fred.id}']", /fred/i)
          output_buffer.should have_tag("form li fieldset ol li label input[@disabled='disabled'][@value='#{@fred.id}']")
        end
      end

      describe "multiple disabled items" do
        before do
          @new_post.stub!(:author_ids).and_return(nil)

          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.input(:authors, :as => :check_boxes, :disabled => [@bob.id, @fred.id]))
          end)
        end

        it "should have multiple items disabled; the specified ones" do
          output_buffer.should have_tag("form li fieldset ol li label input[@disabled='disabled']", :count => 2)
          output_buffer.should have_tag("form li fieldset ol li label[@for='post_author_ids_#{@bob.id}']", /bob/i)
          output_buffer.should have_tag("form li fieldset ol li label input[@disabled='disabled'][@value='#{@bob.id}']")
          output_buffer.should have_tag("form li fieldset ol li label[@for='post_author_ids_#{@fred.id}']", /fred/i)
          output_buffer.should have_tag("form li fieldset ol li label input[@disabled='disabled'][@value='#{@fred.id}']")
        end
      end

    end

    describe "with i18n of the legend label" do

      before do
        ::I18n.backend.store_translations :en, :formtastic => { :labels => { :post => { :authors => "Translated!" }}}
        with_config :i18n_lookups_by_default, true do
          @new_post.stub!(:author_ids).and_return(nil)
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.input(:authors, :as => :check_boxes))
          end)
        end
      end

      after do
        ::I18n.backend.reload!
      end

      it "should do foo" do
        output_buffer.should have_tag("legend.label label", /Translated/)
      end

    end

    describe "when :label option is set" do
      before do
        @new_post.stub!(:author_ids).and_return(nil)
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:authors, :as => :check_boxes, :label => 'The authors'))
        end)
      end

      it "should output the correct label title" do
        output_buffer.should have_tag("legend.label label", /The authors/)
      end
    end

    describe "when :label option is false" do
      before do
        @output_buffer = ''
        @new_post.stub!(:author_ids).and_return(nil)
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:authors, :as => :check_boxes, :label => false))
        end)
      end

      it "should not output the legend" do
        output_buffer.should_not have_tag("legend.label")
      end
      
      it "should not cause escaped HTML" do
        output_buffer.should_not include("&gt;")
      end
      
    end

    describe "when :required option is true" do
      before do
        @new_post.stub!(:author_ids).and_return(nil)
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:authors, :as => :check_boxes, :required => true))
        end)
      end

      it "should output the correct label title" do
        output_buffer.should have_tag("legend.label label abbr")
      end
    end

  end

  describe 'for a has_and_belongs_to_many association' do

    before do
      @output_buffer = ''
      mock_everything

      concat(semantic_form_for(@freds_post) do |builder|
        concat(builder.input(:authors, :as => :check_boxes))
      end)
    end

    it 'should render checkboxes' do
      # I'm aware these two lines test the same thing
      output_buffer.should have_tag('input[type="checkbox"]', :count => 2)
      output_buffer.should have_tag('input[type="checkbox"]', :count => ::Author.all.size)
    end

    it 'should only select checkboxes that are present in the association' do
      # I'm aware these two lines test the same thing
      output_buffer.should have_tag('input[checked="checked"]', :count => 1)
      output_buffer.should have_tag('input[checked="checked"]', :count => @freds_post.authors.size)
    end

  end

  describe 'for an association when a :collection is provided' do
    describe 'it should use the specified :member_value option' do
      before do
        @output_buffer = ''
        mock_everything
      end

      it 'to set the right input value' do
        item = mock('item')
        item.should_not_receive(:id)
        item.stub!(:custom_value).and_return('custom_value')
        item.should_receive(:custom_value).exactly(3).times
        @new_post.author.should_receive(:custom_value).exactly(1).times
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:author, :as => :check_boxes, :member_value => :custom_value, :collection => [item, item, item]))
        end)
        output_buffer.should have_tag('input[@type=checkbox][@value="custom_value"]', :count => 3)
      end
    end
  end
  
  describe 'when :collection is provided as an array of arrays' do
    before do
      @output_buffer = ''
      mock_everything
      @fred.stub(:genres) { ['fiction', 'biography'] }
      
      concat(semantic_form_for(@fred) do |builder|
        concat(builder.input(:genres, :as => :check_boxes, :collection => [['Fiction', 'fiction'], ['Non-fiction', 'non_fiction'], ['Biography', 'biography']]))
      end)
    end
    
    it 'should check the correct checkboxes' do
      output_buffer.should have_tag("form li fieldset ol li label input[@value='fiction'][@checked='checked']")
      output_buffer.should have_tag("form li fieldset ol li label input[@value='biography'][@checked='checked']")
    end
  end

  describe "when namespace is provided" do

    before do
      @output_buffer = ''
      mock_everything

      concat(semantic_form_for(@fred, :namespace => "context2") do |builder|
        concat(builder.input(:posts, :as => :check_boxes))
      end)
    end
    
    it "should have a label for #context2_author_post_ids_19" do
      output_buffer.should have_tag("form li label[@for='context2_author_post_ids_19']")
    end

    it_should_have_input_with_id('context2_author_post_ids_19')
    it_should_have_input_wrapper_with_id("context2_author_posts_input")
  end
  
  describe "when index is provided" do

    before do
      @output_buffer = ''
      mock_everything

      concat(semantic_form_for(@fred) do |builder|
        concat(builder.fields_for(@fred.posts.first, :index => 3) do |author|
          concat(author.input(:authors, :as => :check_boxes))
        end)
      end)
    end
    
    it 'should index the id of the wrapper' do
      output_buffer.should have_tag("li#author_post_3_authors_input")
    end
    
    it 'should index the id of the input tag' do
      output_buffer.should have_tag("input#author_post_3_author_ids_42")
    end

    it 'should index the name of the checkbox input' do
      output_buffer.should have_tag("input[@type='checkbox'][@name='author[post][3][author_ids][]']")
    end
    
  end
  

  describe "when collection is an array" do
    before do
      @output_buffer = ''
      @_collection = [["First", 1], ["Second", 2]]
      mock_everything

      concat(semantic_form_for(@fred) do |builder|
        concat(builder.input(:posts, :as => :check_boxes, :collection => @_collection))
      end)
    end

    it "should use array items for labels and values" do
      @_collection.each do |post|
        output_buffer.should have_tag('form li fieldset ol li label', /#{post.first}/)
        output_buffer.should have_tag("form li fieldset ol li label[@for='author_post_ids_#{post.last}']")
      end
    end

    it "should not check any items" do
      output_buffer.should have_tag('form li input[@checked]', :count => 0)
    end    
  end
  
end

