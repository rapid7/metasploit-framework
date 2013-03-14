# encoding: utf-8
require 'spec_helper'

describe 'select input' do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything
  end

  describe 'explicit values' do
    describe 'using an array of values' do
      before do
        @array_with_values = ["Title A", "Title B", "Title C"]
        @array_with_keys_and_values = [["Title D", 1], ["Title E", 2], ["Title F", 3]]
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:title, :as => :select, :collection => @array_with_values))
          concat(builder.input(:title, :as => :select, :collection => @array_with_keys_and_values))
        end)
      end

      it 'should have a option for each key and/or value' do
        @array_with_values.each do |v|
          output_buffer.should have_tag("form li select option[@value='#{v}']", /^#{v}$/)
        end
        @array_with_keys_and_values.each do |v|
          output_buffer.should have_tag("form li select option[@value='#{v.second}']", /^#{v.first}$/)
        end
      end
    end

    describe "using a related model without reflection's options (Mongoid Document)" do
      before do
        @new_post.stub!(:mongoid_reviewer)
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:mongoid_reviewer, :as => :select))
        end)
      end

      it 'should draw select options' do
        output_buffer.should have_tag('form li select')
        output_buffer.should have_tag('form li select#post_reviewer_id')
        output_buffer.should_not have_tag('form li select#post_mongoid_reviewer_id')
      end
    end

    describe 'using a range' do
      before do
        @range_with_values = 1..5
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:title, :as => :select, :collection => @range_with_values))
        end)
      end

      it 'should have an option for each value' do
        @range_with_values.each do |v|
          output_buffer.should have_tag("form li select option[@value='#{v}']", /^#{v}$/)
        end
      end
    end

    describe 'using a string' do
      before do
        @string ="<option value='0'>0</option><option value='1'>1</option>"
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:title, :as => :select, :collection => @string))
        end)
      end

      it 'should render select options using provided HTML string' do
        2.times do |v|
          output_buffer.should have_tag("form li select option[@value='#{v}']", /^#{v}$/)
        end
      end
    end

    describe 'using a nil name' do
      before do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:title, :as => :select, :collection => [], :input_html => {:name => nil}))
        end)
      end

      it_should_have_select_with_name("post[title]")
    end
  end

  describe 'for boolean columns' do
    describe 'default formtastic locale' do
      before do
        # Note: Works, but something like Formtastic.root.join(...) would probably be "safer".
        ::I18n.load_path = [File.join(File.dirname(__FILE__), *%w[.. .. lib locale en.yml])]
        ::I18n.backend.send(:init_translations)

        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:published, :as => :select))
        end)
      end

      after do
        ::I18n.load_path = []
        ::I18n.backend.store_translations :en, {}
      end

      it 'should render a select with at least options: true/false' do
        output_buffer.should have_tag("form li select option[@value='true']", /^Yes$/)
        output_buffer.should have_tag("form li select option[@value='false']", /^No$/)
      end
    end

    describe 'custom locale' do
      before do
        @boolean_select_labels = {:yes => 'Yep', :no => 'Nope'}
        ::I18n.backend.store_translations :en, :formtastic => @boolean_select_labels

        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:published, :as => :select))
        end)
      end

      after do
        ::I18n.backend.store_translations :en, {}
      end

      it 'should render a select with at least options: true/false' do
        output_buffer.should have_tag("form li select option[@value='true']", /#{@boolean_select_labels[:yes]}/)
        output_buffer.should have_tag("form li select option[@value='false']", /#{@boolean_select_labels[:no]}/)
      end
    end
  end

  describe 'for a belongs_to association' do
    before do
      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.input(:author, :as => :select))
        concat(builder.input(:reviewer, :as => :select))
      end)
    end

    it_should_have_input_wrapper_with_class("select")
    it_should_have_input_wrapper_with_class(:input)
    it_should_have_input_wrapper_with_id("post_author_input")
    it_should_have_label_with_text(/Author/)
    it_should_have_label_for('post_author_id')
    it_should_apply_error_logic_for_input_type(:select)
    it_should_call_find_on_association_class_when_no_collection_is_provided(:select)
    it_should_use_the_collection_when_provided(:select, 'option')

    it 'should have a select inside the wrapper' do
      output_buffer.should have_tag('form li select')
      output_buffer.should have_tag('form li select#post_author_id')
      output_buffer.should have_tag('form li select#post_reviewer_id')
    end

    it 'should have a valid name' do
      output_buffer.should have_tag("form li select[@name='post[author_id]']")
      output_buffer.should_not have_tag("form li select[@name='post[author_id][]']")
      output_buffer.should_not have_tag("form li select[@name='post[reviewer_id][]']")
    end

    it 'should not create a multi-select' do
      output_buffer.should_not have_tag('form li select[@multiple]')
    end
    
    it 'should not add a hidden input' do
      output_buffer.should_not have_tag('form li input[@type="hidden"]')
    end

    it 'should create a select without size' do
      output_buffer.should_not have_tag('form li select[@size]')
    end

    it 'should have a blank option' do
      output_buffer.should have_tag("form li select option[@value='']")
    end

    it 'should have a select option for each Author' do
      output_buffer.should have_tag("form li select[@name='post[author_id]'] option", :count => ::Author.all.size + 1)
      ::Author.all.each do |author|
        output_buffer.should have_tag("form li select option[@value='#{author.id}']", /#{author.to_label}/)
      end
    end

    it 'should have one option with a "selected" attribute (bob)' do
      output_buffer.should have_tag("form li select[@name='post[author_id]'] option[@selected]", :count => 1)
    end

    it 'should not singularize the association name' do
      @new_post.stub!(:author_status).and_return(@bob)
      @new_post.stub!(:author_status_id).and_return(@bob.id)
      @new_post.stub!(:column_for_attribute).and_return(mock('column', :type => :integer, :limit => 255))

      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.input(:author_status, :as => :select))
      end)

      output_buffer.should have_tag('form li select#post_author_status_id')
    end
  end

  describe "for a belongs_to association with :group_by => :author" do
    it "should call author.posts" do
      ::Author.stub!(:reflect_on_all_associations).and_return { |macro| macro == :has_many ? [mock('reflection', :klass => Post, :name => :posts)] : []}

      [@freds_post].each { |post| post.stub!(:to_label).and_return("Post - #{post.id}") }
      @fred.should_receive(:posts)

      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.input(:main_post, :as => :select, :group_by => :author ) )
      end)
    end
  end

  describe "for a belongs_to association with :conditions" do
    before do
      ::Post.stub!(:reflect_on_association).with(:author).and_return do
        mock = mock('reflection', :options => {:conditions => {:active => true}}, :klass => ::Author, :macro => :belongs_to)
        mock.stub!(:[]).with(:class_name).and_return("Author")
        mock
      end
    end

    it "should call author.find with association conditions" do
      ::Author.should_receive(:scoped).with(:conditions => {:active => true})

      semantic_form_for(@new_post) do |builder|
        concat(builder.input(:author, :as => :select))
      end
    end

    it "should call author.find with association conditions and find_options conditions" do
      ::Author.should_receive(:scoped).with(:conditions => {:active => true})
      ::Author.should_receive(:where).with({:publisher => true})

      semantic_form_for(@new_post) do |builder|
        concat(builder.input(:author, :as => :select, :find_options => {:conditions => {:publisher => true}}))
      end
    end
  end

  describe 'for a belongs_to association with :group_by => :continent' do
    before do
      @authors = [@bob, @fred, @fred, @fred]
      ::Author.stub!(:find).and_return(@authors)
      @continent_names = %w(Europe Africa)
      @continents = (0..1).map { |i| c = ::Continent.new; c.stub!(:id).and_return(100 - i);c }
      @authors[0..1].each_with_index { |author, i| author.stub!(:continent).and_return(@continents[i]) }

      ::Continent.stub!(:reflect_on_all_associations).and_return { |macro| macro == :has_many ? [mock('reflection', :klass => Author, :name => :authors)] : [] }
      ::Continent.stub!(:reflect_on_association).and_return {|column_name| mock('reflection', :klass => Author) if column_name == :authors}
      ::Author.stub!(:reflect_on_association).and_return { |column_name| mock('reflection', :options => {}, :klass => Continent, :macro => :belongs_to) if column_name == :continent }


      @continents.each_with_index do |continent, i|
        continent.stub!(:to_label).and_return(@continent_names[i])
        continent.stub!(:authors).and_return([@authors[i]])
      end

      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.input(:author, :as => :select, :group_by => :continent ) )
        concat(builder.input(:author, :as => :select, :group_by => :continent, :group_label => :id ) )
        concat(builder.input(:author, :as => :select, :group_by => :continent, :member_label => :login ) )
        concat(builder.input(:author, :as => :select, :group_by => :continent, :member_label => :login, :group_label => :id ) )
      end)
    end

    it_should_have_input_wrapper_with_class("select")
    it_should_have_input_wrapper_with_id("post_author_input")
    it_should_have_label_with_text(/Author/)
    it_should_have_label_for('post_author_id')

    # TODO, need to find a way to repeat some of the specs and logic from the belongs_to specs without grouping

    0.upto(1) do |i|
      it 'should have all option groups and the right values' do
        output_buffer.should have_tag("form li select optgroup[@label='#{@continent_names[i]}']", @authors[i].to_label)
      end

      it 'should have custom group labels' do
        output_buffer.should have_tag("form li select optgroup[@label='#{@continents[i].id}']", @authors[i].to_label)
      end

      it 'should have custom author labels' do
        output_buffer.should have_tag("form li select optgroup[@label='#{@continent_names[i]}']", @authors[i].login)
      end

      it 'should have custom author and group labels' do
        output_buffer.should have_tag("form li select optgroup[@label='#{@continents[i].id}']", @authors[i].login)
      end
    end

    it 'should have no duplicate groups' do
      output_buffer.should have_tag('form li select optgroup', :count => 8)
    end

    it 'should sort the groups on the label method' do
      output_buffer.should have_tag("form li select optgroup[@label='Africa']")
      output_buffer.should have_tag("form li select optgroup[@label='99']")
    end

    it 'should call find with :include for more optimized queries' do
      Author.should_receive(:where).with(:include => :continent)

      semantic_form_for(@new_post) do |builder|
        concat(builder.input(:author, :as => :select, :group_by => :continent ) )
      end
    end
  end

  describe 'for a has_many association' do
    before do
      concat(semantic_form_for(@fred) do |builder|
        concat(builder.input(:posts, :as => :select))
      end)
    end

    it_should_have_input_wrapper_with_class("select")
    it_should_have_input_wrapper_with_id("author_posts_input")
    it_should_have_label_with_text(/Post/)
    it_should_have_label_for('author_post_ids')
    it_should_apply_error_logic_for_input_type(:select)
    it_should_call_find_on_association_class_when_no_collection_is_provided(:select)
    it_should_use_the_collection_when_provided(:select, 'option')

    it 'should have a select inside the wrapper' do
      output_buffer.should have_tag('form li select')
      output_buffer.should have_tag('form li select#author_post_ids')
    end

    it 'should have a multi-select select' do
      output_buffer.should have_tag('form li select[@multiple="multiple"]')
    end
    
    it 'should append [] to the name attribute for multiple select' do
      output_buffer.should have_tag('form li select[@multiple="multiple"][@name="author[post_ids][]"]')
    end

    it 'should have a hidden field' do
      output_buffer.should have_tag('form li input[@type="hidden"][@name="author[post_ids][]"]')
    end

    it 'should have a select option for each Post' do
      output_buffer.should have_tag('form li select option', :count => ::Post.all.size)
      ::Post.all.each do |post|
        output_buffer.should have_tag("form li select option[@value='#{post.id}']", /#{post.to_label}/)
      end
    end

    it 'should not have a blank option by default' do
      output_buffer.should_not have_tag("form li select option[@value='']")
    end

    it 'should respect the :include_blank option for single selects' do
      concat(semantic_form_for(@fred) do |builder|
        concat(builder.input(:posts, :as => :select, :multiple => false, :include_blank => true))
      end)

      output_buffer.should have_tag("form li select option[@value='']")
    end

    it 'should respect the :include_blank option for multiple selects' do
      concat(semantic_form_for(@fred) do |builder|
        concat(builder.input(:posts, :as => :select, :multiple => true, :include_blank => true))
      end)

      output_buffer.should have_tag("form li select option[@value='']")
    end

    it 'should have one option with a "selected" attribute' do
      output_buffer.should have_tag('form li select option[@selected]', :count => 1)
    end
  end

  describe 'for a has_and_belongs_to_many association' do
    before do
      concat(semantic_form_for(@freds_post) do |builder|
        concat(builder.input(:authors, :as => :select))
      end)
    end

    it_should_have_input_wrapper_with_class("select")
    it_should_have_input_wrapper_with_id("post_authors_input")
    it_should_have_label_with_text(/Author/)
    it_should_have_label_for('post_author_ids')
    it_should_apply_error_logic_for_input_type(:select)
    it_should_call_find_on_association_class_when_no_collection_is_provided(:select)
    it_should_use_the_collection_when_provided(:select, 'option')

    it 'should have a select inside the wrapper' do
      output_buffer.should have_tag('form li select')
      output_buffer.should have_tag('form li select#post_author_ids')
    end

    it 'should have a multi-select select' do
      output_buffer.should have_tag('form li select[@multiple="multiple"]')
    end

    it 'should have a select option for each Author' do
      output_buffer.should have_tag('form li select option', :count => ::Author.all.size)
      ::Author.all.each do |author|
        output_buffer.should have_tag("form li select option[@value='#{author.id}']", /#{author.to_label}/)
      end
    end

    it 'should not have a blank option by default' do
      output_buffer.should_not have_tag("form li select option[@value='']")
    end

    it 'should respect the :include_blank option for single selects' do
      concat(semantic_form_for(@freds_post) do |builder|
        concat(builder.input(:authors, :as => :select, :multiple => false, :include_blank => true))
      end)

      output_buffer.should have_tag("form li select option[@value='']")
    end

    it 'should respect the :include_blank option for multiple selects' do
      concat(semantic_form_for(@freds_post) do |builder|
        concat(builder.input(:authors, :as => :select, :multiple => true, :include_blank => true))
      end)

      output_buffer.should have_tag("form li select option[@value='']")
    end

    it 'should have one option with a "selected" attribute' do
      output_buffer.should have_tag('form li select option[@selected]', :count => 1)
    end
  end

  describe 'when :prompt => "choose something" is set' do
    before do
      @new_post.stub!(:author_id).and_return(nil)
      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.input(:author, :as => :select, :prompt => "choose author"))
      end)
    end

    it 'should have a select with prompt' do
      output_buffer.should have_tag("form li select option[@value='']", /choose author/, :count => 1)
    end

    it 'should not have a second blank select option' do
      output_buffer.should have_tag("form li select option[@value='']", :count => 1)
    end
  end

  describe 'when no object is given' do
    before(:each) do
      concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
        concat(builder.input(:author, :as => :select, :collection => ::Author.all))
      end)
    end

    it 'should generate label' do
      output_buffer.should have_tag('form li label', /Author/)
      output_buffer.should have_tag("form li label[@for='project_author']")
    end

    it 'should generate select inputs' do
      output_buffer.should have_tag('form li select#project_author')
      output_buffer.should have_tag('form li select option', :count => ::Author.all.size + 1)
    end

    it 'should generate an option to each item' do
      ::Author.all.each do |author|
        output_buffer.should have_tag("form li select option[@value='#{author.id}']", /#{author.to_label}/)
      end
    end
  end

  describe 'when no association exists' do

    it 'should still generate a valid name attribute' do
      concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
        concat(builder.input(:author_name, :as => :select, :collection => ::Author.all))
      end)
      output_buffer.should have_tag("form li select[@name='project[author_name]']")
    end

    describe 'and :multiple is set to true through :input_html' do
      it "should make the select a multi-select" do
        concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
          concat(builder.input(:author_name, :as => :select, :input_html => {:multiple => true} ))
        end)
        output_buffer.should have_tag("form li select[@multiple]")
      end
    end

    describe 'and :multiple is set to true' do
      it "should make the select a multi-select" do
        concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
          concat(builder.input(:author_name, :as => :select, :multiple => true, :collection => ["Fred", "Bob"]))
        end)
        output_buffer.should have_tag("form li select[@multiple]")
      end
    end

  end

  describe 'when a grouped collection collection is given' do
    before(:each) do
      concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
        @grouped_opts = [['one',   ['pencil', 'crayon', 'pen']],
                         ['two',   ['eyes', 'hands', 'feet']],
                         ['three', ['wickets', 'witches', 'blind mice']]]
        concat(builder.input(:author, :as => :select, :collection => grouped_options_for_select(@grouped_opts, "hands")))
      end)
    end

    it 'should generate an option to each item' do
      @grouped_opts.each do |opt_pair|
        output_buffer.should have_tag("form li select optgroup[@label='#{opt_pair[0]}']")
        opt_pair[1].each do |v|
          output_buffer.should have_tag("form li select optgroup[@label='#{opt_pair[0]}'] option[@value='#{v}']")
        end
      end
      output_buffer.should have_tag("form li select optgroup option[@selected]","hands")
    end
  end

  describe "enum" do
    before do
      @output_buffer = ''
      @some_meta_descriptions = ["One", "Two", "Three"]
      @new_post.stub!(:meta_description).any_number_of_times
    end

    describe ":as is not set" do
      before do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:meta_description, :collection => @some_meta_descriptions))
        end)
        concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
          concat(builder.input(:meta_description, :collection => @some_meta_descriptions))
        end)
      end

      it "should render a select field" do
        output_buffer.should have_tag("form li select", :count => 2)
      end
    end

    describe ":as is set" do
      before do
        # Should not be a case, but just checking :as got highest priority in setting input type.
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:meta_description, :as => :string, :collection => @some_meta_descriptions))
        end)
        concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
          concat(builder.input(:meta_description, :as => :string, :collection => @some_meta_descriptions))
        end)
      end

      it "should render a text field" do
        output_buffer.should have_tag("form li input[@type='text']", :count => 2)
      end
    end
  end

  describe 'when a namespace is provided' do
    before do
      concat(semantic_form_for(@freds_post, :namespace => 'context2') do |builder|
        concat(builder.input(:authors, :as => :select))
      end)
    end
    it_should_have_input_wrapper_with_id("context2_post_authors_input")
    it_should_have_select_with_id("context2_post_author_ids")
    it_should_have_label_for("context2_post_author_ids")
  end
  
  describe "when index is provided" do
  
    before do
      @output_buffer = ''
      mock_everything
  
      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.fields_for(:author, :index => 3) do |author|
          concat(author.input(:name, :as => :select))
        end)
      end)
    end
    
    it 'should index the id of the wrapper' do
      output_buffer.should have_tag("li#post_author_attributes_3_name_input")
    end
    
    it 'should index the id of the select tag' do
      output_buffer.should have_tag("select#post_author_attributes_3_name")
    end
    
    it 'should index the name of the select' do
      output_buffer.should have_tag("select[@name='post[author_attributes][3][name]']")
    end
    
  end

  context "when required" do
    it "should add the required attribute to the select's html options" do
      with_config :use_required_attribute, true do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:author, :as => :select, :required => true))
        end)
        output_buffer.should have_tag("select[@required]")
      end
    end
  end

end
