# encoding: utf-8
require 'spec_helper'

describe 'Formtastic::FormBuilder#inputs' do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything
  end

  describe 'with a block (block forms syntax)' do
  
    describe 'when no options are provided' do
      before do
        output_buffer.replace 'before_builder' # clear the output buffer and sets before_builder
        concat(semantic_form_for(@new_post) do |builder|
          @inputs_output = builder.inputs do
            concat('hello')
          end
        end)
      end
  
      it 'should output just the content wrapped in inputs, not the whole template' do
        output_buffer.should      =~ /before_builder/
        @inputs_output.should_not =~ /before_builder/
      end
  
      it 'should render a fieldset inside the form, with a class of "inputs"' do
        output_buffer.should have_tag("form fieldset.inputs")
      end
  
      it 'should render an ol inside the fieldset' do
        output_buffer.should have_tag("form fieldset.inputs ol")
      end
  
      it 'should render the contents of the block inside the ol' do
        output_buffer.should have_tag("form fieldset.inputs ol", /hello/)
      end
  
      it 'should not render a legend inside the fieldset' do
        output_buffer.should_not have_tag("form fieldset.inputs legend")
      end
  
      it 'should render a fieldset even if no object is given' do
        concat(semantic_form_for(:project, :url => 'http://test.host/') do |builder|
          @inputs_output = builder.inputs do
            concat('bye')
          end
        end)
        output_buffer.should have_tag("form fieldset.inputs ol", /bye/)
      end
    end
  
    describe 'when a :for option is provided' do
  
      before do
        @new_post.stub!(:respond_to?).and_return(true, true)
        @new_post.stub!(:author).and_return(@bob)
      end
  
      it 'should render nested inputs' do
        @bob.stub!(:column_for_attribute).and_return(mock('column', :type => :string, :limit => 255))
  
        concat(semantic_form_for(@new_post) do |builder|
          inputs = builder.inputs :for => [:author, @bob] do |bob_builder|
            concat(bob_builder.input(:login))
          end
          concat(inputs)
        end)
        output_buffer.should have_tag("form fieldset.inputs #post_author_attributes_login")
        output_buffer.should_not have_tag("form fieldset.inputs #author_login")
      end
  
      it 'should concat rendered nested inputs to the template' do
        @bob.stub!(:column_for_attribute).and_return(mock('column', :type => :string, :limit => 255))
  
        concat(semantic_form_for(@new_post) do |builder|
          builder.inputs :for => [:author, @bob] do |bob_builder|
            concat(bob_builder.input(:login))
          end
        end)
  
        output_buffer.should have_tag("form fieldset.inputs #post_author_attributes_login")
        output_buffer.should_not have_tag("form fieldset.inputs #author_login")
  
      end
  
      describe "as a symbol representing the association name" do
  
        it 'should nest the inputs with an _attributes suffix on the association name' do
          concat(semantic_form_for(@new_post) do |post|
            inputs = post.inputs :for => :author do |author|
              concat(author.input(:login))
            end
            concat(inputs)
          end)
          output_buffer.should have_tag("form input[@name='post[author_attributes][login]']")
        end
  
      end
  
      describe "as a symbol representing a has_many association name" do
        before do
          @new_post.stub!(:authors).and_return([@bob, @fred])
          @new_post.stub!(:authors_attributes=)
        end
  
        it 'should nest the inputs with a fieldset, legend and :name input for each item' do
          concat(semantic_form_for(@new_post) do |post|
            post.inputs :for => :authors, :name => '%i' do |author|
              concat(author.input(:login))
            end
          end)
          
          output_buffer.should have_tag("form fieldset.inputs", :count => 2)
          output_buffer.should have_tag("form fieldset.inputs legend", :count => 2)
          output_buffer.should have_tag("form fieldset.inputs legend", "1", :count => 1)
          output_buffer.should have_tag("form fieldset.inputs legend", "2")
          output_buffer.should have_tag("form input[@name='post[authors_attributes][0][login]']")
          output_buffer.should have_tag("form input[@name='post[authors_attributes][1][login]']")
          output_buffer.should_not have_tag('form fieldset[@name]')
        end
        
        it 'should include an indexed :label input for each item' do
          concat(semantic_form_for(@new_post) do |post|
            post.inputs :for => :authors do |author, index|
              concat(author.input(:login, :label => "#{index}", :required => false))
            end
          end)
          
          output_buffer.should have_tag("form fieldset.inputs label", "1", :count => 1)
          output_buffer.should have_tag("form fieldset.inputs label", "2", :count => 1)
          output_buffer.should_not have_tag('form fieldset legend')
        end
      end
  
      describe 'as an array containing the a symbole for the association name and the associated object' do
  
        it 'should nest the inputs with an _attributes suffix on the association name' do
          concat(semantic_form_for(@new_post) do |post|
            inputs = post.inputs :for => [:author, @new_post.author] do |author|
              concat(author.input(:login))
            end
            concat(inputs)
          end)
          output_buffer.should have_tag("form input[@name='post[author_attributes][login]']")
        end
  
      end
  
      describe 'as an associated object' do
  
        it 'should not nest the inputs with an _attributes suffix' do
          concat(semantic_form_for(@new_post) do |post|
            inputs = post.inputs :for => @new_post.author do |author|
              concat(author.input(:login))
            end
            concat(inputs)
          end)
          output_buffer.should have_tag("form input[@name='post[author][login]']")
        end
  
      end
  
      it 'should raise an error if :for and block with no argument is given' do
        semantic_form_for(@new_post) do |builder|
          proc {
            builder.inputs(:for => [:author, @bob]) do
              #
            end
          }.should raise_error(ArgumentError, 'You gave :for option with a block to inputs method, ' <<
                                              'but the block does not accept any argument.')
        end
      end
  
      it 'should pass options down to semantic_fields_for' do
        @bob.stub!(:column_for_attribute).and_return(mock('column', :type => :string, :limit => 255))
  
        concat(semantic_form_for(@new_post) do |builder|
          inputs = builder.inputs :for => [:author, @bob], :for_options => { :index => 10 } do |bob_builder|
            concat(bob_builder.input(:login))
          end
          concat(inputs)
        end)
  
        output_buffer.should have_tag('form fieldset ol li #post_author_attributes_10_login')
      end
  
      it 'should not add builder as a fieldset attribute tag' do
        concat(semantic_form_for(@new_post) do |builder|
          inputs = builder.inputs :for => [:author, @bob], :for_options => { :index => 10 } do |bob_builder|
            concat('input')
          end
          concat(inputs)
        end)
  
        output_buffer.should_not have_tag('fieldset[@builder="Formtastic::Helpers::FormHelper"]')
      end
  
      it 'should send parent_builder as an option to allow child index interpolation for legends' do
        concat(semantic_form_for(@new_post) do |builder|
          builder.instance_variable_set('@nested_child_index', 0)
          inputs = builder.inputs :for => [:author, @bob], :name => 'Author #%i' do |bob_builder|
            concat('input')
          end
          concat(inputs)
        end)
  
        output_buffer.should have_tag('fieldset legend', 'Author #1')
      end
  
      it 'should also provide child index interpolation for legends when nested child index is a hash' do
        concat(semantic_form_for(@new_post) do |builder|
          builder.instance_variable_set('@nested_child_index', :author => 10)
          inputs = builder.inputs :for => [:author, @bob], :name => 'Author #%i' do |bob_builder|
            concat('input')
          end
          concat(inputs)
        end)
  
        output_buffer.should have_tag('fieldset legend', 'Author #11')
      end
      
      it 'should send parent_builder as an option to allow child index interpolation for labels' do
        concat(semantic_form_for(@new_post) do |builder|
          builder.instance_variable_set('@nested_child_index', 'post[author_attributes]' => 0)
          inputs = builder.inputs :for => [:author, @bob] do |bob_builder, index|
            concat(bob_builder.input(:name, :label => "Author ##{index}", :required => false))
          end
          concat(inputs)
        end)
        
        output_buffer.should have_tag('fieldset label', 'Author #1')
      end
      
      it 'should also provide child index interpolation for labels when nested child index is a hash' do
        concat(semantic_form_for(@new_post) do |builder|
          builder.instance_variable_set('@nested_child_index', 'post[author_attributes]' => 10)
          inputs = builder.inputs :for => [:author, @bob] do |bob_builder, index|
            concat(bob_builder.input(:name, :label => "Author ##{index}", :required => false))
          end
          concat(inputs)
        end)
        
        output_buffer.should have_tag('fieldset label', 'Author #11')
      end
    end
  
    describe 'when a :name or :title option is provided' do
      describe 'and is a string' do
        before do
          @legend_text = "Advanced options"
          @legend_text_using_name = "Advanced options 2"
          @legend_text_using_title = "Advanced options 3"
          @nested_forms_legend_text = "This is a nested form title"
          concat(semantic_form_for(@new_post) do |builder|
            inputs = builder.inputs @legend_text do
            end
            concat(inputs)
            inputs = builder.inputs :name => @legend_text_using_name do
            end
            concat(inputs)
            inputs = builder.inputs :title => @legend_text_using_title do
            end
            concat(inputs)
            inputs = builder.inputs @nested_forms_legend_text, :for => :authors do |nf|
            end
            concat(inputs)
          end)
        end
  
        it 'should render a fieldset with a legend inside the form' do
          output_buffer.should have_tag("form fieldset legend", /^#{@legend_text}$/)
          output_buffer.should have_tag("form fieldset legend", /^#{@legend_text_using_name}$/)
          output_buffer.should have_tag("form fieldset legend", /^#{@legend_text_using_title}$/)
          output_buffer.should have_tag("form fieldset legend", /^#{@nested_forms_legend_text}$/)
        end
      end
  
      describe 'and is a symbol' do
        before do
          @localized_legend_text = "Localized advanced options"
          @localized_legend_text_using_name = "Localized advanced options 2"
          @localized_legend_text_using_title = "Localized advanced options 3"
          @localized_nested_forms_legend_text = "This is a localized nested form title"
          ::I18n.backend.store_translations :en, :formtastic => {
              :titles => {
                  :post => {
                      :advanced_options => @localized_legend_text,
                      :advanced_options_using_name => @localized_legend_text_using_name,
                      :advanced_options_using_title => @localized_legend_text_using_title,
                      :nested_forms_title => @localized_nested_forms_legend_text
                    }
                }
            }
          concat(semantic_form_for(@new_post) do |builder|
            inputs = builder.inputs :advanced_options do
            end
            concat(inputs)
            inputs =builder.inputs :name => :advanced_options_using_name do
            end
            concat(inputs)
            inputs = builder.inputs :title => :advanced_options_using_title do
            end
            concat(inputs)
            inputs = builder.inputs :nested_forms_title, :for => :authors do |nf|
            end
            concat(inputs)
          end)
        end
  
        it 'should render a fieldset with a localized legend inside the form' do
          output_buffer.should have_tag("form fieldset legend", /^#{@localized_legend_text}$/)
          output_buffer.should have_tag("form fieldset legend", /^#{@localized_legend_text_using_name}$/)
          output_buffer.should have_tag("form fieldset legend", /^#{@localized_legend_text_using_title}$/)
          output_buffer.should have_tag("form fieldset legend", /^#{@localized_nested_forms_legend_text}$/)
        end
      end
    end
  
    describe 'when other options are provided' do
      before do
        @id_option = 'advanced'
        @class_option = 'wide'
  
        concat(semantic_form_for(@new_post) do |builder|
          builder.inputs :id => @id_option, :class => @class_option do
          end
        end)
      end
  
      it 'should pass the options into the fieldset tag as attributes' do
        output_buffer.should have_tag("form fieldset##{@id_option}")
        output_buffer.should have_tag("form fieldset.#{@class_option}")
      end
    end
  
  end
  
  describe 'without a block' do
  
    before do
      ::Post.stub!(:reflections).and_return({:author => mock('reflection', :options => {}, :macro => :belongs_to),
                                           :comments => mock('reflection', :options => {}, :macro => :has_many) })
      ::Author.stub!(:find).and_return([@fred, @bob])
  
      @new_post.stub!(:title)
      @new_post.stub!(:body)
      @new_post.stub!(:author_id)
  
      @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :string, :limit => 255))
      @new_post.stub!(:column_for_attribute).with(:body).and_return(mock('column', :type => :text))
      @new_post.stub!(:column_for_attribute).with(:created_at).and_return(mock('column', :type => :datetime))
      @new_post.stub!(:column_for_attribute).with(:author).and_return(nil)
    end
  
    describe 'with no args (quick forms syntax)' do
      before do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.inputs)
        end)
      end
  
      it 'should render a form' do
        output_buffer.should have_tag('form')
      end
  
      it 'should render a fieldset inside the form' do
        output_buffer.should have_tag('form > fieldset.inputs')
      end
  
      it 'should not render a legend in the fieldset' do
        output_buffer.should_not have_tag('form > fieldset.inputs > legend')
      end
  
      it 'should render an ol in the fieldset' do
        output_buffer.should have_tag('form > fieldset.inputs > ol')
      end
  
      it 'should render a list item in the ol for each column and reflection' do
        # Remove the :has_many macro and :created_at column
        count = ::Post.content_columns.size + ::Post.reflections.size - 2
        output_buffer.should have_tag('form > fieldset.inputs > ol > li', :count => count)
      end
  
      it 'should render a string list item for title' do
        output_buffer.should have_tag('form > fieldset.inputs > ol > li.string')
      end
  
      it 'should render a text list item for body' do
        output_buffer.should have_tag('form > fieldset.inputs > ol > li.text')
      end
  
      it 'should render a select list item for author_id' do
        output_buffer.should have_tag('form > fieldset.inputs > ol > li.select', :count => 1)
      end
  
      it 'should not render timestamps inputs by default' do
        output_buffer.should_not have_tag('form > fieldset.inputs > ol > li.datetime')
      end
    
      context "with a polymorphic association" do
        
        before do 
          @new_post.stub!(:commentable)
          @new_post.class.stub!(:reflections).and_return({ 
            :commentable => mock('macro_reflection', :options => { :polymorphic => true }, :macro => :belongs_to)
          })
          @new_post.stub!(:column_for_attribute).with(:commentable).and_return(
            mock('column', :type => :integer)
          )
        end
        
        it 'should not render an input for the polymorphic association (the collection class cannot be guessed)' do
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.inputs)
          end)
          output_buffer.should_not have_tag('li#post_commentable_input')
        end
        
      end
    end
  
    describe 'with column names as args (short hand forms syntax)' do
      describe 'and an object is given' do
        it 'should render a form with a fieldset containing two list items' do
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.inputs(:title, :body))
          end)
  
          output_buffer.should have_tag('form > fieldset.inputs > ol > li', :count => 2)
          output_buffer.should have_tag('form > fieldset.inputs > ol > li.string')
          output_buffer.should have_tag('form > fieldset.inputs > ol > li.text')
        end
      end
  
      describe 'and no object is given' do
        it 'should render a form with a fieldset containing two list items' do
          concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
            concat(builder.inputs(:title, :body))
          end)
  
          output_buffer.should have_tag('form > fieldset.inputs > ol > li.string', :count => 2)
        end
      end
      
      context "with a polymorphic association" do
        
        it 'should raise an error for polymorphic associations (the collection class cannot be guessed)' do
          @new_post.stub!(:commentable)
          @new_post.class.stub!(:reflections).and_return({ 
            :commentable => mock('macro_reflection', :options => { :polymorphic => true }, :macro => :belongs_to)
          })
          @new_post.stub!(:column_for_attribute).with(:commentable).and_return(
            mock('column', :type => :integer)
          )
          @new_post.class.stub!(:reflect_on_association).with(:commentable).and_return(
            mock('reflection', :macro => :belongs_to, :options => { :polymorphic => true })
          )
          
          expect { 
            concat(semantic_form_for(@new_post) do |builder|
              concat(builder.inputs :commentable)
            end)
          }.to raise_error(Formtastic::PolymorphicInputWithoutCollectionError)
        end
        
      end
      
    end
  
    describe 'when a :for option is provided' do
      describe 'and an object is given' do
        it 'should render nested inputs' do
          @bob.stub!(:column_for_attribute).and_return(mock('column', :type => :string, :limit => 255))
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.inputs(:login, :for => @bob))
          end)
  
          output_buffer.should have_tag("form fieldset.inputs #post_author_login")
          output_buffer.should_not have_tag("form fieldset.inputs #author_login")
        end
      end
  
      describe 'and no object is given' do
        it 'should render nested inputs' do
          concat(semantic_form_for(:project, :url => 'http://test.host/') do |builder|
            concat(builder.inputs(:login, :for => @bob))
          end)
          output_buffer.should have_tag("form fieldset.inputs #project_author_login")
          output_buffer.should_not have_tag("form fieldset.inputs #project_login")
        end
      end
    end
  
    describe 'with column names and an options hash as args' do
      before do
        concat(semantic_form_for(@new_post) do |builder|
          @legend_text_using_option = "Legendary Legend Text"
          @legend_text_using_arg = "Legendary Legend Text 2"
          concat(builder.inputs(:title, :body, :name => @legend_text_using_option, :id => "my-id"))
          concat(builder.inputs(@legend_text_using_arg, :title, :body, :id => "my-id-2"))
        end)
      end
  
      it 'should render a form with a fieldset containing two list items' do
        output_buffer.should have_tag('form > fieldset.inputs > ol > li', :count => 4)
      end
  
      it 'should pass the options down to the fieldset' do
        output_buffer.should have_tag('form > fieldset#my-id.inputs')
      end
  
      it 'should use the special :name option as a text for the legend tag' do
        output_buffer.should have_tag('form > fieldset#my-id.inputs > legend', /^#{@legend_text_using_option}$/)
        output_buffer.should have_tag('form > fieldset#my-id-2.inputs > legend', /^#{@legend_text_using_arg}$/)
      end
    end
  
  end
  
  describe 'nesting' do
    
    context "when not nested" do
      it "should not wrap the inputs in an li block" do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.inputs do
          end)
        end)
        output_buffer.should_not have_tag('form > li')
      end
    end
    
    context "when nested (with block)" do
      it "should wrap the nested inputs in an li block to maintain HTML validity" do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.inputs do
            concat(builder.inputs do
            end)
          end)
        end)
        output_buffer.should have_tag('form > fieldset.inputs > ol > li > fieldset.inputs > ol')
      end
    end
    
    context "when nested (with block and :for)" do
      it "should wrap the nested inputs in an li block to maintain HTML validity" do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.inputs do
            concat(builder.inputs(:for => :author) do |author_builder|
            end)
          end)
        end)
        output_buffer.should have_tag('form > fieldset.inputs > ol > li > fieldset.inputs > ol')
      end
    end
    
    context "when nested (without block)" do
      it "should wrap the nested inputs in an li block to maintain HTML validity" do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.inputs do
            concat(builder.inputs(:title))
          end)
        end)
        output_buffer.should have_tag('form > fieldset.inputs > ol > li > fieldset.inputs > ol')
      end
    end
  
    context "when nested (without block, with :for)" do
      it "should wrap the nested inputs in an li block to maintain HTML validity" do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.inputs do
            concat(builder.inputs(:name, :for => :author))
          end)
        end)
        output_buffer.should have_tag('form > fieldset.inputs > ol > li > fieldset.inputs > ol')
      end
    end
  
    context "when double nested" do
      it "should wrap the nested inputs in an li block to maintain HTML validity" do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.inputs do
            concat(builder.inputs do
              concat(builder.inputs do
              end)
            end)
          end)
        end)
        output_buffer.should have_tag('form > fieldset.inputs > ol > li > fieldset.inputs > ol > li > fieldset.inputs > ol')
      end
    end

    context "when several are nested" do
      it "should wrap each of the nested inputs in an li block to maintain HTML validity" do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.inputs do
            concat(builder.inputs do
            end)
            concat(builder.inputs do
            end)
          end)
        end)
        output_buffer.should have_tag('form > fieldset.inputs > ol > li > fieldset.inputs > ol', :count => 2)
      end
    end
    
  end

  describe 'when using MongoMapper associations ' do
    def generate_form
      semantic_form_for(@new_mm_post) do |builder|
        builder.inputs :title, :sub_posts
      end
    end
    it "should throw PolymorphicInputWithoutCollectionError on sub_posts" do
      ::MongoPost.should_receive(:associations).at_least(3).times
      expect { generate_form }.to raise_error(Formtastic::PolymorphicInputWithoutCollectionError)
    end
  end

end
