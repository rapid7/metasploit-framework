# encoding: utf-8
require 'spec_helper'

describe 'number input' do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything
    
    @new_post.class.stub!(:validators_on).with(:title).and_return([
      active_model_numericality_validator([:title], {:only_integer=>false, :allow_nil=>false, :greater_than=>2})
    ])
  end
  
  describe "all cases" do
    
    before do
      concat(
      semantic_form_for(@new_post) do |builder|
        concat(builder.input(:title, :as => :number))
      end
      )
    end

    it_should_have_input_wrapper_with_class(:number)
    it_should_have_input_wrapper_with_class(:input)
    it_should_have_input_wrapper_with_class(:numeric)
    it_should_have_input_wrapper_with_class(:stringish)
    it_should_have_input_wrapper_with_id("post_title_input")
    it_should_have_label_with_text(/Title/)
    it_should_have_label_for("post_title")
    it_should_have_input_with_id("post_title")
    it_should_have_input_with_type(:number)
    it_should_have_input_with_name("post[title]")
    # @todo this is not testing what it should be testing!
    # it_should_use_default_text_field_size_when_not_nil(:string)
    # it_should_not_use_default_text_field_size_when_nil(:string)
    # it_should_apply_custom_input_attributes_when_input_html_provided(:string)
    # it_should_apply_custom_for_to_label_when_input_html_id_provided(:string)
    it_should_apply_error_logic_for_input_type(:number)
    
  end

  describe "when no object is provided" do
    before do
      concat(semantic_form_for(:project, :url => 'http://test.host/') do |builder|
        concat(builder.input(:title, :as => :number, :input_html => { :min => 1, :max => 2 }))
      end)
    end
    
    it_should_have_label_with_text(/Title/)
    it_should_have_label_for("project_title")
    it_should_have_input_with_id("project_title")
    it_should_have_input_with_type(:number)
    it_should_have_input_with_name("project[title]")
  end

  describe "when namespace provided" do
    before do
      concat(semantic_form_for(@new_post, :namespace => :context2) do |builder|
        concat(builder.input(:title, :as => :number))
      end)
    end
  
    it_should_have_input_wrapper_with_id("context2_post_title_input")
    it_should_have_label_and_input_with_id("context2_post_title")
  end
  
  describe "when index is provided" do

    before do
      @output_buffer = ''
      mock_everything

      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.fields_for(:author, :index => 3) do |author|
          concat(author.input(:name, :as => :number))
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
          concat(builder.input(:title, :as => :number, :required => true))
        end)
        output_buffer.should have_tag("input[@required]")
      end
    end
  end
  
  describe "when validations require a minimum value (:greater_than)" do
    before do
      @new_post.class.stub!(:validators_on).with(:title).and_return([
        active_model_numericality_validator([:title], {:only_integer=>false, :allow_nil=>false, :greater_than=>2})
      ])
    end
    
    it "should allow :input_html to override :min" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :input_html => { :min => 5 })
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end
    
    it "should allow :input_html to override :min through :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :input_html => { :in => 5..102 })
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end
    
    it "should allow options to override :min" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :min => 5)
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end
    
    it "should allow options to override :min through :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :in => 5..102)
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end
    
    describe "and the column is an integer" do
      before do
        @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :integer))
      end
      
      it "should add a min attribute to the input one greater than the validation" do
        concat(semantic_form_for(@new_post) do |builder|
          builder.input(:title, :as => :number)
        end)
        output_buffer.should have_tag('input[@min="3"]')
      end
    end
    
    describe "and the column is a float" do
      before do
        @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :float))
      end
      
      it "should raise an error" do
        lambda {
          concat(semantic_form_for(@new_post) do |builder|
            builder.input(:title, :as => :number)
          end)
        }.should raise_error(Formtastic::Inputs::Base::Validations::IndeterminableMinimumAttributeError)
      end
    end
    
    describe "and the column is a big decimal" do
      before do
        @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :decimal))
      end
      
      it "should raise an error" do
        lambda {
          concat(semantic_form_for(@new_post) do |builder|
            builder.input(:title, :as => :number)
          end)
        }.should raise_error(Formtastic::Inputs::Base::Validations::IndeterminableMinimumAttributeError)
      end
    end
    
  end
  
  describe "when validations require a minimum value (:greater_than) that takes a proc" do
    before do
      @new_post.class.stub!(:validators_on).with(:title).and_return([
        active_model_numericality_validator([:title], {:only_integer=>false, :allow_nil=>false, :greater_than=> Proc.new {|post| 2}})
      ])
    end
    
    it "should allow :input_html to override :min" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :input_html => { :min => 5 })
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end
    
    it "should allow :input_html to override :min through :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :input_html => { :in => 5..102 })
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end
    
    it "should allow options to override :min" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :min => 5)
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end
    
    it "should allow options to override :min through :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :in => 5..102)
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end
    
    describe "and the column is an integer" do
      before do
        @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :integer))
      end
      
      it "should add a min attribute to the input one greater than the validation" do
        concat(semantic_form_for(@new_post) do |builder|
          builder.input(:title, :as => :number)
        end)
        output_buffer.should have_tag('input[@min="3"]')
      end
    end
    
    describe "and the column is a float" do
      before do
        @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :float))
      end
      
      it "should raise an error" do
        lambda {
          concat(semantic_form_for(@new_post) do |builder|
            builder.input(:title, :as => :number)
          end)
        }.should raise_error(Formtastic::Inputs::Base::Validations::IndeterminableMinimumAttributeError)
      end
    end
    
    describe "and the column is a big decimal" do
      before do
        @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :decimal))
      end
      
      it "should raise an error" do
        lambda {
          concat(semantic_form_for(@new_post) do |builder|
            builder.input(:title, :as => :number)
          end)
        }.should raise_error(Formtastic::Inputs::Base::Validations::IndeterminableMinimumAttributeError)
      end
    end
    
  end
  
  describe "when validations require a minimum value (:greater_than_or_equal_to)" do
    before do
      @new_post.class.stub!(:validators_on).with(:title).and_return([
        active_model_numericality_validator([:title], {:only_integer=>false, :allow_nil=>false, :greater_than_or_equal_to=>2})
      ])
    end
    
    it "should allow :input_html to override :min" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :input_html => { :min => 5 })
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end
    
    it "should allow options to override :min" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :min => 5)
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end

    it "should allow :input_html to override :min with :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :input_html => { :in => 5..102 })
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end
    
    it "should allow options to override :min  with :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :in => 5..102)
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end
    

    [:integer, :decimal, :float].each do |column_type|
      describe "and the column is a #{column_type}" do
        before do
          @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => column_type))
        end

        it "should add a max attribute to the input equal to the validation" do
          concat(semantic_form_for(@new_post) do |builder|
            builder.input(:title, :as => :number)
          end)
          output_buffer.should have_tag('input[@min="2"]')
        end
      end
    end

    describe "and there is no column" do
      before do
        @new_post.stub!(:column_for_attribute).with(:title).and_return(nil)
      end
    
      it "should add a max attribute to the input equal to the validation" do
        concat(semantic_form_for(@new_post) do |builder|
          builder.input(:title, :as => :number)
        end)
        output_buffer.should have_tag('input[@min="2"]')
      end
    end
  end
  
  describe "when validations require a minimum value (:greater_than_or_equal_to) that takes a Proc" do
     before do
       @new_post.class.stub!(:validators_on).with(:title).and_return([
         active_model_numericality_validator([:title], {:only_integer=>false, :allow_nil=>false, :greater_than_or_equal_to=> Proc.new { |post| 2}})
       ])
     end

     it "should allow :input_html to override :min" do
       concat(semantic_form_for(@new_post) do |builder|
         builder.input(:title, :as => :number, :input_html => { :min => 5 })
       end)
       output_buffer.should have_tag('input[@min="5"]')
     end

     it "should allow options to override :min" do
       concat(semantic_form_for(@new_post) do |builder|
         builder.input(:title, :as => :number, :min => 5)
       end)
       output_buffer.should have_tag('input[@min="5"]')
     end

     it "should allow :input_html to override :min with :in" do
       concat(semantic_form_for(@new_post) do |builder|
         builder.input(:title, :as => :number, :input_html => { :in => 5..102 })
       end)
       output_buffer.should have_tag('input[@min="5"]')
     end

     it "should allow options to override :min  with :in" do
       concat(semantic_form_for(@new_post) do |builder|
         builder.input(:title, :as => :number, :in => 5..102)
       end)
       output_buffer.should have_tag('input[@min="5"]')
     end


     [:integer, :decimal, :float].each do |column_type|
       describe "and the column is a #{column_type}" do
         before do
           @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => column_type))
         end

         it "should add a max attribute to the input equal to the validation" do
           concat(semantic_form_for(@new_post) do |builder|
             builder.input(:title, :as => :number)
           end)
           output_buffer.should have_tag('input[@min="2"]')
         end
       end
     end

     describe "and there is no column" do
       before do
         @new_post.stub!(:column_for_attribute).with(:title).and_return(nil)
       end

       it "should add a max attribute to the input equal to the validation" do
         concat(semantic_form_for(@new_post) do |builder|
           builder.input(:title, :as => :number)
         end)
         output_buffer.should have_tag('input[@min="2"]')
       end
     end
   end

  describe "when validations require a maximum value (:less_than)" do
    
   before do
     @new_post.class.stub!(:validators_on).with(:title).and_return([
       active_model_numericality_validator([:title], {:only_integer=>false, :allow_nil=>false, :less_than=>20})
     ])
   end
   
   it "should allow :input_html to override :max" do
     concat(semantic_form_for(@new_post) do |builder|
       builder.input(:title, :as => :number, :input_html => { :max => 102 })
     end)
     output_buffer.should have_tag('input[@max="102"]')
   end
   
   it "should allow option to override :max" do
     concat(semantic_form_for(@new_post) do |builder|
       builder.input(:title, :as => :number, :max => 102)
     end)
     output_buffer.should have_tag('input[@max="102"]')
   end
   
   it "should allow :input_html to override :max with :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :input_html => { :in => 1..102 })
      end)
      output_buffer.should have_tag('input[@max="102"]')
    end

    it "should allow option to override :max with :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :in => 1..102)
      end)
      output_buffer.should have_tag('input[@max="102"]')
    end
   
   describe "and the column is an integer" do
     before do
       @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :integer))
     end
     
     it "should add a max attribute to the input one greater than the validation" do
       concat(semantic_form_for(@new_post) do |builder|
         builder.input(:title, :as => :number)
       end)
       output_buffer.should have_tag('input[@max="19"]')
     end
   end
   
   describe "and the column is a float" do
     before do
       @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :float))
     end
     
     it "should raise an error" do
       lambda {
         concat(semantic_form_for(@new_post) do |builder|
           builder.input(:title, :as => :number)
         end)
       }.should raise_error(Formtastic::Inputs::Base::Validations::IndeterminableMaximumAttributeError)
     end
   end
   
   describe "and the column is a big decimal" do
     before do
       @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :decimal))
     end
     
     it "should raise an error" do
       lambda {
         concat(semantic_form_for(@new_post) do |builder|
           builder.input(:title, :as => :number)
         end)
       }.should raise_error(Formtastic::Inputs::Base::Validations::IndeterminableMaximumAttributeError)
     end
   end
   describe "and the validator takes a proc" do
     before do
       @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :decimal))
     end
   end
  end
  
  describe "when validations require a maximum value (:less_than) that takes a Proc" do
    
   before do
     @new_post.class.stub!(:validators_on).with(:title).and_return([
       active_model_numericality_validator([:title], {:only_integer=>false, :allow_nil=>false, :less_than=> Proc.new {|post| 20 }})
     ])
   end
   
   it "should allow :input_html to override :max" do
     concat(semantic_form_for(@new_post) do |builder|
       builder.input(:title, :as => :number, :input_html => { :max => 102 })
     end)
     output_buffer.should have_tag('input[@max="102"]')
   end
   
   it "should allow option to override :max" do
     concat(semantic_form_for(@new_post) do |builder|
       builder.input(:title, :as => :number, :max => 102)
     end)
     output_buffer.should have_tag('input[@max="102"]')
   end
   
   it "should allow :input_html to override :max with :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :input_html => { :in => 1..102 })
      end)
      output_buffer.should have_tag('input[@max="102"]')
    end

    it "should allow option to override :max with :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :in => 1..102)
      end)
      output_buffer.should have_tag('input[@max="102"]')
    end
   
   describe "and the column is an integer" do
     before do
       @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :integer))
     end
     
     it "should add a max attribute to the input one greater than the validation" do
       concat(semantic_form_for(@new_post) do |builder|
         builder.input(:title, :as => :number)
       end)
       output_buffer.should have_tag('input[@max="19"]')
     end
   end
   
   describe "and the column is a float" do
     before do
       @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :float))
     end
     
     it "should raise an error" do
       lambda {
         concat(semantic_form_for(@new_post) do |builder|
           builder.input(:title, :as => :number)
         end)
       }.should raise_error(Formtastic::Inputs::Base::Validations::IndeterminableMaximumAttributeError)
     end
   end
   
   describe "and the column is a big decimal" do
     before do
       @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :decimal))
     end
     
     it "should raise an error" do
       lambda {
         concat(semantic_form_for(@new_post) do |builder|
           builder.input(:title, :as => :number)
         end)
       }.should raise_error(Formtastic::Inputs::Base::Validations::IndeterminableMaximumAttributeError)
     end
   end
   describe "and the validator takes a proc" do
     before do
       @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :decimal))
     end
   end
  end
  
  
  describe "when validations require a maximum value (:less_than_or_equal_to)" do
    before do
      @new_post.class.stub!(:validators_on).with(:title).and_return([
        active_model_numericality_validator([:title], {:only_integer=>false, :allow_nil=>false, :less_than_or_equal_to=>20})
      ])
    end
    
    it "should allow :input_html to override :max" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :input_html => { :max => 102 })
      end)
      output_buffer.should have_tag('input[@max="102"]')
    end
    
    it "should allow options to override :max" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :max => 102)
      end)
      output_buffer.should have_tag('input[@max="102"]')
    end
    
    it "should allow :input_html to override :max with :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :input_html => { :in => 1..102 })
      end)
      output_buffer.should have_tag('input[@max="102"]')
    end
    
    it "should allow options to override :max with :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :in => 1..102)
      end)
      output_buffer.should have_tag('input[@max="102"]')
    end

    [:integer, :decimal, :float].each do |column_type|
      describe "and the column is a #{column_type}" do
        before do
          @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => column_type))
        end

        it "should add a max attribute to the input equal to the validation" do
          concat(semantic_form_for(@new_post) do |builder|
            builder.input(:title, :as => :number)
          end)
          output_buffer.should have_tag('input[@max="20"]')
        end
      end
    end

    describe "and there is no column" do
      before do
        @new_post.stub!(:column_for_attribute).with(:title).and_return(nil)
      end
    
      it "should add a max attribute to the input equal to the validation" do
        concat(semantic_form_for(@new_post) do |builder|
          builder.input(:title, :as => :number)
        end)
        output_buffer.should have_tag('input[@max="20"]')
      end
    end
  end
 
  describe "when validations require a maximum value (:less_than_or_equal_to) that takes a proc" do
     before do
       @new_post.class.stub!(:validators_on).with(:title).and_return([
         active_model_numericality_validator([:title], {:only_integer=>false, :allow_nil=>false, :less_than_or_equal_to=> Proc.new { |post| 20 }})
       ])
     end

     it "should allow :input_html to override :max" do
       concat(semantic_form_for(@new_post) do |builder|
         builder.input(:title, :as => :number, :input_html => { :max => 102 })
       end)
       output_buffer.should have_tag('input[@max="102"]')
     end

     it "should allow options to override :max" do
       concat(semantic_form_for(@new_post) do |builder|
         builder.input(:title, :as => :number, :max => 102)
       end)
       output_buffer.should have_tag('input[@max="102"]')
     end

     it "should allow :input_html to override :max with :in" do
       concat(semantic_form_for(@new_post) do |builder|
         builder.input(:title, :as => :number, :input_html => { :in => 1..102 })
       end)
       output_buffer.should have_tag('input[@max="102"]')
     end

     it "should allow options to override :max with :in" do
       concat(semantic_form_for(@new_post) do |builder|
         builder.input(:title, :as => :number, :in => 1..102)
       end)
       output_buffer.should have_tag('input[@max="102"]')
     end

     [:integer, :decimal, :float].each do |column_type|
       describe "and the column is a #{column_type}" do
         before do
           @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => column_type))
         end

         it "should add a max attribute to the input equal to the validation" do
           concat(semantic_form_for(@new_post) do |builder|
             builder.input(:title, :as => :number)
           end)
           output_buffer.should have_tag('input[@max="20"]')
         end
       end
     end

     describe "and there is no column" do
       before do
         @new_post.stub!(:column_for_attribute).with(:title).and_return(nil)
       end

       it "should add a max attribute to the input equal to the validation" do
         concat(semantic_form_for(@new_post) do |builder|
           builder.input(:title, :as => :number)
         end)
         output_buffer.should have_tag('input[@max="20"]')
       end
     end
   end
  
  describe "when validations require conflicting minimum values (:greater_than, :greater_than_or_equal_to)" do
    before do
      @new_post.class.stub!(:validators_on).with(:title).and_return([
        active_model_numericality_validator([:title], {:only_integer=>false, :allow_nil=>false, :greater_than => 20, :greater_than_or_equal_to=>2})
      ])
    end
    
    it "should add a max attribute to the input equal to the :greater_than_or_equal_to validation" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number)
      end)
      output_buffer.should have_tag('input[@min="2"]')
    end
  end
  
  describe "when validations require conflicting maximum values (:less_than, :less_than_or_equal_to)" do
    before do
      @new_post.class.stub!(:validators_on).with(:title).and_return([
        active_model_numericality_validator([:title], {:only_integer=>false, :allow_nil=>false, :less_than => 20, :less_than_or_equal_to=>2})
      ])
    end
    
    it "should add a max attribute to the input equal to the :greater_than_or_equal_to validation" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number)
      end)
      output_buffer.should have_tag('input[@max="2"]')
    end
  end
  
  describe "when validations require only an integer (:only_integer)" do
    
    before do
      @new_post.class.stub!(:validators_on).with(:title).and_return([
        active_model_numericality_validator([:title], {:allow_nil=>false, :only_integer=>true})
      ])
    end
    
    it "should add a step=1 attribute to the input to signify that only whole numbers are allowed" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number)
      end)
      output_buffer.should have_tag('input[@step="1"]')
    end
    
    it "should let input_html override :step" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :input_html => { :step => 3 })
      end)
      output_buffer.should have_tag('input[@step="3"]')
    end
    
    it "should let options override :step" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :step => 3)
      end)
      output_buffer.should have_tag('input[@step="3"]')
    end
    
  end
  
  describe "when validations require a :step (non standard)" do
    
    before do
      @new_post.class.stub!(:validators_on).with(:title).and_return([
        active_model_numericality_validator([:title], {:allow_nil=>false, :only_integer=>true, :step=>2})
      ])
    end
    
    it "should add a step=1 attribute to the input to signify that only whole numbers are allowed" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number)
      end)
      output_buffer.should have_tag('input[@step="2"]')
    end
    
    it "should let input_html override :step" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :input_html => { :step => 3 })
      end)
      output_buffer.should have_tag('input[@step="3"]')
    end
    
    it "should let options override :step" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :step => 3)
      end)
      output_buffer.should have_tag('input[@step="3"]')
    end
    
  end
  
  describe "when validations do not specify :step (non standard) or :only_integer" do
    
    before do
      @new_post.class.stub!(:validators_on).with(:title).and_return([
        active_model_numericality_validator([:title], {:allow_nil=>false})
      ])
    end
    
    it "should default step to 'any'" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number)
      end)
      output_buffer.should have_tag('input[@step="any"]')
    end
    
    it "should let input_html set :step" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :input_html => { :step => 3 })
      end)
      output_buffer.should have_tag('input[@step="3"]')
    end
    
    it "should let options set :step" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :number, :step => 3)
      end)
      output_buffer.should have_tag('input[@step="3"]')
    end
    
  end
  
end

