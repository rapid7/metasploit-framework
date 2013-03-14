# encoding: utf-8
require 'spec_helper'

describe 'range input' do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything
  end

  describe "when object is provided" do
    before do
      concat(semantic_form_for(@bob) do |builder|
        concat(builder.input(:age, :as => :range))
      end)
    end

    it_should_have_input_wrapper_with_class(:range)
    it_should_have_input_wrapper_with_class(:input)
    it_should_have_input_wrapper_with_class(:numeric)
    it_should_have_input_wrapper_with_class(:stringish)
    it_should_have_input_wrapper_with_id("author_age_input")
    it_should_have_label_with_text(/Age/)
    it_should_have_label_for("author_age")
    it_should_have_input_with_id("author_age")
    it_should_have_input_with_type(:range)
    it_should_have_input_with_name("author[age]")

  end

  describe "when namespace is provided" do

    before do
      concat(semantic_form_for(@james, :namespace => "context2") do |builder|
        concat(builder.input(:age, :as => :range))
      end)
    end

    it_should_have_input_wrapper_with_id("context2_author_age_input")
    it_should_have_label_and_input_with_id("context2_author_age")

  end
  
  describe "when index is provided" do

    before do
      @output_buffer = ''
      mock_everything

      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.fields_for(:author, :index => 3) do |author|
          concat(author.input(:name, :as => :range))
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
  

  describe "when validations require a minimum value (:greater_than)" do
    before do
      @new_post.class.stub!(:validators_on).with(:title).and_return([
        active_model_numericality_validator([:title], {:only_integer=>false, :allow_nil=>false, :greater_than=>2})
      ])
    end
    
    it "should allow :input_html to override :min" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :input_html => { :min => 5 })
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end
    
    it "should allow :input_html to override :min through :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :input_html => { :in => 5..102 })
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end
    
    it "should allow options to override :min" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :min => 5)
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end
    
    it "should allow options to override :min through :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :in => 5..102)
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end
    
    describe "and the column is an integer" do
      before do
        @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :integer))
      end
      
      it "should add a min attribute to the input one greater than the validation" do
        concat(semantic_form_for(@new_post) do |builder|
          builder.input(:title, :as => :range)
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
            builder.input(:title, :as => :range)
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
            builder.input(:title, :as => :range)
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
        builder.input(:title, :as => :range, :input_html => { :min => 5 })
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end
    
    it "should allow options to override :min" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :min => 5)
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end

    it "should allow :input_html to override :min with :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :input_html => { :in => 5..102 })
      end)
      output_buffer.should have_tag('input[@min="5"]')
    end
    
    it "should allow options to override :min  with :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :in => 5..102)
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
            builder.input(:title, :as => :range)
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
          builder.input(:title, :as => :range)
        end)
        output_buffer.should have_tag('input[@min="2"]')
      end
    end
  end

  describe "when validations do not require a minimum value" do
    
    it "should default to 1" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range)
      end)
      output_buffer.should have_tag('input[@min="1"]')
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
       builder.input(:title, :as => :range, :input_html => { :max => 102 })
     end)
     output_buffer.should have_tag('input[@max="102"]')
   end
   
   it "should allow option to override :max" do
     concat(semantic_form_for(@new_post) do |builder|
       builder.input(:title, :as => :range, :max => 102)
     end)
     output_buffer.should have_tag('input[@max="102"]')
   end
   
   it "should allow :input_html to override :max with :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :input_html => { :in => 1..102 })
      end)
      output_buffer.should have_tag('input[@max="102"]')
    end

    it "should allow option to override :max with :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :in => 1..102)
      end)
      output_buffer.should have_tag('input[@max="102"]')
    end
   
   describe "and the column is an integer" do
     before do
       @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :integer))
     end
     
     it "should add a max attribute to the input one greater than the validation" do
       concat(semantic_form_for(@new_post) do |builder|
         builder.input(:title, :as => :range)
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
           builder.input(:title, :as => :range)
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
           builder.input(:title, :as => :range)
         end)
       }.should raise_error(Formtastic::Inputs::Base::Validations::IndeterminableMaximumAttributeError)
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
        builder.input(:title, :as => :range, :input_html => { :max => 102 })
      end)
      output_buffer.should have_tag('input[@max="102"]')
    end
    
    it "should allow options to override :max" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :max => 102)
      end)
      output_buffer.should have_tag('input[@max="102"]')
    end
    
    it "should allow :input_html to override :max with :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :input_html => { :in => 1..102 })
      end)
      output_buffer.should have_tag('input[@max="102"]')
    end
    
    it "should allow options to override :max with :in" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :in => 1..102)
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
            builder.input(:title, :as => :range)
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
          builder.input(:title, :as => :range)
        end)
        output_buffer.should have_tag('input[@max="20"]')
      end
    end
  end
  
  describe "when validations do not require a maximum value" do
    
    it "should default to 1" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range)
      end)
      output_buffer.should have_tag('input[@max="100"]')
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
        builder.input(:title, :as => :range)
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
        builder.input(:title, :as => :range)
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
        builder.input(:title, :as => :range)
      end)
      output_buffer.should have_tag('input[@step="1"]')
    end
    
    it "should let input_html override :step" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :input_html => { :step => 3 })
      end)
      output_buffer.should have_tag('input[@step="3"]')
    end
    
    it "should let options override :step" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :step => 3)
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
        builder.input(:title, :as => :range)
      end)
      output_buffer.should have_tag('input[@step="2"]')
    end
    
    it "should let input_html override :step" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :input_html => { :step => 3 })
      end)
      output_buffer.should have_tag('input[@step="3"]')
    end
    
    it "should let options override :step" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :step => 3)
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
    
    it "should default step to 1" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range)
      end)
      output_buffer.should have_tag('input[@step="1"]')
    end
    
    it "should let input_html set :step" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :input_html => { :step => 3 })
      end)
      output_buffer.should have_tag('input[@step="3"]')
    end
    
    it "should let options set :step" do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :range, :step => 3)
      end)
      output_buffer.should have_tag('input[@step="3"]')
    end
    
  end
  
end

