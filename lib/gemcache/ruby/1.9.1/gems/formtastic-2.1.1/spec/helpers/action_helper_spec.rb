# encoding: utf-8
require 'spec_helper'

describe 'Formtastic::FormBuilder#action' do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything
  end

  after do
    ::I18n.backend.reload!
  end

  describe 'arguments and options' do

    it 'should require the first argument (the action method)' do
      lambda {
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.action()) # no args passed in at all
        end)
      }.should raise_error(ArgumentError)
    end

    describe ':as option' do
    
      describe 'when not provided' do
    
        it 'should default to a commit for commit' do
          concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
            concat(builder.action(:submit))
          end)
          output_buffer.should have_tag('form li.action.input_action', :count => 1)
        end
    
        it 'should default to a button for reset' do
          concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
            concat(builder.action(:reset))
          end)
          output_buffer.should have_tag('form li.action.input_action', :count => 1)
        end

        it 'should default to a link for cancel' do
          concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
            concat(builder.action(:cancel))
          end)
          output_buffer.should have_tag('form li.action.link_action', :count => 1)
        end
      end
    
      it 'should call the corresponding action class with .to_html' do
        [:input, :button, :link].each do |action_style|
          semantic_form_for(:project, :url => "http://test.host") do |builder|
            action_instance = mock('Action instance')
            action_class = "#{action_style.to_s}_action".classify
            action_constant = "Formtastic::Actions::#{action_class}".constantize
    
            action_constant.should_receive(:new).and_return(action_instance)
            action_instance.should_receive(:to_html).and_return("some HTML")
    
            concat(builder.action(:submit, :as => action_style))
          end
        end
      end
    
    end
    
    #describe ':label option' do
    #
    #  describe 'when provided' do
    #    it 'should be passed down to the label tag' do
    #      concat(semantic_form_for(@new_post) do |builder|
    #        concat(builder.input(:title, :label => "Kustom"))
    #      end)
    #      output_buffer.should have_tag("form li label", /Kustom/)
    #    end
    #
    #    it 'should not generate a label if false' do
    #      concat(semantic_form_for(@new_post) do |builder|
    #        concat(builder.input(:title, :label => false))
    #      end)
    #      output_buffer.should_not have_tag("form li label")
    #    end
    #
    #    it 'should be dupped if frozen' do
    #      concat(semantic_form_for(@new_post) do |builder|
    #        concat(builder.input(:title, :label => "Kustom".freeze))
    #      end)
    #      output_buffer.should have_tag("form li label", /Kustom/)
    #    end
    #  end
    #
    #  describe 'when not provided' do
    #    describe 'when localized label is provided' do
    #      describe 'and object is given' do
    #        describe 'and label_str_method not :humanize' do
    #          it 'should render a label with localized text and not apply the label_str_method' do
    #            with_config :label_str_method, :reverse do
    #              @localized_label_text = 'Localized title'
    #              @new_post.stub!(:meta_description)
    #              ::I18n.backend.store_translations :en,
    #                :formtastic => {
    #                  :labels => {
    #                    :meta_description => @localized_label_text
    #                  }
    #                }
    #
    #              concat(semantic_form_for(@new_post) do |builder|
    #                concat(builder.input(:meta_description))
    #              end)
    #              output_buffer.should have_tag('form li label', /Localized title/)
    #            end
    #          end
    #        end
    #      end
    #    end
    #
    #    describe 'when localized label is NOT provided' do
    #      describe 'and object is not given' do
    #        it 'should default the humanized method name, passing it down to the label tag' do
    #          ::I18n.backend.store_translations :en, :formtastic => {}
    #          with_config :label_str_method, :humanize do
    #            concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
    #              concat(builder.input(:meta_description))
    #            end)
    #            output_buffer.should have_tag("form li label", /#{'meta_description'.humanize}/)
    #          end
    #        end
    #      end
    #
    #      describe 'and object is given' do
    #        it 'should delegate the label logic to class human attribute name and pass it down to the label tag' do
    #          @new_post.stub!(:meta_description) # a two word method name
    #          @new_post.class.should_receive(:human_attribute_name).with('meta_description').and_return('meta_description'.humanize)
    #
    #          concat(semantic_form_for(@new_post) do |builder|
    #            concat(builder.input(:meta_description))
    #          end)
    #          output_buffer.should have_tag("form li label", /#{'meta_description'.humanize}/)
    #        end
    #      end
    #
    #      describe 'and object is given with label_str_method set to :capitalize' do
    #        it 'should capitalize method name, passing it down to the label tag' do
    #          with_config :label_str_method, :capitalize do
    #            @new_post.stub!(:meta_description)
    #
    #            concat(semantic_form_for(@new_post) do |builder|
    #              concat(builder.input(:meta_description))
    #            end)
    #            output_buffer.should have_tag("form li label", /#{'meta_description'.capitalize}/)
    #          end
    #        end
    #      end
    #    end
    #
    #    describe 'when localized label is provided' do
    #      before do
    #        @localized_label_text = 'Localized title'
    #        @default_localized_label_text = 'Default localized title'
    #        ::I18n.backend.store_translations :en,
    #          :formtastic => {
    #              :labels => {
    #                :title => @default_localized_label_text,
    #                :published => @default_localized_label_text,
    #                :post => {
    #                  :title => @localized_label_text,
    #                  :published => @default_localized_label_text
    #                 }
    #               }
    #            }
    #      end
    #
    #      it 'should render a label with localized label (I18n)' do
    #        with_config :i18n_lookups_by_default, false do
    #          concat(semantic_form_for(@new_post) do |builder|
    #            concat(builder.input(:title, :label => true))
    #            concat(builder.input(:published, :as => :boolean, :label => true))
    #          end)
    #          output_buffer.should have_tag('form li label', Regexp.new('^' + @localized_label_text))
    #        end
    #      end
    #
    #      it 'should render a hint paragraph containing an optional localized label (I18n) if first is not set' do
    #        with_config :i18n_lookups_by_default, false do
    #          ::I18n.backend.store_translations :en,
    #            :formtastic => {
    #                :labels => {
    #                  :post => {
    #                    :title => nil,
    #                    :published => nil
    #                   }
    #                 }
    #              }
    #          concat(semantic_form_for(@new_post) do |builder|
    #            concat(builder.input(:title, :label => true))
    #            concat(builder.input(:published, :as => :boolean, :label => true))
    #          end)
    #          output_buffer.should have_tag('form li label', Regexp.new('^' + @default_localized_label_text))
    #        end
    #      end
    #    end
    #  end
    #
    #end
    #
    describe ':wrapper_html option' do
    
      describe 'when provided' do
        it 'should be passed down to the li tag' do
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.action(:submit, :wrapper_html => {:id => :another_id}))
          end)
          output_buffer.should have_tag("form li#another_id")
        end
    
        it 'should append given classes to li default classes' do
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.action(:submit, :wrapper_html => {:class => :another_class}))
          end)
          output_buffer.should have_tag("form li.action")
          output_buffer.should have_tag("form li.input_action")
          output_buffer.should have_tag("form li.another_class")
        end
    
        it 'should allow classes to be an array' do
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.action(:submit, :wrapper_html => {:class => [ :my_class, :another_class ]}))
          end)
          output_buffer.should have_tag("form li.action")
          output_buffer.should have_tag("form li.input_action")
          output_buffer.should have_tag("form li.my_class")
          output_buffer.should have_tag("form li.another_class")
        end
      end
    
      describe 'when not provided' do
        it 'should use default id and class' do
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.action(:submit))
          end)
          output_buffer.should have_tag("form li#post_submit_action")
          output_buffer.should have_tag("form li.action")
          output_buffer.should have_tag("form li.input_action")
        end
      end
    
    end
    
  end

  describe 'instantiating an action class' do
  
    context 'when a class does not exist' do
      it "should raise an error" do
        lambda {
          concat(semantic_form_for(@new_post) do |builder|
            builder.action(:submit, :as => :non_existant)
          end)
        }.should raise_error(Formtastic::UnknownActionError)
      end
    end
  
    context 'when a customized top-level class does not exist' do
  
      it 'should instantiate the Formtastic action' do
        action = mock('action', :to_html => 'some HTML')
        Formtastic::Actions::ButtonAction.should_receive(:new).and_return(action)
        concat(semantic_form_for(@new_post) do |builder|
          builder.action(:commit, :as => :button)
        end)
      end
  
    end
  
    describe 'when a top-level (custom) action class exists' do
      it "should instantiate the top-level action instead of the Formtastic one" do
        class ::ButtonAction < Formtastic::Actions::ButtonAction
        end
  
        action = mock('action', :to_html => 'some HTML')
        Formtastic::Actions::ButtonAction.should_not_receive(:new).and_return(action)
        ::ButtonAction.should_receive(:new).and_return(action)
  
        concat(semantic_form_for(@new_post) do |builder|
          builder.action(:commit, :as => :button)
        end)
      end
    end
  
    describe 'when instantiated multiple times with the same action type' do
  
      it "should be cached (not calling the internal methods)" do
        # TODO this is really tied to the underlying implementation
        concat(semantic_form_for(@new_post) do |builder|
          builder.should_receive(:custom_action_class_name).with(:button).once.and_return(::Formtastic::Actions::ButtonAction)
          builder.action(:submit, :as => :button)
          builder.action(:submit, :as => :button)
        end)
      end
  
    end
    
    describe 'support for :as on each action' do
      
      it "should raise an error when the action does not support the :as" do
        lambda {
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.action(:submit, :as => :link))
          end)
        }.should raise_error(Formtastic::UnsupportedMethodForAction)
        
        lambda {
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.action(:cancel, :as => :input))
          end)
        }.should raise_error(Formtastic::UnsupportedMethodForAction)
        
        lambda {
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.action(:cancel, :as => :button))
          end)
        }.should raise_error(Formtastic::UnsupportedMethodForAction)
      end
      
      it "should not raise an error when the action does not support the :as" do
        lambda {
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.action(:cancel, :as => :link))
          end)
        }.should_not raise_error(Formtastic::UnsupportedMethodForAction)
        
        lambda {
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.action(:submit, :as => :input))
          end)
        }.should_not raise_error(Formtastic::UnsupportedMethodForAction)

        lambda {
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.action(:submit, :as => :button))
          end)
        }.should_not raise_error(Formtastic::UnsupportedMethodForAction)
        
        lambda {
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.action(:reset, :as => :input))
          end)
        }.should_not raise_error(Formtastic::UnsupportedMethodForAction)
        
        lambda {
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.action(:reset, :as => :button))
          end)
        }.should_not raise_error(Formtastic::UnsupportedMethodForAction)
      end
      
    end
    
  end

end

