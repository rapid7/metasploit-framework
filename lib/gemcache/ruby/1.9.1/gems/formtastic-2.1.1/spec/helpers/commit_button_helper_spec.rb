# encoding: utf-8
require 'spec_helper'

describe 'Formtastic::FormBuilder#commit_button' do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything
  end
  
  describe 'when the object responds to :persisted? (ActiveModel)' do

    before do
      @new_post.stub(:respond_to?).with(:to_model).and_return("X")
      @new_post.stub(:respond_to?).with(:persisted?).and_return(true)
      @new_post.stub(:respond_to?).with(:new_record?).and_return(false)
    end

    it 'should call :persisted?' do
      with_deprecation_silenced do
        with_config :i18n_lookups_by_default, false do
          @new_post.should_receive(:persisted?)
          @new_post.should_not_receive(:new_record?)
          semantic_form_for(@new_post) do |builder|
            concat(builder.commit_button)
          end
        end
      end
    end

  end

  describe 'when not persisted' do

    before do
      @new_post.stub(:respond_to?).with(:to_model).and_return("X")
      @new_post.stub(:respond_to?).with(:persisted?).and_return(false)
      @new_post.stub(:respond_to?).with(:new_record?).and_return(false)
    end

    it 'should have a submit button label' do
      with_deprecation_silenced do
        with_config :i18n_lookups_by_default, false do
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.commit_button)
          end)
        end
      end

      output_buffer.should have_tag('.commit input[@value="Submit Post"]')
    end
  end

  describe 'when used on any record' do

    before do
      @new_post.stub!(:new_record?).and_return(false)
      with_deprecation_silenced do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.commit_button)
        end)
      end
    end

    it 'should render a commit li' do
      output_buffer.should have_tag('li.commit')
    end

    it 'should render a button li' do
      output_buffer.should have_tag('li.button')
    end

    it 'should render an input with a type attribute of "submit"' do
      output_buffer.should have_tag('li.commit input[@type="submit"]')
    end

    it 'should render an input with a name attribute of "commit"' do
      output_buffer.should have_tag('li.commit input[@name="commit"]')
    end

    it 'should pass options given in :button_html to the button' do
      @new_post.stub!(:new_record?).and_return(false)
      with_deprecation_silenced do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.commit_button('text', :button_html => {:class => 'my_class', :id => 'my_id'}))
        end)
      end

      output_buffer.should have_tag('li.commit input#my_id')
      output_buffer.should have_tag('li.commit input.my_class')
    end

  end

  describe "its accesskey" do

    it 'should allow nil default' do
      with_config :default_commit_button_accesskey, nil do
        output_buffer.should_not have_tag('li.commit input[@accesskey]')
      end
    end

    it 'should use the default if set' do
      with_config :default_commit_button_accesskey, 's' do
        @new_post.stub!(:new_record?).and_return(false)
        with_deprecation_silenced do
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.commit_button('text', :button_html => {}))
          end)
        end
        output_buffer.should have_tag('li.commit input[@accesskey="s"]')
      end
    end

    it 'should use the value set in options over the default' do
      with_config :default_commit_button_accesskey, 's' do
        @new_post.stub!(:new_record?).and_return(false)
        with_deprecation_silenced do
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.commit_button('text', :accesskey => 'o'))
          end)
        end
        output_buffer.should_not have_tag('li.commit input[@accesskey="s"]')
        output_buffer.should have_tag('li.commit input[@accesskey="o"]')
      end
    end

    it 'should use the value set in button_html over options' do
      with_config :default_commit_button_accesskey, 's' do
        @new_post.stub!(:new_record?).and_return(false)
        with_deprecation_silenced do
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.commit_button('text', :accesskey => 'o', :button_html => {:accesskey => 't'}))
          end)
        end
        output_buffer.should_not have_tag('li.commit input[@accesskey="s"]')
        output_buffer.should_not have_tag('li.commit input[@accesskey="o"]')
        output_buffer.should have_tag('li.commit input[@accesskey="t"]')
      end
    end

  end

  describe 'when the first option is a string and the second is a hash' do

    before do
      @new_post.stub!(:new_record?).and_return(false)
      with_deprecation_silenced do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.commit_button("a string", :button_html => { :class => "pretty"}))
        end)
      end
    end

    it "should render the string as the value of the button" do
      output_buffer.should have_tag('li input[@value="a string"]')
    end

    it "should deal with the options hash" do
      output_buffer.should have_tag('li input.pretty')
    end

  end

  describe 'when the first option is a hash' do

    before do
      @new_post.stub!(:new_record?).and_return(false)
      with_deprecation_silenced do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.commit_button(:button_html => { :class => "pretty"}))
        end)
      end
    end

    it "should deal with the options hash" do
      output_buffer.should have_tag('li input.pretty')
    end

  end

  describe 'label' do

    # No object
    describe 'when used without object' do
      describe 'when explicit label is provided' do
        it 'should render an input with the explicitly specified label' do
          with_deprecation_silenced do
            concat(semantic_form_for(:post, :url => 'http://example.com') do |builder|
              concat(builder.commit_button("Click!"))
            end)
          end
          output_buffer.should have_tag('li.commit input[@value="Click!"][@class~="submit"]')
        end
      end

      describe 'when no explicit label is provided' do
        describe 'when no I18n-localized label is provided' do
          before do
            ::I18n.backend.store_translations :en, :formtastic => {:submit => 'Submit %{model}'}
          end

          after do
            ::I18n.backend.reload!
          end

          it 'should render an input with default I18n-localized label (fallback)' do
            with_deprecation_silenced do
              concat(semantic_form_for(:post, :url => 'http://example.com') do |builder|
                concat(builder.commit_button)
              end)
            end
            output_buffer.should have_tag('li.commit input[@value="Submit Post"][@class~="submit"]')
          end
        end

       describe 'when I18n-localized label is provided' do
         before do
           ::I18n.backend.store_translations :en,
             :formtastic => {
                 :actions => {
                   :submit => 'Custom Submit',
                  }
               }
         end

         after do
           ::I18n.backend.reload!
         end

         it 'should render an input with localized label (I18n)' do
           with_config :i18n_lookups_by_default, true do
             ::I18n.backend.store_translations :en,
               :formtastic => {
                   :actions => {
                     :post => {
                       :submit => 'Custom Submit %{model}'
                      }
                    }
                 }
             with_deprecation_silenced do
               concat(semantic_form_for(:post, :url => 'http://example.com') do |builder|
                 concat(builder.commit_button)
               end)
             end
             output_buffer.should have_tag(%Q{li.commit input[@value="Custom Submit Post"][@class~="submit"]})
           end
         end

         it 'should render an input with anoptional localized label (I18n) - if first is not set' do
           with_config :i18n_lookups_by_default, true do
             with_deprecation_silenced do
               concat(semantic_form_for(:post, :url => 'http://example.com') do |builder|
                 concat(builder.commit_button)
               end)
             end
             output_buffer.should have_tag(%Q{li.commit input[@value="Custom Submit"][@class~="submit"]})
           end
         end

       end
      end
    end

    # New record
    describe 'when used on a new record' do
      before do
        @new_post.stub!(:new_record?).and_return(true)
      end

      describe 'when explicit label is provided' do
        it 'should render an input with the explicitly specified label' do
          with_deprecation_silenced do
            concat(semantic_form_for(@new_post) do |builder|
              concat(builder.commit_button("Click!"))
            end)
          end
          output_buffer.should have_tag('li.commit input[@value="Click!"][@class~="create"]')
        end
      end

      describe 'when no explicit label is provided' do
        describe 'when no I18n-localized label is provided' do
          before do
            ::I18n.backend.store_translations :en, :formtastic => {:create => 'Create %{model}'}
          end

          after do
            ::I18n.backend.reload!
          end

          it 'should render an input with default I18n-localized label (fallback)' do
            with_deprecation_silenced do
              concat(semantic_form_for(@new_post) do |builder|
                concat(builder.commit_button)
              end)
            end
            output_buffer.should have_tag('li.commit input[@value="Create Post"][@class~="create"]')
          end
        end

        describe 'when I18n-localized label is provided' do
          before do
            ::I18n.backend.store_translations :en,
              :formtastic => {
                  :actions => {
                    :create => 'Custom Create',
                   }
                }
          end

          after do
            ::I18n.backend.reload!
          end

          it 'should render an input with localized label (I18n)' do
            with_config :i18n_lookups_by_default, true do
              ::I18n.backend.store_translations :en,
                :formtastic => {
                    :actions => {
                      :post => {
                        :create => 'Custom Create %{model}'
                       }
                     }
                  }
              with_deprecation_silenced do
                concat(semantic_form_for(@new_post) do |builder|
                  concat(builder.commit_button)
                end)
              end
              output_buffer.should have_tag(%Q{li.commit input[@value="Custom Create Post"][@class~="create"]})
            end
          end

          it 'should render an input with anoptional localized label (I18n) - if first is not set' do
            with_config :i18n_lookups_by_default, true do
              with_deprecation_silenced do
                concat(semantic_form_for(@new_post) do |builder|
                  concat(builder.commit_button)
                end)
              end
              output_buffer.should have_tag(%Q{li.commit input[@value="Custom Create"][@class~="create"]})
            end
          end

        end
      end
    end

    # Existing record
    describe 'when used on an existing record' do
      before do
        @new_post.stub!(:persisted?).and_return(true)
      end

      describe 'when explicit label is provided' do
        it 'should render an input with the explicitly specified label' do
          with_deprecation_silenced do
            concat(semantic_form_for(@new_post) do |builder|
              concat(builder.commit_button("Click!"))
            end)
          end
          output_buffer.should have_tag('li.commit input[@value="Click!"][@class~="update"]')
        end
      end

      describe 'when no explicit label is provided' do
        describe 'when no I18n-localized label is provided' do
          before do
            ::I18n.backend.store_translations :en, :formtastic => {:update => 'Save %{model}'}
          end

          after do
            ::I18n.backend.reload!
          end

          it 'should render an input with default I18n-localized label (fallback)' do
            with_deprecation_silenced do
              concat(semantic_form_for(@new_post) do |builder|
                concat(builder.commit_button)
              end)
            end
            output_buffer.should have_tag('li.commit input[@value="Save Post"][@class~="update"]')
          end
        end

        describe 'when I18n-localized label is provided' do
          before do
            ::I18n.backend.reload!
            ::I18n.backend.store_translations :en,
              :formtastic => {
                  :actions => {
                    :update => 'Custom Save',
                   }
                }
          end

          after do
            ::I18n.backend.reload!
          end

          it 'should render an input with localized label (I18n)' do
            with_config :i18n_lookups_by_default, true do
              ::I18n.backend.store_translations :en,
                :formtastic => {
                    :actions => {
                      :post => {
                        :update => 'Custom Save %{model}'
                       }
                     }
                  }
              with_deprecation_silenced do
                concat(semantic_form_for(@new_post) do |builder|
                  concat(builder.commit_button)
                end)
              end
              output_buffer.should have_tag(%Q{li.commit input[@value="Custom Save Post"][@class~="update"]})
            end
          end

          it 'should render an input with anoptional localized label (I18n) - if first is not set' do
            with_config :i18n_lookups_by_default, true do
              with_deprecation_silenced do
                concat(semantic_form_for(@new_post) do |builder|
                  concat(builder.commit_button)
                end)
              end
              output_buffer.should have_tag(%Q{li.commit input[@value="Custom Save"][@class~="update"]})
              ::I18n.backend.store_translations :en, :formtastic => {}
            end
          end

        end
      end
    end
  end

  describe 'when the model is two words' do
    before do
      output_buffer = ''
      class ::UserPost
        extend ActiveModel::Naming if defined?(ActiveModel::Naming)
        include ActiveModel::Conversion if defined?(ActiveModel::Conversion)

        def id
        end

        def persisted?
        end

        # Rails does crappy human_name
        def self.human_name
          "User post"
        end
      end
      @new_user_post = ::UserPost.new

      @new_user_post.stub!(:new_record?).and_return(true)
      with_deprecation_silenced do
        concat(semantic_form_for(@new_user_post, :url => '') do |builder|
          concat(builder.commit_button())
        end)
      end
    end

    it "should render the string as the value of the button" do
      output_buffer.should have_tag('li input[@value="Create User post"]')
    end

  end

  describe ':wrapper_html option' do

    describe 'when provided' do
      it 'should be passed down to the li tag' do
        with_deprecation_silenced do
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.commit_button('text', :wrapper_html => {:id => :another_id}))
          end)
        end
        output_buffer.should have_tag("form li#another_id")
      end

      it 'should append given classes to li default classes' do
        with_deprecation_silenced do 
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.commit_button('text', :wrapper_html => {:class => :another_class}))
          end)
        end
        output_buffer.should have_tag("form li.commit")
        output_buffer.should have_tag("form li.another_class")
      end

      it 'should allow classes to be an array' do
        with_deprecation_silenced do 
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.commit_button('text', :wrapper_html => {:class => [ :my_class, :another_class ]}))
          end)
        end
        output_buffer.should have_tag("form li.commit")
        output_buffer.should have_tag("form li.my_class")
        output_buffer.should have_tag("form li.another_class")
      end
    end

    describe 'when not provided' do
      it 'should use default class' do
        with_deprecation_silenced do 
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.commit_button('text'))
          end)
        end
        output_buffer.should have_tag("form li.commit.button")
      end

      it 'should use default id' do
        with_deprecation_silenced do 
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.commit_button('text'))
          end)
        end
        output_buffer.should have_tag("form li.commit.button input#post_submit")
      end
    end

  end

end
