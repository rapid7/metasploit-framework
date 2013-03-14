# encoding: utf-8
require 'spec_helper'

describe 'Formtastic::I18n' do

  FORMTASTIC_KEYS = [:required, :yes, :no, :create, :update].freeze

  it "should be defined" do
    lambda { Formtastic::I18n }.should_not raise_error(::NameError)
  end

  describe "default translations" do
    it "should be defined" do
      lambda { Formtastic::I18n::DEFAULT_VALUES }.should_not raise_error(::NameError)
      Formtastic::I18n::DEFAULT_VALUES.is_a?(::Hash).should == true
    end

    it "should exists for the core I18n lookup keys" do
      (Formtastic::I18n::DEFAULT_VALUES.keys & FORMTASTIC_KEYS).size.should == FORMTASTIC_KEYS.size
    end
  end

  describe "when I18n locales are available" do

    before do
      @formtastic_strings = {
          :yes            => 'Default Yes',
          :no             => 'Default No',
          :create         => 'Default Create %{model}',
          :update         => 'Default Update %{model}',
          :custom_scope   => {
              :duck           => 'Duck',
              :duck_pond      => '%{ducks} ducks in a pond'
            }
        }
      ::I18n.backend.store_translations :en, :formtastic => @formtastic_strings
    end

    after do
      ::I18n.backend.reload!
    end

    it "should translate core strings correctly" do
      ::I18n.backend.store_translations :en, {:formtastic => {:required => 'Default Required'}}
      Formtastic::I18n.t(:required).should  == "Default Required"
      Formtastic::I18n.t(:yes).should       == "Default Yes"
      Formtastic::I18n.t(:no).should        == "Default No"
      Formtastic::I18n.t(:create, :model => 'Post').should == "Default Create Post"
      Formtastic::I18n.t(:update, :model => 'Post').should == "Default Update Post"
    end

    it "should all belong to scope 'formtastic'" do
      Formtastic::I18n.t(:duck, :scope => [:custom_scope]).should == 'Duck'
    end

    it "should override default I18n lookup args if these are specified" do
      Formtastic::I18n.t(:duck_pond, :scope => [:custom_scope], :ducks => 15).should == '15 ducks in a pond'
    end

    it "should be possible to override default values" do
      Formtastic::I18n.t(:required, :default => 'Nothing found!').should == 'Nothing found!'
    end

  end

  describe "when no I18n locales are available" do

    before do
      ::I18n.backend.reload!
    end

    it "should use default strings" do
      (Formtastic::I18n::DEFAULT_VALUES.keys).each do |key|
        Formtastic::I18n.t(key, :model => '%{model}').should == Formtastic::I18n::DEFAULT_VALUES[key]
      end
    end

  end

  describe "I18n string lookups" do

    include FormtasticSpecHelper

    before do
      @output_buffer = ''
      mock_everything

      ::I18n.backend.store_translations :en, {:formtastic => {
          :labels => {
              :author   => { :name => "Top author name transation" },
              :post     => {:title => "Hello post!", :author => {:name => "Hello author name!"}},
              :project  => {:title => "Hello project!"},
            }
        }, :helpers => {
          :label => {
            :post => {:body => "Elaborate..." },
            :author => { :login => "Hello login" }
          }
        }}

      @new_post.stub!(:title)
      @new_post.stub!(:column_for_attribute).with(:title).and_return(mock('column', :type => :string, :limit => 255))
    end

    after do
      ::I18n.backend.reload!
    end

    it "lookup scopes should be defined" do
      with_config :i18n_lookups_by_default, true do
        lambda { Formtastic::I18n::SCOPES }.should_not raise_error(::NameError)
      end
    end

    it "should be able to translate with namespaced object" do
      with_config :i18n_lookups_by_default, true do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:title))
        end)
        output_buffer.should have_tag("form label", /Hello post!/)
      end
    end

    it "should be able to translate without form-object" do
      with_config :i18n_lookups_by_default, true do
        concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
          concat(builder.input(:title))
        end)
        output_buffer.should have_tag("form label", /Hello project!/)
      end
    end

    it "should be able to translate when method name is same as model" do
      with_config :i18n_lookups_by_default, true do
        concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
          concat(builder.input(:author))
        end)
        output_buffer.should have_tag("form label", /Author/)
      end
    end

    it 'should be able to translate nested objects with nested translations' do
      with_config :i18n_lookups_by_default, true do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.semantic_fields_for(:author) do |f|
            concat(f.input(:name))
          end)
        end)
        output_buffer.should have_tag("form label", /Hello author name!/)
      end
    end

    it 'should be able to translate nested objects with top level translations' do
      with_config :i18n_lookups_by_default, true do
        concat(semantic_form_for(@new_post) do |builder|
          builder.semantic_fields_for(:author) do |f|
            concat(f.input(:name))
          end
        end)
        output_buffer.should have_tag("form label", /Hello author name!/)
      end
    end

    it 'should be able to translate nested objects with nested object translations' do
      with_config :i18n_lookups_by_default, true do
        concat(semantic_form_for(@new_post) do |builder|
          builder.semantic_fields_for(:project) do |f|
            concat(f.input(:title))
          end
        end)
        output_buffer.should have_tag("form label", /Hello project!/)
      end
    end
    
    it 'should be able to translate nested forms with top level translations' do
      with_config :i18n_lookups_by_default, true do
        concat(semantic_form_for(:post) do |builder|
          builder.semantic_fields_for(:author) do |f|
            concat(f.input(:name))
          end
        end)
        output_buffer.should have_tag("form label", /Hello author name!/)
      end
    end

    it 'should be able to translate helper label as Rails does' do
      with_config :i18n_lookups_by_default, true do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:body))
        end)
        output_buffer.should have_tag("form label", /Elaborate/)
      end
    end
    
    it 'should be able to translate nested helper label as Rails does' do
      with_config :i18n_lookups_by_default, true do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.inputs(:for => :author) do |f|
            concat(f.input(:login))
          end)
        end)
        output_buffer.should have_tag("form label", /Hello login/)
      end
    end

    # TODO: Add spec for namespaced models?

  end

end
