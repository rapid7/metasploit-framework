# encoding: utf-8
require 'spec_helper'

describe 'string input' do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything
  end

  describe "with_options and :wrapper_html" do
    before do
      concat(semantic_form_for(@new_post) do |builder|
        builder.with_options :wrapper_html => { :class => ['extra'] } do |opt_builder|
          concat(opt_builder.input(:title, :as => :string))
          concat(opt_builder.input(:author, :as => :radio))
        end
      end)
    end

    it "should have extra class on title" do
      output_buffer.should have_tag("form li#post_title_input.extra")
    end
    it "should have title as string" do
      output_buffer.should have_tag("form li#post_title_input.string")
    end
    it "should not have title as radio" do
      output_buffer.should_not have_tag("form li#post_title_input.radio")
    end

    it "should have extra class on author" do
      output_buffer.should have_tag("form li#post_author_input.extra")
    end
    it "should not have author as string" do
      output_buffer.should_not have_tag("form li#post_author_input.string")
    end
    it "should have author as radio" do
      output_buffer.should have_tag("form li#post_author_input.radio")
    end
  end
end
