# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'
require File.dirname(__FILE__) + '/class_method_handler_shared_examples'

RSpec.describe "YARD::Handlers::Ruby::#{LEGACY_PARSER ? "Legacy::" : ""}PrivateClassMethodHandler" do
  before { Registry.clear }

  let(:visibility) { :private }

  include_examples "class method visibility decorator"
end
