require 'active_support/concern'
require 'nokogiri'

module Rails
  module Dom
    module Testing
      module Assertions
        autoload :DomAssertions, 'rails/dom/testing/assertions/dom_assertions'
        autoload :SelectorAssertions, 'rails/dom/testing/assertions/selector_assertions'
        autoload :TagAssertions, 'rails/dom/testing/assertions/tag_assertions'

        extend ActiveSupport::Concern

        include DomAssertions
        include SelectorAssertions
        include TagAssertions
      end
    end
  end
end