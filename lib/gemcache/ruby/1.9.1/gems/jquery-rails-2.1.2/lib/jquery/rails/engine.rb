require "jquery/assert_select" if ::Rails.env.test?

module Jquery
  module Rails
    class Engine < ::Rails::Engine
    end
  end
end
