require 'rspec/core/warnings'
require 'rspec/expectations'
require 'rspec/rails/feature_check'

module RSpec
  module Rails
    # @api public
    # Container module for Rails specific matchers.
    module Matchers
    end
  end
end

require 'rspec/rails/matchers/have_rendered'
require 'rspec/rails/matchers/redirect_to'
require 'rspec/rails/matchers/routing_matchers'
require 'rspec/rails/matchers/be_new_record'
require 'rspec/rails/matchers/be_a_new'
require 'rspec/rails/matchers/relation_match_array'
require 'rspec/rails/matchers/be_valid'
require 'rspec/rails/matchers/have_http_status'
if RSpec::Rails::FeatureCheck.has_active_job?
  require 'rspec/rails/matchers/active_job'
end
