# frozen_string_literal: true

SimpleCov.profiles.define "bundler_filter" do
  add_filter "/vendor/bundle/"
end
