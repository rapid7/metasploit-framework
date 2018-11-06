# frozen_string_literal: true

SimpleCov.profiles.define "test_frameworks" do
  add_filter "/test/"
  add_filter "/features/"
  add_filter "/spec/"
  add_filter "/autotest/"
end
