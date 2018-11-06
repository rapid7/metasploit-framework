# frozen_string_literal: true

SimpleCov.profiles.define "root_filter" do
  # Exclude all files outside of simplecov root
  root_filter = nil
  add_filter do |src|
    root_filter ||= /\A#{Regexp.escape(SimpleCov.root + File::SEPARATOR)}/io
    src.filename !~ root_filter
  end
end
