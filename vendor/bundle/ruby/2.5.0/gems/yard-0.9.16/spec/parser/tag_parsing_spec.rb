# frozen_string_literal: true

RSpec.describe YARD::Parser, "tag handling" do
  before { parse_file :tag_handler_001, __FILE__ }

  it "knows the list of all available tags" do
    expect(P("Foo#foo").tags).to include(P("Foo#foo").tag(:api))
  end

  it "knows the text of tags on a method" do
    expect(P("Foo#foo").tag(:api).text).to eq "public"
  end

  it "returns true when asked whether a tag exists" do
    expect(P("Foo#foo").has_tag?(:api)).to be true
  end
end
