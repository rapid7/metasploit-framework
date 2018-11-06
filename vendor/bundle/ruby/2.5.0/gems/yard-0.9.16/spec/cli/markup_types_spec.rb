# frozen_string_literal: true

RSpec.describe YARD::CLI::MarkupTypes do
  it "lists all available markup types" do
    YARD::CLI::MarkupTypes.run
    data = log.io.string
    exts = YARD::Templates::Helpers::MarkupHelper::MARKUP_EXTENSIONS
    YARD::Templates::Helpers::MarkupHelper::MARKUP_PROVIDERS.each do |name, providers|
      expect(data).to match(/\b#{name}\b/)

      # Match all extensions
      exts[name].each do |ext|
        expect(data).to include(".#{ext}")
      end if exts[name]

      # Match all provider libs
      providers.each do |provider|
        expect(data).to match(/\b#{provider[:lib]}\b/)
      end
    end
  end
end
