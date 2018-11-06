# frozen_string_literal: true

RSpec.describe YARD::I18n::Text do
  describe "#extract_messages" do
    def extract_messages(input, options = {})
      text = YARD::I18n::Text.new(StringIO.new(input), options)
      messages = []
      text.extract_messages do |*message|
        messages << message
      end
      messages
    end

    describe "Header" do
      it "extracts at attribute" do
        text = <<-eot
# @title Getting Started Guide

# Getting Started with YARD
eot
        expect(extract_messages(text, :have_header => true)).to eq(
          [[:attribute, "title", "Getting Started Guide", 1],
           [:paragraph, "# Getting Started with YARD", 3]]
        )
      end

      it "ignores markup line" do
        text = <<-eot
#!markdown
# @title Getting Started Guide

# Getting Started with YARD
eot
        expect(extract_messages(text, :have_header => true)).to eq(
          [[:attribute, "title", "Getting Started Guide", 2],
           [:paragraph, "# Getting Started with YARD", 4]]
        )
      end

      it "terminates header block by markup line not at the first line" do
        text = <<-eot
# @title Getting Started Guide
#!markdown

# Getting Started with YARD
eot
        expect(extract_messages(text, :have_header => true)).to eq(
          [[:attribute, "title", "Getting Started Guide", 1],
           [:paragraph, "#!markdown", 2],
           [:paragraph, "# Getting Started with YARD", 4]]
        )
      end
    end

    describe "Body" do
      it "splits to paragraphs" do
        paragraph1 = <<-eop.strip
Note that class methods must not be referred to with the "::" namespace
separator. Only modules, classes and constants should use "::".
eop
        paragraph2 = <<-eop.strip
You can also do lookups on any installed gems. Just make sure to build the
.yardoc databases for installed gems with:
eop
        text = <<-eot
#{paragraph1}

#{paragraph2}
eot
        expect(extract_messages(text)).to eq(
          [[:paragraph, paragraph1, 1],
           [:paragraph, paragraph2, 4]]
        )
      end
    end
  end

  describe "#translate" do
    def locale
      locale = YARD::I18n::Locale.new("fr")
      messages = locale.instance_variable_get(:@messages)
      messages["markdown"] = "markdown (markdown in fr)"
      messages["Hello"] = "Bonjour (Hello in fr)"
      messages["Paragraph 1."] = "Paragraphe 1."
      messages["Paragraph 2."] = "Paragraphe 2."
      locale
    end

    def translate(input, options = {})
      text = YARD::I18n::Text.new(StringIO.new(input), options)
      text.translate(locale)
    end

    describe "Header" do
      it "extracts at attribute" do
        text = <<-eot
# @title Hello

# Getting Started with YARD

Paragraph.
eot
        expect(translate(text, :have_header => true)).to eq <<-eot
# @title Bonjour (Hello in fr)

# Getting Started with YARD

Paragraph.
eot
      end

      it "ignores markup line" do
        text = <<-eot
#!markdown
# @title Hello

# Getting Started with YARD

Paragraph.
eot
        expect(translate(text, :have_header => true)).to eq <<-eot
#!markdown
# @title Bonjour (Hello in fr)

# Getting Started with YARD

Paragraph.
eot
      end
    end

    describe "Body" do
      it "splits to paragraphs" do
        paragraph1 = <<-eop.strip
Paragraph 1.
eop
        paragraph2 = <<-eop.strip
Paragraph 2.
eop
        text = <<-eot
#{paragraph1}

#{paragraph2}
eot
        expect(translate(text)).to eq <<-eot
Paragraphe 1.

Paragraphe 2.
eot
      end

      it "does not modify non-translated message" do
        nonexistent_paragraph = <<-eop.strip
Nonexsitent paragraph.
eop
        text = <<-eot
#{nonexistent_paragraph}
eot
        expect(translate(text)).to eq <<-eot
#{nonexistent_paragraph}
eot
      end

      it "keeps empty lines" do
        text = <<-eot
Paragraph 1.




Paragraph 2.
eot
        expect(translate(text)).to eq <<-eot
Paragraphe 1.




Paragraphe 2.
eot
      end
    end
  end
end
