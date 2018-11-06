# frozen_string_literal: true

module YARD::Templates::Helpers::MarkupHelper
  public :load_markup_provider, :markup_class, :markup_provider
end

class GeneratorMock
  attr_accessor :options
  include YARD::Templates::Helpers::MarkupHelper
  def initialize(options = Templates::TemplateOptions.new)
    self.options = options
  end
end

RSpec.describe YARD::Templates::Helpers::MarkupHelper do
  before do
    YARD::Templates::Helpers::MarkupHelper.clear_markup_cache
  end

  describe "#load_markup_provider" do
    before do
      allow(log).to receive(:error)
      @gen = GeneratorMock.new
      @gen.options.reset_defaults
    end

    it "exits on an invalid markup type" do
      @gen.options.markup = :invalid
      expect(@gen.load_markup_provider).to be false
    end

    it "fails when an invalid markup provider is specified" do
      @gen.options.update(:markup => :markdown, :markup_provider => :invalid)
      expect(@gen.load_markup_provider).to be false
      expect(@gen.markup_class).to eq nil
    end

    it "loads RDocMarkup if rdoc is specified and it is installed" do
      @gen.options.markup = :rdoc
      expect(@gen.load_markup_provider).to be true
      expect(@gen.markup_class).to eq YARD::Templates::Helpers::Markup::RDocMarkup
    end

    it "fails if RDoc cannot be loaded" do
      @gen.options.markup = :rdoc
      expect(@gen).to receive(:eval).with('::YARD::Templates::Helpers::Markup::RDocMarkup').and_raise(NameError)
      expect(@gen.load_markup_provider).to be false
      expect(@gen.markup_provider).to eq nil
    end

    it "searches through available markup providers for the markup type if none is set" do
      expect(@gen).to receive(:eval).with('::RedcarpetCompat').and_return(double(:bluecloth))
      expect(@gen).to receive(:require).with('redcarpet').and_return(true)
      expect(@gen).not_to receive(:require).with('maruku')
      @gen.options.markup = :markdown
      # this only raises an exception because we mock out require to avoid
      # loading any libraries but our implementation tries to return the library
      # name as a constant
      expect(@gen.load_markup_provider).to be true
      expect(@gen.markup_provider).to eq :redcarpet
    end

    it "continues searching if some of the providers are unavailable" do
      expect(@gen).to receive(:require).with('redcarpet').and_raise(LoadError)
      expect(@gen).to receive(:require).with('rdiscount').and_raise(LoadError)
      expect(@gen).to receive(:require).with('kramdown').and_raise(LoadError)
      expect(@gen).to receive(:require).with('bluecloth').and_raise(LoadError)
      expect(@gen).to receive(:require).with('maruku').and_raise(LoadError)
      expect(@gen).to receive(:require).with('rpeg-markdown').and_return(true)
      expect(@gen).to receive(:eval).with('::PEGMarkdown').and_return(true)
      @gen.options.markup = :markdown
      # this only raises an exception because we mock out require to avoid
      # loading any libraries but our implementation tries to return the library
      # name as a constant
      @gen.load_markup_provider
      expect(@gen.markup_provider).to eq :"rpeg-markdown"
    end

    it "overrides the search if `:markup_provider` is set in options" do
      expect(@gen).to receive(:require).with('rdiscount').and_return(true)
      expect(@gen).to receive(:eval).with('::RDiscount').and_return(true)
      @gen.options.update(:markup => :markdown, :markup_provider => :rdiscount)
      @gen.load_markup_provider
      expect(@gen.markup_provider).to eq :rdiscount
    end

    it "fails if no provider is found" do
      YARD::Templates::Helpers::MarkupHelper::MARKUP_PROVIDERS[:markdown].each do |p|
        expect(@gen).to receive(:require).with(p[:lib].to_s).and_raise(LoadError)
      end
      @gen.options.markup = :markdown
      expect(@gen.load_markup_provider).to be false
      expect(@gen.markup_provider).to eq nil
    end

    it "fails if overridden provider is not found" do
      expect(@gen).to receive(:require).with('rdiscount').and_raise(LoadError)
      @gen.options.update(:markup => :markdown, :markup_provider => :rdiscount)
      expect(@gen.load_markup_provider).to be false
      expect(@gen.markup_provider).to eq nil
    end

    it "fails if the markup type is not found" do
      expect(log).to receive(:error).with(/Invalid markup/)
      @gen.options.markup = :xxx
      expect(@gen.load_markup_provider).to be false
      expect(@gen.markup_provider).to eq nil
    end
  end

  describe "#markup_for_file" do
    include YARD::Templates::Helpers::MarkupHelper

    it "looks for a shebang line" do
      expect(markup_for_file("#!text\ntext here", 'file.rdoc')).to eq :text
    end

    it "returns the default markup type if no shebang is found or no valid ext is found" do
      allow(self).to receive(:options).and_return(Options.new.update(:markup => :default_type))
      expect(markup_for_file('', 'filename')).to eq :default_type
    end

    it "looks for a file extension if no shebang is found" do
      expect(markup_for_file('', 'filename.MD')).to eq :markdown
      expect(markup_for_file('', 'filename.ORG')).to eq :org
    end

    Templates::Helpers::MarkupHelper::MARKUP_EXTENSIONS.each do |type, exts|
      exts.each do |ext|
        it "recognizes .#{ext} as #{type} markup type" do
          expect(markup_for_file('', "filename.#{ext}")).to eq type
        end
      end
    end
  end
end
