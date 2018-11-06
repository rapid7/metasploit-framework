# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::Templates::Engine do
  before { @paths = Engine.template_paths }
  after { Engine.template_paths = @paths }

  describe ".register_template_path" do
    it "registers a String path" do
      Engine.register_template_path('.')
      expect(Engine.template_paths.pop).to eq '.'
    end

    it "does not duplicate paths" do
      Engine.template_paths = []
      Engine.register_template_path('foo')
      Engine.register_template_path('foo')
      expect(Engine.template_paths).to eq ['foo']
    end
  end

  describe ".template!" do
    it "creates a module including Template" do
      mod = Engine.template!('path/to/template')
      expect(mod).to include(Template)
      expect(mod.full_path.to_s).to eq 'path/to/template'
    end

    it "creates a module including Template with full_path" do
      mod = Engine.template!('path/to/template2', '/full/path/to/template2')
      expect(mod).to include(Template)
      expect(mod.full_path.to_s).to eq '/full/path/to/template2'
    end
  end

  describe ".template" do
    it "raises an error if the template is not found" do
      expect { Engine.template(:a, :b, :c) }.to raise_error(ArgumentError)
    end

    it "creates a module including Template" do
      mock = double(:template)
      expect(Engine).to receive(:find_template_paths).with(nil, 'template/name').and_return(['/full/path/template/name'])
      expect(Engine).to receive(:template!).with('template/name', ['/full/path/template/name']).and_return(mock)
      expect(Engine.template('template/name')).to eq mock
    end

    it "creates a Template from a relative Template path" do
      expect(Engine).to receive(:template_paths).and_return([])
      expect(File).to receive(:directory?).with("/full/path/template/notname").and_return(true)
      start_template = double(:start_template,
        :full_path  => '/full/path/template/name',
        :full_paths => ['/full/path/template/name'])
      expect(start_template).to receive(:is_a?).with(Template).and_return(true)
      mod = Engine.template(start_template, '..', 'notname')
      expect(mod).to include(Template)
      expect(mod.full_path.to_s).to eq "/full/path/template/notname"
    end

    it "creates a Template including other matching templates in path" do
      paths = ['/full/path/template/name', '/full/path2/template/name']
      expect(Engine).to receive(:find_template_paths).with(nil, 'template').at_least(1).times.and_return([])
      expect(Engine).to receive(:find_template_paths).with(nil, 'template/name').and_return(paths)
      ancestors = Engine.template('template/name').ancestors.map(&:class_name)
      expect(ancestors).to include("Template__full_path2_template_name")
    end

    it "includes parent directories before other template paths" do
      paths = ['/full/path/template/name', '/full/path2/template/name']
      expect(Engine).to receive(:find_template_paths).with(nil, 'template/name').and_return(paths)
      ancestors = Engine.template('template/name').ancestors.map(&:class_name)
      expect(ancestors[0, 4]).to eq ["Template__full_path_template_name", "Template__full_path_template",
        "Template__full_path2_template_name", "Template__full_path2_template"]
    end
  end

  describe ".generate" do
    it "generates with fulldoc template" do
      mod = double(:template)
      options = TemplateOptions.new
      options.reset_defaults
      options.objects = [:a, :b, :c]
      options.object = Registry.root
      expect(mod).to receive(:run).with(options)
      expect(Engine).to receive(:template).with(:default, :fulldoc, :text).and_return(mod)
      Engine.generate([:a, :b, :c])
    end
  end

  describe ".render" do
    def loads_template(*args)
      expect(Engine).to receive(:template).with(*args).and_return(@template)
    end

    before(:all) do
      @object = CodeObjects::MethodObject.new(:root, :method)
    end

    before do
      @options = TemplateOptions.new
      @options.reset_defaults
      @options.object = @object
      @options.type = @object.type
      @template = double(:template, :include => nil)
      expect(@template).to receive(:run).with(@options)
    end

    it "accepts method call with no parameters" do
      loads_template(:default, :method, :text)
      @object.format
    end

    it "allows template key to be changed" do
      loads_template(:javadoc, :method, :text)
      @options.template = :javadoc
      @object.format(:template => :javadoc)
    end

    it "allows type key to be changed" do
      loads_template(:default, :fulldoc, :text)
      @options.type = :fulldoc
      @object.format(:type => :fulldoc)
    end

    it "allows format key to be changed" do
      loads_template(:default, :method, :html)
      @options.format = :html
      @object.format(:format => :html)
    end
  end
end
