# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::Server::Adapter do
  after(:all) { Server::Adapter.shutdown }

  describe "#add_library" do
    it "adds a library" do
      lib = LibraryVersion.new('yard')
      a = Adapter.new({})
      expect(a.libraries).to be_empty
      a.add_library(lib)
      expect(a.libraries['yard']).to eq [lib]
    end
  end

  describe "#start" do
    it "does not implement #start" do
      expect { Adapter.new({}).start }.to raise_error(NotImplementedError)
    end
  end

  describe ".setup" do
    it "adds template paths and helpers" do
      Adapter.setup
      expect(Templates::Template.extra_includes).to include(DocServerHelper)
      expect(Templates::Engine.template_paths).to include(YARD::ROOT + '/yard/server/templates')
    end
  end

  describe ".shutdown" do
    it "cleans up template paths and helpers" do
      Adapter.setup
      Adapter.shutdown
      expect(Templates::Template.extra_includes).not_to include(DocServerHelper)
      expect(Templates::Engine.template_paths).not_to include(YARD::ROOT + '/yard/server/templates')
    end
  end
end
