# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::Handlers::Processor do
  before do
    @proc = Handlers::Processor.new(OpenStruct.new(:parser_type => :ruby))
  end

  it "starts with public visibility" do
    expect(@proc.visibility).to eq :public
  end

  it "starts in instance scope" do
    expect(@proc.scope).to eq :instance
  end

  it "starts in root namespace" do
    expect(@proc.namespace).to eq Registry.root
  end

  it "has a globals structure" do
    expect(@proc.globals).to be_a(OpenStruct)
  end

  it "ignores HandlerAborted exceptions (but print debug info)" do
    class AbortHandlerProcessor < YARD::Handlers::Ruby::Base
      process { abort! }
    end
    stmt = OpenStruct.new(:line => 1, :show => 'SOURCE')
    allow(@proc).to receive(:find_handlers).and_return([AbortHandlerProcessor])
    expect(log).to receive(:debug).with(/AbortHandlerProcessor cancelled from/)
    expect(log).to receive(:debug).with("\tin file '(stdin)':1:\n\nSOURCE\n")
    @proc.process([stmt])
  end
end
