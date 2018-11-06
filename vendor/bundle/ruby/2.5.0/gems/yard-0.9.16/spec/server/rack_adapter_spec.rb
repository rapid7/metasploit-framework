# frozen_string_literal: true
require File.dirname(__FILE__) + "/spec_helper"

RSpec.describe "YARD::Server::RackMiddleware" do
  before do
    begin; require 'rack'; rescue LoadError; pending "rack required for these tests" end
    @superapp = double(:superapp)
    @app = YARD::Server::RackMiddleware.new(@superapp, :libraries => {'foo' => [LibraryVersion.new('foo', nil)]})
  end

  after(:all) { YARD::Server::Adapter.shutdown }

  it "handles requests" do
    expect(@app.call(Rack::MockRequest.env_for('/'))[0]).to eq 200
  end

  it "passes up to the next middleware on 404" do
    expect(@superapp).to receive(:call).and_return([200, {}, ['OK']])
    expect(@app.call(Rack::MockRequest.env_for('/INVALID'))).to eq [200, {}, ['OK']]
  end
end
