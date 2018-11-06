# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::Server::WebrickServlet do
  describe "#do_GET" do
    it "performs a GET" do
      resp = OpenStruct.new
      class << resp
        def []=(name, value) (self.headers ||= {})[name] = value end
      end
      server = double(:server, :[] => nil)
      adapter = mock_adapter
      adapter.router = proc { [200, {'Header' => 'foo'}, ['body']] }
      WebrickServlet.new(server, adapter).do_GET(mock_request('/foo'), resp)
      expect(resp.status).to eq 200
      expect(resp.headers).to eq('Header' => 'foo')
      expect(resp.body).to eq 'body'
    end
  end
end
