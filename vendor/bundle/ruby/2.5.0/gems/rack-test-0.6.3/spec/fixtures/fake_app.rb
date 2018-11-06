require "rubygems"
require "sinatra/base"

module Rack
  module Test

    class FakeApp < Sinatra::Base
      head "/" do
        "meh"
      end

      options "/" do
        [200, {}, ""]
      end

      get "/" do
        "Hello, GET: #{params.inspect}"
      end

      get "/redirect" do
        redirect "/redirected"
      end

      get "/redirected" do
        "You've been redirected"
      end

      get "/void" do
        [200, {}, ""]
      end

      get "/cookies/show" do
        request.cookies.inspect
      end

      get "/COOKIES/show" do
        request.cookies.inspect
      end

      get "/not-cookies/show" do
        request.cookies.inspect
      end

      get "/cookies/set-secure" do
        raise if params["value"].nil?

        response.set_cookie("secure-cookie", :value => params["value"], :secure => true)
        "Set"
      end

      get "/cookies/set-simple" do
        raise if params["value"].nil?

        response.set_cookie "simple", params["value"]
        "Set"
      end

      post "/cookies/default-path" do
        raise if params["value"].nil?

        response.set_cookie "simple", params["value"]
        "Set"
      end

      get "/cookies/default-path" do
        response.cookies.inspect
      end

      get "/cookies/delete" do
        response.delete_cookie "value"
      end

      get "/cookies/count" do
        old_value = request.cookies["count"].to_i || 0
        new_value = (old_value + 1).to_s

        response.set_cookie("count", :value => new_value)
        new_value
      end

      get "/cookies/set" do
        raise if params["value"].nil?

        response.set_cookie("value", {
          :value => params["value"],
          :path => "/cookies",
          :expires => Time.now + 10
        })
        "Set"
      end

      get "/cookies/domain" do
        old_value = request.cookies["count"].to_i || 0
        new_value = (old_value + 1).to_s

        response.set_cookie("count", :value => new_value, :domain => "localhost.com")
        new_value
      end

      get "/cookies/subdomain" do
        old_value = request.cookies["count"].to_i || 0
        new_value = (old_value + 1).to_s

        response.set_cookie("count", :value => new_value, :domain => ".example.org")
        new_value
      end

      get "/cookies/set-uppercase" do
        raise if params["value"].nil?

        response.set_cookie("VALUE", {
          :value => params["value"],
          :path => "/cookies",
          :expires => Time.now + 10
        })
        "Set"
      end

      get "/cookies/set-multiple" do
        response.set_cookie("key1", :value => "value1")
        response.set_cookie("key2", :value => "value2")
        "Set"
      end

      post "/" do
        "Hello, POST: #{params.inspect}"
      end

      put "/" do
        "Hello, PUT: #{params.inspect}"
      end

      patch "/" do
        "Hello, PUT: #{params.inspect}"
      end

      delete "/" do
        "Hello, DELETE: #{params.inspect}"
      end
    end

  end
end
