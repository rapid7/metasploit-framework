# encoding: UTF-8
require File.expand_path('../helper', __FILE__)
require 'erb'

class BaseTest < Minitest::Test
  setup do
    @base = Sinatra.new(Sinatra::Base)
    @base.set :views, File.dirname(__FILE__) + "/views"
  end

  it 'allows unicode strings in ascii templates per default (1.9)' do
    next unless defined? Encoding
    @base.new!.erb(File.read(@base.views + "/ascii.erb").encode("ASCII"), {}, :value => "åkej")
  end

  it 'allows ascii strings in unicode templates per default (1.9)' do
    next unless defined? Encoding
    @base.new!.erb(:utf8, {}, :value => "Some Lyrics".encode("ASCII"))
  end
end
