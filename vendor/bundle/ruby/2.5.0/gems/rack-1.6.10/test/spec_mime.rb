require 'rack/mime'

describe Rack::Mime do

  it "should return the fallback mime-type for files with no extension" do
    fallback = 'image/jpg'
    Rack::Mime.mime_type(File.extname('no_ext'), fallback).should.equal fallback
  end

  it "should always return 'application/octet-stream' for unknown file extensions" do
    unknown_ext = File.extname('unknown_ext.abcdefg')
    Rack::Mime.mime_type(unknown_ext).should.equal 'application/octet-stream'
  end

  it "should return the mime-type for a given extension" do
    # sanity check. it would be infeasible test every single mime-type.
    Rack::Mime.mime_type(File.extname('image.jpg')).should.equal 'image/jpeg'
  end

  it "should support null fallbacks" do
    Rack::Mime.mime_type('.nothing', nil).should.equal nil
  end

  it "should match exact mimes" do
    Rack::Mime.match?('text/html', 'text/html').should.equal true
    Rack::Mime.match?('text/html', 'text/meme').should.equal false
    Rack::Mime.match?('text', 'text').should.equal true
    Rack::Mime.match?('text', 'binary').should.equal false
  end

  it "should match class wildcard mimes" do
    Rack::Mime.match?('text/html', 'text/*').should.equal true
    Rack::Mime.match?('text/plain', 'text/*').should.equal true
    Rack::Mime.match?('application/json', 'text/*').should.equal false
    Rack::Mime.match?('text/html', 'text').should.equal true
  end

  it "should match full wildcards" do
    Rack::Mime.match?('text/html', '*').should.equal true
    Rack::Mime.match?('text/plain', '*').should.equal true
    Rack::Mime.match?('text/html', '*/*').should.equal true
    Rack::Mime.match?('text/plain', '*/*').should.equal true
  end

  it "should match type wildcard mimes" do
    Rack::Mime.match?('text/html', '*/html').should.equal true
    Rack::Mime.match?('text/plain', '*/plain').should.equal true
  end

end

