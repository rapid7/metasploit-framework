require 'sinatra'
require 'rack/cache'

use Rack::Cache do
  set :verbose, true
  set :metastore,   'heap:/'
  set :entitystore, 'heap:/'
end

before do
  last_modified $updated_at ||= Time.now
end

get '/' do
  erb :index
end

put '/' do
  $updated_at = nil
  redirect '/'
end
