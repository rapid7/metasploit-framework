require 'rack/lobster'

use Rack::ShowExceptions
use Rack::Auth::Basic, "Lobster 2.0" do |username, password|
  'secret' == password
end

run Rack::Lobster.new
