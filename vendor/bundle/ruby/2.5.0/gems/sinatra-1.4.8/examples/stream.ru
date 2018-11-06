# this example does *not* work properly with WEBrick
#
# run *one* of these:
#
#   rackup -s mongrel stream.ru   # gem install mongrel
#   thin -R stream.ru start       # gem install thin
#   unicorn stream.ru             # gem install unicorn
#   puma stream.ru                # gem install puma

require 'sinatra/base'

class Stream < Sinatra::Base
  get '/' do
    content_type :txt

    stream do |out|
      out << "It's gonna be legen -\n"
      sleep 0.5
      out << " (wait for it) \n"
      sleep 1
      out << "- dary!\n"
    end
  end
end

run Stream
