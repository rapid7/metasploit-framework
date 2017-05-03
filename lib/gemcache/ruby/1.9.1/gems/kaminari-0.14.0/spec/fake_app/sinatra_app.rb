require 'fake_app/active_record/config' if defined? ActiveRecord
require 'fake_app/data_mapper/config' if defined? DataMapper
require 'fake_app/mongoid/config' if defined? Mongoid
require 'fake_app/mongo_mapper/config' if defined? MongoMapper

#models
require 'fake_app/active_record/models' if defined? ActiveRecord
require 'fake_app/data_mapper/models' if defined? DataMapper
require 'fake_app/mongoid/models' if defined? Mongoid
require 'fake_app/mongo_mapper/models' if defined? MongoMapper

class SinatraApp < Sinatra::Base
  register Kaminari::Helpers::SinatraHelpers

  get '/users' do
    @users = User.page params[:page]
    erb <<-ERB
<%= @users.map(&:name).join("\n") %>
<%= paginate @users %>
ERB
  end
end
