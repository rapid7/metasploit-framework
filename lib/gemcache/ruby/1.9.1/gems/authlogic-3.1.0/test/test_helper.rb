require "test/unit"
require "rubygems"
require "ruby-debug"
require "active_record"
require "active_record/fixtures"

#ActiveRecord::Schema.verbose = false
ActiveRecord::Base.establish_connection(:adapter => "sqlite3", :database => ":memory:")
logger = Logger.new(STDOUT)
logger.level= Logger::FATAL
ActiveRecord::Base.logger = logger

ActiveRecord::Base.configurations = true
ActiveRecord::Schema.define(:version => 1) do
  create_table :companies do |t|
    t.datetime  :created_at
    t.datetime  :updated_at
    t.string    :name
    t.boolean   :active
  end

  create_table :projects do |t|
    t.datetime  :created_at
    t.datetime  :updated_at
    t.string    :name
  end

  create_table :projects_users, :id => false do |t|
    t.integer :project_id
    t.integer :user_id
  end

  create_table :users do |t|
    t.datetime  :created_at
    t.datetime  :updated_at
    t.integer   :lock_version, :default => 0
    t.integer   :company_id
    t.string    :login
    t.string    :crypted_password
    t.string    :password_salt
    t.string    :persistence_token
    t.string    :single_access_token
    t.string    :perishable_token
    t.string    :email
    t.string    :first_name
    t.string    :last_name
    t.integer   :login_count, :default => 0, :null => false
    t.integer   :failed_login_count, :default => 0, :null => false
    t.datetime  :last_request_at
    t.datetime  :current_login_at
    t.datetime  :last_login_at
    t.string    :current_login_ip
    t.string    :last_login_ip
    t.boolean   :active, :default => true
    t.boolean   :approved, :default => true
    t.boolean   :confirmed, :default => true
  end

  create_table :employees do |t|
    t.datetime  :created_at
    t.datetime  :updated_at
    t.integer   :company_id
    t.string    :email
    t.string    :crypted_password
    t.string    :password_salt
    t.string    :persistence_token
    t.string    :first_name
    t.string    :last_name
    t.integer   :login_count, :default => 0, :null => false
    t.datetime  :last_request_at
    t.datetime  :current_login_at
    t.datetime  :last_login_at
    t.string    :current_login_ip
    t.string    :last_login_ip
  end

  create_table :affiliates do |t|
    t.datetime  :created_at
    t.datetime  :updated_at
    t.integer   :company_id
    t.string    :username
    t.string    :pw_hash
    t.string    :pw_salt
    t.string    :persistence_token
  end

  create_table :ldapers do |t|
    t.datetime  :created_at
    t.datetime  :updated_at
    t.string    :ldap_login
    t.string    :persistence_token
  end
end

require File.dirname(__FILE__) + '/../lib/authlogic' unless defined?(Authlogic)
require File.dirname(__FILE__) + '/../lib/authlogic/test_case'
require File.dirname(__FILE__) + '/libs/project'
require File.dirname(__FILE__) + '/libs/affiliate'
require File.dirname(__FILE__) + '/libs/employee'
require File.dirname(__FILE__) + '/libs/employee_session'
require File.dirname(__FILE__) + '/libs/ldaper'
require File.dirname(__FILE__) + '/libs/user'
require File.dirname(__FILE__) + '/libs/user_session'
require File.dirname(__FILE__) + '/libs/company'

Authlogic::CryptoProviders::AES256.key = "myafdsfddddddddddddddddddddddddddddddddddddddddddddddd"

class ActiveSupport::TestCase
  include ActiveRecord::TestFixtures
  self.fixture_path = File.dirname(__FILE__) + "/fixtures"
  self.use_transactional_fixtures = false
  self.use_instantiated_fixtures  = false
  self.pre_loaded_fixtures = false
  fixtures :all
  setup :activate_authlogic

  private
    def password_for(user)
      case user
      when users(:ben)
        "benrocks"
      when users(:zack)
        "zackrocks"
      end
    end

    def http_basic_auth_for(user = nil, &block)
      unless user.blank?
        controller.http_user = user.login
        controller.http_password = password_for(user)
      end
      yield
      controller.http_user = controller.http_password = controller.realm = nil
    end

    def set_cookie_for(user, id = nil)
      controller.cookies["user_credentials"] = {:value => user.persistence_token, :expires => nil}
    end

    def unset_cookie
      controller.cookies["user_credentials"] = nil
    end

    def set_params_for(user, id = nil)
      controller.params["user_credentials"] = user.single_access_token
    end

    def unset_params
      controller.params["user_credentials"] = nil
    end

    def set_request_content_type(type)
      controller.request_content_type = type
    end

    def unset_request_content_type
      controller.request_content_type = nil
    end

    def set_session_for(user, id = nil)
      controller.session["user_credentials"] = user.persistence_token
      controller.session["user_credentials_id"] = user.id
    end

    def unset_session
      controller.session["user_credentials"] = controller.session["user_credentials_id"] = nil
    end
end
