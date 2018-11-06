begin
  require 'capybara/rspec'
rescue LoadError
end

begin
  require 'capybara/rails'
rescue LoadError
end

if defined?(Capybara)
  require 'rspec/support/comparable_version'
  unless RSpec::Support::ComparableVersion.new(Capybara::VERSION) >= '2.2.0'
    raise "You are using capybara #{Capybara::VERSION}. RSpec requires >= 2.2.0."
  end

  RSpec.configure do |c|
    if defined?(Capybara::DSL)
      c.include Capybara::DSL, :type => :feature
      if defined?(ActionPack) && ActionPack::VERSION::STRING >= "5.1"
        c.include Capybara::DSL, :type => :system
      end
    end

    if defined?(Capybara::RSpecMatchers)
      c.include Capybara::RSpecMatchers, :type => :view
      c.include Capybara::RSpecMatchers, :type => :helper
      c.include Capybara::RSpecMatchers, :type => :mailer
      c.include Capybara::RSpecMatchers, :type => :controller
      c.include Capybara::RSpecMatchers, :type => :feature
      c.include Capybara::RSpecMatchers, :type => :system
    end

    unless defined?(Capybara::RSpecMatchers) || defined?(Capybara::DSL)
      c.include Capybara, :type => :request
      c.include Capybara, :type => :controller
    end
  end
end
