require 'fiddle'
Fiddle.const_set(:VERSION, '0.0.0') unless Fiddle.const_defined?(:VERSION)

require 'rails'
require File.expand_path('../boot', __FILE__)

require 'action_view'
# Monkey patch https://github.com/rails/rails/blob/v7.2.2.1/actionview/lib/action_view/helpers/tag_helper.rb#L51
# Might be fixed by 8.x https://github.com/rails/rails/blob/v8.0.2/actionview/lib/action_view/helpers/tag_helper.rb#L51C1-L52C1
raise unless ActionView::VERSION::STRING == '7.2.2.2' # A developer will need to ensure this is still required when bumping rails
module ActionView::Helpers::TagHelper
  class TagBuilder
    def self.define_element(name, code_generator:, method_name: name.to_s.underscore)
      code_generator.define_cached_method(method_name, namespace: :tag_builder) do |batch|
        # Fixing a bug introduced by Metasploit's global Kernel patch: https://github.com/rapid7/metasploit-framework/blob/ae1db09f32cd04c007dbf445cf16dc22c9fc2e53/lib/rex.rb#L74-L79
        # which fails when using the below 'instance_methods.include?(method_name.to_sym)' check
        batch.push(<<~RUBY) # unless instance_methods.include?(method_name.to_sym)
              def #{method_name}(content = nil, escape: true, **options, &block)
                tag_string("#{name}", content, options, escape: escape, &block)
              end
            RUBY
      end
    end
  end
end

all_environments = [
    :development,
    :production,
    :test
]

Bundler.require(
    *Rails.groups(
        coverage: [:test],
        db: all_environments,
        pcap: all_environments
    )
)

#
# Railties
#

# For compatibility with jquery-rails (and other engines that need action_view) in pro
require 'action_controller/railtie'
require 'action_view/railtie'

#
# Project
#

require 'metasploit/framework/common_engine'
require 'metasploit/framework/database'
module Metasploit
  module Framework
    class Application < Rails::Application
      include Metasploit::Framework::CommonEngine

      config.paths['log']             = "#{Msf::Config.log_directory}/#{Rails.env}.log"
      config.paths['config/database'] = [Metasploit::Framework::Database.configurations_pathname.try(:to_path)]
      config.autoloader = :zeitwerk

      config.load_defaults 7.2

      config.eager_load = false
    end
  end
end

# Silence warnings about this defaulting to true
I18n.enforce_available_locales = true
require 'msfenv'
