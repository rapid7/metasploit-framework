require 'fiddle'
Fiddle.const_set(:VERSION, '0.0.0') unless Fiddle.const_defined?(:VERSION)

require 'rails'
require File.expand_path('../boot', __FILE__)

require 'action_view'
# Monkey patch https://github.com/rails/rails/blob/v8.0.5/actionview/lib/action_view/helpers/tag_helper.rb#L51
# Last verified against ActionView 8.0.5 — re-check if this patch is still needed on 8.1+
raise "ActionView version mismatch: expected 8.0.x, got #{ActionView::VERSION::STRING}" unless ActionView::VERSION::STRING.start_with?('8.0.')
module ActionView::Helpers::TagHelper
  class TagBuilder
    def self.define_element(name, code_generator:, method_name: name)
      # Removed 'return if method_defined?(name)' guard that conflicts with
      # Metasploit's Kernel select patch (rex.rb adds select to Kernel)
      code_generator.class_eval do |batch|
        batch << "\n" <<
          "def #{method_name}(content = nil, escape: true, **options, &block)" <<
          "  tag_string(#{name.inspect}, content, options, escape: escape, &block)" <<
          "end"
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

      config.load_defaults 8.0

      config.eager_load = false
    end
  end
end

# Silence warnings about this defaulting to true
I18n.enforce_available_locales = true
require 'msfenv'
