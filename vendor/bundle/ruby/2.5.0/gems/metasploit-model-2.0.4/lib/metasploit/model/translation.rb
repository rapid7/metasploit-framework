# ActiveRecord::Translation is a dirty bastard and overrides `ActiveModel::Translation#lookup_ancestors`, so that it
# will only count superclasses, and not all ancestors.  Metasploit::Model needs the original behavior so that its
# {Metasploit::Model::Module} modules can supply translations to both `ActiveRecord::Base` descendants in `Mdm` and
# `ActiveModel` descendants in `Metasploit::Framework`
#
# @see https://github.com/rails/rails/issues/11409
module Metasploit::Model::Translation
  extend ActiveSupport::Concern

  # Adds {#lookup_ancestors} and {#i18n_scope} so that {Metasploit::Model} modules can participate in translation
  # lookups.
  module ClassMethods
    # When localizing a string, it goes through the lookup returned by this method, which is used in
    # ActiveModel::Name#human, # ActiveModel::Errors#full_messages and ActiveModel::Translation#human_attribute_name.
    #
    # @return [Array<Module>] Array of `Class#ancestors` that respond to `module_name`.
    def lookup_ancestors
      self.ancestors.select { |ancestor|
        ancestor.respond_to?(:model_name)
      }
    end

    # Classes that include a metasploit-model are trying to share code between ActiveRecord and ActiveModel, so the scope
    # should be neither 'activerecord' nor 'activemodel'.
    #
    # @return [String] `'metasploit.model'`
    def i18n_scope
      'metasploit.model'
    end
  end
end