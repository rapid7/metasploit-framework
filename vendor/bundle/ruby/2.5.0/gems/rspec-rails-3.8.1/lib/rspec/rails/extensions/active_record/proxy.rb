RSpec.configure do |rspec|
  # Delay this in order to give users a chance to configure `expect_with`...
  rspec.before(:suite) do
    if defined?(RSpec::Matchers) && RSpec::Matchers.configuration.syntax.include?(:should) && defined?(ActiveRecord::Associations)
      # In Rails 3.0, it was AssociationProxy.
      # In 3.1+, it's CollectionProxy.
      const_name = [:CollectionProxy, :AssociationProxy].find do |const|
        ActiveRecord::Associations.const_defined?(const)
      end

      proxy_class = ActiveRecord::Associations.const_get(const_name)

      RSpec::Matchers.configuration.add_should_and_should_not_to proxy_class
    end
  end
end
