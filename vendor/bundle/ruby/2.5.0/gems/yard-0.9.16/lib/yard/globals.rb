# frozen_string_literal: true
# @group Global Convenience Methods

# Shortcut for creating a YARD::CodeObjects::Proxy via a path
#
# @see YARD::CodeObjects::Proxy
# @see YARD::Registry.resolve
def P(namespace, name = nil, type = nil) # rubocop:disable Style/MethodName
  if name.nil?
    name = namespace
    namespace = nil
  end
  YARD::Registry.resolve(namespace, name, false, true, type)
end

# The global {YARD::Logger} instance
#
# @return [YARD::Logger] the global {YARD::Logger} instance
# @see YARD::Logger
def log
  YARD::Logger.instance
end
