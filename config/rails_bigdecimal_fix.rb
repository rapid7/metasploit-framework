# Remove bigdecimal warning - start
# https://github.com/ruby/bigdecimal/pull/115
# https://github.com/rapid7/metasploit-framework/pull/11184#issuecomment-461971266
# TODO: remove when upgrading from rails 4.x
require 'bigdecimal'

def BigDecimal.new(*args, **kwargs)
  return BigDecimal(*args) if kwargs.empty?
  BigDecimal(*args, **kwargs)
end
# Remove bigdecimal warning - end
