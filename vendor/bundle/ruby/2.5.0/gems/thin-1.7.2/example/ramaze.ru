# Ramaze Rackup config file.
# by tmm1
# Use with --rackup option:
# 
#   thin start -r ramaze.ru
# 
require 'start'

Ramaze.trait[:essentials].delete Ramaze::Adapter
Ramaze.start :force => true

run Ramaze::Adapter::Base
