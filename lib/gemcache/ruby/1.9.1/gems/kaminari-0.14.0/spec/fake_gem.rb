# Simulate a gem providing a subclass of ActiveRecord::Base before the Railtie is loaded.

class GemDefinedModel < ActiveRecord::Base
end
