# Load each available integration
require 'state_machine/integrations/base'
Dir["#{File.dirname(__FILE__)}/integrations/*.rb"].sort.each do |path|
  require "state_machine/integrations/#{File.basename(path)}"
end

require 'state_machine/error'

module StateMachine
  # An invalid integration was specified
  class IntegrationNotFound < Error
    def initialize(name)
      super(nil, "#{name.inspect} is an invalid integration")
    end
  end
  
  # Integrations allow state machines to take advantage of features within the
  # context of a particular library.  This is currently most useful with
  # database libraries.  For example, the various database integrations allow
  # state machines to hook into features like:
  # * Saving
  # * Transactions
  # * Observers
  # * Scopes
  # * Callbacks
  # * Validation errors
  # 
  # This type of integration allows the user to work with state machines in a
  # fashion similar to other object models in their application.
  # 
  # The integration interface is loosely defined by various unimplemented
  # methods in the StateMachine::Machine class.  See that class or the various
  # built-in integrations for more information about how to define additional
  # integrations.
  module Integrations
    # Attempts to find an integration that matches the given class.  This will
    # look through all of the built-in integrations under the StateMachine::Integrations
    # namespace and find one that successfully matches the class.
    # 
    # == Examples
    # 
    #   class Vehicle
    #   end
    #   
    #   class ActiveModelVehicle
    #     include ActiveModel::Observing
    #     include ActiveModel::Validations
    #   end
    #   
    #   class ActiveRecordVehicle < ActiveRecord::Base
    #   end
    #   
    #   class DataMapperVehicle
    #     include DataMapper::Resource
    #   end
    #   
    #   class MongoidVehicle
    #     include Mongoid::Document
    #   end
    #   
    #   class MongoMapperVehicle
    #     include MongoMapper::Document
    #   end
    #   
    #   class SequelVehicle < Sequel::Model
    #   end
    #   
    #   StateMachine::Integrations.match(Vehicle)             # => nil
    #   StateMachine::Integrations.match(ActiveModelVehicle)  # => StateMachine::Integrations::ActiveModel
    #   StateMachine::Integrations.match(ActiveRecordVehicle) # => StateMachine::Integrations::ActiveRecord
    #   StateMachine::Integrations.match(DataMapperVehicle)   # => StateMachine::Integrations::DataMapper
    #   StateMachine::Integrations.match(MongoidVehicle)      # => StateMachine::Integrations::Mongoid
    #   StateMachine::Integrations.match(MongoMapperVehicle)  # => StateMachine::Integrations::MongoMapper
    #   StateMachine::Integrations.match(SequelVehicle)       # => StateMachine::Integrations::Sequel
    def self.match(klass)
      all.detect {|integration| integration.matches?(klass)}
    end
    
    # Attempts to find an integration that matches the given list of ancestors.
    # This will look through all of the built-in integrations under the StateMachine::Integrations
    # namespace and find one that successfully matches one of the ancestors.
    # 
    # == Examples
    # 
    #   StateMachine::Integrations.match([])                    # => nil
    #   StateMachine::Integrations.match(['ActiveRecord::Base') # => StateMachine::Integrations::ActiveModel
    def self.match_ancestors(ancestors)
      all.detect {|integration| integration.matches_ancestors?(ancestors)}
    end
    
    # Finds an integration with the given name.  If the integration cannot be
    # found, then a NameError exception will be raised.
    # 
    # == Examples
    # 
    #   StateMachine::Integrations.find_by_name(:active_record) # => StateMachine::Integrations::ActiveRecord
    #   StateMachine::Integrations.find_by_name(:active_model)  # => StateMachine::Integrations::ActiveModel
    #   StateMachine::Integrations.find_by_name(:data_mapper)   # => StateMachine::Integrations::DataMapper
    #   StateMachine::Integrations.find_by_name(:mongoid)       # => StateMachine::Integrations::Mongoid
    #   StateMachine::Integrations.find_by_name(:mongo_mapper)  # => StateMachine::Integrations::MongoMapper
    #   StateMachine::Integrations.find_by_name(:sequel)        # => StateMachine::Integrations::Sequel
    #   StateMachine::Integrations.find_by_name(:invalid)       # => StateMachine::IntegrationNotFound: :invalid is an invalid integration
    def self.find_by_name(name)
      all.detect {|integration| integration.integration_name == name} || raise(IntegrationNotFound.new(name))
    end
    
    # Gets a list of all of the available integrations for use.  This will
    # always list the ActiveModel integration last.
    # 
    # == Example
    # 
    #   StateMachine::Integrations.all
    #   # => [StateMachine::Integrations::ActiveRecord, StateMachine::Integrations::DataMapper
    #   #     StateMachine::Integrations::Mongoid, StateMachine::Integrations::MongoMapper,
    #   #     StateMachine::Integrations::Sequel, StateMachine::Integrations::ActiveModel]
    def self.all
      constants = self.constants.map {|c| c.to_s}.select {|c| c != 'ActiveModel'}.sort << 'ActiveModel'
      constants.map {|c| const_get(c)}
    end
  end
end
