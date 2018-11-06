# Superclass for all Metasploit::Models.  Just adds a default {#initialize} to make models mimic behavior of
# ActiveRecord::Base subclasses.
class Metasploit::Model::Base
  include ActiveModel::Validations

  # After ActiveModel::Validations so Metasploit::Model::Translation is favored over ActiveModel::Translation
  include Metasploit::Model::Translation

  # @param attributes [Hash{Symbol => String,nil}]
  def initialize(attributes={})
    attributes.each do |attribute, value|
      public_send("#{attribute}=", value)
    end
  end

  # Validates the model.
  #
  # @return [void]
  # @raise [Metasploit::Model::Invalid] if invalid
  def valid!
    unless valid?
      raise Metasploit::Model::Invalid.new(self)
    end
  end
end