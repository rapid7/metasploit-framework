class Metasploit::Framework::ValidationProxy < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] target
  #   The `Module` being validated
  #
  #   @return [Module]
  attr_accessor :target

  def method_missing(method_name, *args, &block)
    if target.respond_to? method_name
      target.public_send(method_name, *args, &block)
    else
      super
    end
  end
end