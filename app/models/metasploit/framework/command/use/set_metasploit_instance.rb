#
# Project
#

class Metasploit::Framework::Command::Use::SetMetasploitInstance < Metasploit::Framework::Command::Base
  include Metasploit::Framework::Command::Child
  include Metasploit::Framework::Command::Use::SetMetasploitInstance::TabCompletion

  #
  # Attributes
  #

  # @!attribute [rw] module_class_full_name
  #   The `Mdm::Module::Class#full_name` to be activated.
  #
  #   @return [String]
  attr_accessor :module_class_full_name

  #
  # Validations
  #

  validates :metasploit_instance,
            presence: true
  validates :words,
            # Catch if use accidentally types multiple module class full names.
            length: {
                is: 1
            }

  #
  # Methods
  #

  # Instance wit {#module_class_full_name} for its Class's full name.
  #
  # @return [nil] if {#modle_class_full_name} is not the name of a module in the cache or if the module failed to
  #   initialize
  # @return [Msf::Module] otherwise
  def metasploit_instance
    unless instance_variable_defined? :@metasploit_instance
      if dispatcher
        @metasploit_instance = dispatcher.framework.modules.create(module_class_full_name)
      else
        @metasploit_instance = nil
      end
    end

    @metasploit_instance
  end

  protected

  def run_with_valid
    dispatcher.metasploit_instance = metasploit_instance
  end
end
