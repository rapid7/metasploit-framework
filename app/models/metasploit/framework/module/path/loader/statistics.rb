class Metasploit::Framework::Module::Path::Loader::Statistics < Metasploit::Model::Base
  # @todo remove once Metasploit::Model::Base includs ActiveModel::Validations
  include ActiveModel::Validations

  #
  # Attributes
  #

  # @!attribute [rw] loader
  #   The loader that generated these statistics
  #
  #   @return [Metasploit::Framework::Module::Path::Loader::Base]
  attr_accessor :loader

  # @!attribute [rw] module_path
  #   The module path that the {#loader}
  #   {Metasploit::Framework::Module::Path::Loader::Base#load_module_path
  #   loaded}.
  #
  #   @return [Metasploit::Model::Module::Path]
  attr_accessor :module_path

  #
  # Validations
  #

  validates :loader, presence: true
  validates :module_path, presence: true

  #
  # Methods
  #

  def types
    []
  end
end