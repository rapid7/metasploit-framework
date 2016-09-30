module Msf::Module::Arch
  #
  # Attributes
  #

  # @!attribute arch
  #   The array of zero or more architectures.
  attr_reader   :arch

  #
  # Instance Methods
  #

  #
  # Return whether or not the module supports the supplied architecture.
  #
  def arch?(what)
    if (what == ARCH_ANY)
      true
    else
      arch.index(what) != nil
    end
  end

  #
  # Return a comma separated list of supported architectures, if any.
  #
  def arch_to_s
    arch.join(", ")
  end

  #
  # Enumerate each architecture.
  #
  def each_arch(&block)
    arch.each(&block)
  end

  protected

  #
  # Attributes
  #

  attr_writer :arch
end