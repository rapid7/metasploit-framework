module Pry::Platform
  extend self

  #
  # @return [Boolean]
  #  Returns true if Pry is running on Mac OSX.
  #
  # @note
  #   Queries RbConfig::CONFIG['host_os'] with a best guess.
  #
  def mac_osx?
    !!(RbConfig::CONFIG['host_os'] =~ /\Adarwin/i)
  end

  #
  # @return [Boolean]
  #   Returns true if Pry is running on Linux.
  #
  # @note
  #   Queries RbConfig::CONFIG['host_os'] with a best guess.
  #
  def linux?
    !!(RbConfig::CONFIG['host_os'] =~ /linux/i)
  end

  #
  # @return [Boolean]
  #   Returns true if Pry is running on Windows.
  #
  # @note
  #   Queries RbConfig::CONFIG['host_os'] with a best guess.
  #
  def windows?
    !!(RbConfig::CONFIG['host_os'] =~ /mswin|mingw/)
  end

  #
  # @return [Boolean]
  #   Returns true when Pry is running on Windows with ANSI support.
  #
  def windows_ansi?
    return false if not windows?
    !!(defined?(Win32::Console) or ENV['ANSICON'] or mri_2?)
  end

  #
  # @return [Boolean]
  #   Returns true when Pry is being run from JRuby.
  #
  def jruby?
    RbConfig::CONFIG['ruby_install_name'] == 'jruby'
  end

  #
  # @return [Boolean]
  #   Returns true when Pry is being run from JRuby in 1.9 mode.
  #
  def jruby_19?
    jruby? and RbConfig::CONFIG['ruby_version'] == '1.9'
  end

  #
  # @return [Boolean]
  #   Returns true when Pry is being run from Rubinius.
  #
  def rbx?
    RbConfig::CONFIG['ruby_install_name'] == 'rbx'
  end

  #
  # @return [Boolean]
  #   Returns true when Pry is being run from MRI (CRuby).
  #
  def mri?
    RbConfig::CONFIG['ruby_install_name'] == 'ruby'
  end

  #
  # @return [Boolean]
  #   Returns true when Pry is being run from MRI v1.9+ (CRuby).
  #
  def mri_19?
    !!(mri? and RUBY_VERSION =~ /\A1\.9/)
  end

  #
  # @return [Boolean]
  #   Returns true when Pry is being run from MRI v2+ (CRuby).
  #
  def mri_2?
    !!(mri? and RUBY_VERSION =~ /\A2/)
  end
end
