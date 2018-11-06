begin
  File.open(__FILE__, :mode => 'r'){}
rescue TypeError
  require 'backports/tools/alias_method_chain'
  require 'backports/tools/io'

  def open_with_options_hash(file, mode = nil, perm_or_options = Backports::Undefined)
    mode, perm = Backports.combine_mode_perm_and_option(mode, perm_or_options)
    perm ||= 0666 # Avoid error on Rubinius, see issue #52
    if block_given?
      open_without_options_hash(file, mode, perm){|f| yield f}
    else
      open_without_options_hash(file, mode, perm)
    end
  end

  class << File
    Backports.alias_method_chain self, :open, :options_hash
  end
end

if RUBY_VERSION < '1.9'
  require 'backports/tools/path'

  Backports.convert_first_argument_to_path File, :open
end
