if RUBY_VERSION < '1.9'
  require 'backports/tools/path'

  Backports.convert_first_argument_to_path File, :link
end
