if RUBY_VERSION < '1.9'
  require 'backports/tools/path'

  Backports.convert_all_arguments_to_path File, :delete, 0
end
