if RUBY_VERSION < '1.9'
  require 'backports/tools/path'

  Backports.convert_all_arguments_to_path File, :symlink, 0
  Backports.convert_first_argument_to_path File, :symlink?
end
