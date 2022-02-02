RSpec.shared_examples_for 'all modules with module type can be instantiated' do |options={}|
  options.assert_valid_keys(:module_type, :modules_pathname, :type_directory)

  module_type = options.fetch(:module_type)
  modules_pathname = options.fetch(:modules_pathname)
  modules_path = modules_pathname.to_path
  type_directory = options.fetch(:type_directory)

  include_context 'Msf::Simple::Framework#modules loading'

  #
  # lets
  #

  context module_type do
    type_pathname = modules_pathname.join(type_directory)
    module_extension = ".rb"
    module_extension_regexp = /#{Regexp.escape(module_extension)}$/

    Dir.glob(type_pathname.join('**', "*#{module_extension}")) do |module_path|
      unless File.executable? module_path
        module_pathname = Pathname.new(module_path)
        module_reference_pathname = module_pathname.relative_path_from(type_pathname)
        module_reference_name = module_reference_pathname.to_path.gsub(module_extension_regexp, '')

        context module_reference_name do
          it 'can be instantiated' do
            load_and_create_module(
                module_type: module_type,
                modules_path: modules_path,
                reference_name: module_reference_name
            )
          end
        end
      end
    end
  end
end
