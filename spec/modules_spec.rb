require 'spec_helper'

RSpec.describe 'modules', :content do
  modules_pathname = Pathname.new(__FILE__).parent.parent.join('modules')

  it_should_behave_like 'all modules with module type can be instantiated',
                        module_type: 'auxiliary',
                        modules_pathname: modules_pathname,
                        type_directory: 'auxiliary'

  it_should_behave_like 'all modules with module type can be instantiated',
                        module_type: 'encoder',
                        modules_pathname: modules_pathname,
                        type_directory: 'encoders'

  it_should_behave_like 'all modules with module type can be instantiated',
                        module_type: 'exploit',
                        modules_pathname: modules_pathname,
                        type_directory: 'exploits'

  it_should_behave_like 'all modules with module type can be instantiated',
                        module_type: 'nop',
                        modules_pathname: modules_pathname,
                        type_directory: 'nops'

  it_should_behave_like 'all modules with module type can be instantiated',
                        module_type: 'post',
                        modules_pathname: modules_pathname,
                        type_directory: 'posts'
end