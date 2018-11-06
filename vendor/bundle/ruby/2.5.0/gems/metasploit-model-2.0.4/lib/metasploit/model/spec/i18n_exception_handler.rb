# Raises all I18n errors as exceptions so that missing translations (or other errors) with en.yml are caught by the
# specs.
#
# @example Use in spec_helper.rb to find missing translations
#   RSpec.configure do |config|
#     config.before(:suite) do
#       # catch missing translations
#       I18n.exception_handler = Metasploit::Model::Spec::I18nExceptionHandler.new
#     end
#  end
class Metasploit::Model::Spec::I18nExceptionHandler < I18n::ExceptionHandler
  # Raises `exception`.
  #
  # @return [void]
  # @raise [Exception]
  def call(exception, locale, key, options)
    raise exception.to_exception
  end
end