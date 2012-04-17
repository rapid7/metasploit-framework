filename = "#{File.dirname(__FILE__)}/../active_model/locale.rb"
translations = eval(IO.read(filename), binding, filename)
translations[:en][:activerecord] = translations[:en].delete(:activemodel)

# Only ActiveRecord 2.3.5+ can pull i18n >= 0.1.3 from system-wide gems (and
# therefore possibly have I18n::VERSION available)
begin
  require 'i18n/version'
rescue Exception => ex
end unless ::ActiveRecord::VERSION::MAJOR == 2 && (::ActiveRecord::VERSION::MINOR < 3 || ::ActiveRecord::VERSION::TINY < 5)

# Only i18n 0.4.0+ has the new %{key} syntax
if !defined?(I18n::VERSION) || I18n::VERSION < '0.4.0'
  translations[:en][:activerecord][:errors][:messages].each do |key, message|
    message.gsub!('%{', '{{')
    message.gsub!('}', '}}')
  end
end

translations
