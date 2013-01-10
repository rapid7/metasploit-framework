#Test config class provides public methods or varables to use for ever test
#Includes housing data such as default web site to test, time out varaibels, etc
require 'singleton'
class TestConfig
  include Singleton
  
  def initialize(*args)

	yml_path = File.join(File.dirname(__FILE__),'test_config.yml')
  
	if File.exists?(yml_path)
		@yaml_options = YAML::load(File.open(yml_path))
	else
		@yaml_options = {}
	end
    
    @options = {
    	"rhost" => "localhost",
	"smbuser" => "user",
	"smbpass" => "password" 
   } 
  end
  
  def run_server
    @options[:define_site].nil?
  end

  def method_missing(method)
    if @options.has_key? method.to_s
      return @options[method.to_s]
    else
      super
    end
  end

def respond_to?(method_sym, include_private = false)
    if @options.include? method_s
      true
    else
      super
    end
  end

end
