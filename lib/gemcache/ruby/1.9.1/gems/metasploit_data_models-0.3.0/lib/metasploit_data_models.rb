require "active_record"
require "active_support"
require "active_support/all"
require "shellwords"

require "metasploit_data_models/version"
require "metasploit_data_models/serialized_prefs"
require "metasploit_data_models/base64_serializer"

require "metasploit_data_models/validators/ip_format_validator"
require "metasploit_data_models/validators/password_is_strong_validator"


# Declare the (blessedly short) common namespace for the ActiveRecord classes
module Mdm; end

module MetasploitDataModels
  module ActiveRecordModels; end

  # Dynamically create AR classes if being included from Msf::DBManager
  # otherwise, just make the modules available for arbitrary inclusion.
  def self.included(base)
    ar_mixins.each{|file| require file}
    create_and_load_ar_classes if base.to_s == 'Msf::DBManager'
  end

  # The code in each of these represents the basic structure of a correspondingly named
  # ActiveRecord model class.  Those classes are explicitly created in our Rails app
  # for the commercial versions, and the functionality from the mixins is included 
  # into model classes directly.
  # 
  # When not explicitly overloading the classes in your own files use MetasploitDataModels#create_and_load_ar_classes
  # to dynamically generate ActiveRecord classes in the Mdm namespace.
  def self.ar_mixins
    models_dir = File.expand_path(File.dirname(__FILE__)) + "/metasploit_data_models/active_record_models"
    Dir.glob("#{models_dir}/*.rb")
  end

  # Dynamically create ActiveRecord descendant classes in the Mdm namespace
  def self.create_and_load_ar_classes
    ar_module_names.each do |cname|
      class_str =<<-RUBY
        class Mdm::#{cname} < ActiveRecord::Base
          include MetasploitDataModels::ActiveRecordModels::#{cname}
        end
      RUBY
      eval class_str, binding, __FILE__, __LINE__ # *slightly* more obvious stack trace
    end
  end

  # Derive "constant" strings from the names of the files in
  # lib/metasploit_data_models/active_record_models
  def self.ar_module_names
    ar_mixins.inject([]) do |array, path|
      filename = File.basename(path).split(".").first
      c_name = filename.classify
      c_name << "s" if filename =~ /^[\w]+s$/ # classify can't do plurals
      array << c_name
      array
    end
  end

end
