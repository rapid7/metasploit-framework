module Metasploit::Framework::Module::Instance::MetasploitInstance::Cache
  extend Metasploit::Framework::Synchronizes

  include Metasploit::Framework::Module::Instance::Logging

  #
  # Synchronization
  #

  synchronizes :actions,
               :module_authors,
               :module_architectures,
               :module_platforms,
               :module_references,
               :stance,
               :targets,
               for: 'Module::Instance'

  #
  # Methods
  #


  # @note It is the caller's responsibility to check that returned `Metasploit::Model::Module::Ancestor` saved
  #   successful.
  #
  # Caches instance metadata.
  #
  # @param module_instance [Metasploit::Model::Module::Instance]
  def cache_module_instance(module_instance=nil)
    module_instance ||= self.module_instance

    # use explicit `self.` so that ruby raises the more specific NoMethodError instead of NameError when it can't
    # determine if `description` is an undefined local variable or method.
    [:description, :license, :name, :privileged].each do |attribute|
      # user could have undefined these methods or subclassed the wrong thing when writing a module, so handle bad
      # modules here
      rescue_module_instance_error(module_instance, NoMethodError) {
        value = send(attribute)
        module_instance.send("#{attribute}=", value)
      }
    end

    ActiveRecord::Base.connection_pool.with_connection do
      # make sure a transaction wraps author/email creation in addition to module instance so they'll all get unwound
      ActiveRecord::Base.transaction do
        Metasploit::Framework::Module::Instance::MetasploitInstance::Cache.synchronization_classes(for: 'Module::Instance') do |synchronization_class|
          if synchronization_class.can_synchronize?(module_instance)
            synchronization = synchronization_class.new(
                destination: module_instance,
                source: self
            )
            synchronization.valid!

            synchronization.synchronize
          end
        end

        unless module_instance.batched_save
          location = module_instance_location(module_instance)

          elog(
              "#{location} didn't save its Module::Instance to cache because: " \
              "#{module_instance.errors.full_messages}"
          )
        end
      end
    end

    module_instance
  end
end
