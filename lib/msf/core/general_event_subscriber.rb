
###
#
# This event subscriber class exposes methods that are called when internal
# framework events occur, such as the loading and creation of a module.
#
###
module Msf::GeneralEventSubscriber
  #
  # Called when a module is loaded
  #
  def on_module_load(refname, klass)
  end

  #
  # Called when a new module instance is created
  #
  def on_module_created(instance)
  end

  #
  # Called when a module is run
  #
  def on_module_run(instance)
  end

  #
  # Called when a module finishes
  #
  def on_module_complete(instance)
  end

  #
  # Called when a module raises an exception
  #
  def on_module_error(instance, exception)
  end

end