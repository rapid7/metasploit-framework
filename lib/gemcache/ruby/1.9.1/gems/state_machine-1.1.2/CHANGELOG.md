# master

* Fix callbacks not working for methods that respond via method_missing [Balwant Kane]
* Fix observer callbacks being run when disabled in ActiveModel / ActiveRecord integrations
* Add YARD integration for autogenerating documentation / embedding visualizations of state machines
* Allow states / events to be drawn with their human name instead of their internal name

## 1.1.2 / 2012-01-20

* Fix states not being initialized properly on ActiveRecord 3.2+

## 1.1.1 / 2011-12-31

* Fix fields being defined for Mongoid / MongoMapper state attributes even if they're already defined in the model
* Raise error when states / events are referenced in a definition with different types (e.g. both Strings and Symbols)
* Allow all states / events to be looked up by their string / symbol equivalent
* Allow state_machine to be loaded without extensions to the Ruby core

## 1.1.0 / 2011-11-13

* Allow the transitions / known states for an event to be reset
* Add fire_#{name}_event instance method for firing an arbitrary event on a state machine
* Improve InvalidTransition exception messages to include the failure reason(s) in ORM integrations
* Don't allow around_transitions to attempt to be called in multiple execution contexts when run in jruby
* Allow :from option to be used in transitions defined within state contexts
* Fix arguments / block not being preserved when chaining methods defined in state contexts
* Fix super not being allowed when a method is defined for multiple state contexts
* Change loopbacks to only cause objects to be persisted when the ORM decides it's necessary, instead of always forcing persistence
* Fix Mongoid 2.3.x integrations not initializing dynamic states in the same manner as other integrations with initialize callbacks

## 1.0.3 / 2011-11-03

* Fix MongoMapper 0.10.0+ integrations not matching versions properly
* Update warnings for method conflicts to include instructions on how to ignore conflicts
* Fix state initialization in Mongoid 2.3.x integrations [Durran Jordan]
* Fix after_transition callbacks sometimes not running in Mongoid 2.2.x integrations
* Automatically load the plugins required in Sequel integrations
* Allow all / any matcher helpers to be used when defining states / events
* Allow states / events to be referenced by the string equivalent of their name
* Fix observer callbacks being run incorrectly when using nil states in ActiveModel-based integrations
* Remove ActiveModel Observer method chains in order to better ensure compatibility
* Update DataMapper integration for 1.2.0+ support [Markus Schirp]
* Provide access to the human state name in invalid_transition translations
* Add support for i18n keys in the form of #{i18n_scope}.state_machines.#{model_name}.states/events.#{value}
* Clarify documentation on writing to state machine attributes, using factory_girl and can_#{event} / #{event}_transition helpers
* Add documentation for dynmically generating state machines

## 1.0.2 / 2011-08-09

* Allow transitions to be defined within a state, event, or machine context
* Use supported framework hooks for integrating Sequel 3.24.0+
* Use appraisal for testing integrations
* Improve documentation on the handling of method conflicts
* Update Mongoid integration for 2.1.0+ support
* Fix ActiveRecord machine state predicates incorrectly calling superclass implementation when using targeted attributes
* Fix error when defining states with the same name as the state's machine in ActiveRecord, MongoMapper, and Mongoid integrations
* Fix machine state predicate not calling superclass implementation if defined after machine definition
* Generate warnings when defining a helper method more than once
* Fix multiple machines not being able to target the same attribute if all possible states aren't defined in each
* Fix ActiveModel / DataMapper integrations not overriding StateMachine::Machine#after_initialize properly
* Improve documentation for overriding states and integration transactions

## 1.0.1 / 2011-05-30

* Add the ability to ignore method conflicts for helpers
* Generate warnings for any helper, not just state helpers, that has a conflicting method defined in the class
* Fix scopes in Sequel not working if the table name contains double underscores or is not a string/symbol
* Add full support for chaining state scopes within Sequel integrations
* Fix Rails 3.1 deprecation warnings for configuring engine locales [Stefan Penner]

## 1.0.0 / 2011-05-12

* Celebrate

## 0.10.4 / 2011-04-14

* Fix translations not being available under certain environments in Rails applications

## 0.10.3 / 2011-04-07

* Fix state initialization failing in ActiveRecord 3.0.2+ when using with_state scopes for the default scope

## 0.10.2 / 2011-03-31

* Use more integrated state initialization hooks for ActiveRecord, Mongoid, and Sequel
* Remove mass-assignment filtering usage in all ORM integrations
* Only support official Mongoid 2.0.0 release and up (no more RC support)
* Fix attributes getting initialized more than once if different state machines use the same attribute
* Only initialize states if state is blank and blank is not a valid state
* Fix instance / class helpers failing when used with certain libraries (such as Thin)

## 0.10.1 / 2011-03-22

* Fix classes with multiple state machines failing to initialize in ActiveRecord / Mongoid / Sequel integrations

## 0.10.0 / 2011-03-19

* Support callback terminators in MongoMapper 0.9.0+
* Fix pluralization integration on DataMapper 1.0.0 and 1.1.0
* Allow transition guards to be bypassed for event / transition / path helpers
* Allow state / condition requirements to be specified for all event / transition / path helpers
* Add the ability to skip automatically initializing state machines on #initialize
* Add #{name}_paths for walking the available paths in a state machine
* Add Mongoid 2.0.0+ support
* Use around hooks to improve compatibility with other libraries in ActiveModel / ActiveRecord / MongoMapper integrations
* Add support for MassAssignmentSecurity feature in ActiveModel integrations
* Add support for more observer hooks within MongoMapper integrations
* Add i18n support for MongoMapper validation errors
* Update support for MongoMapper integration based on rails3 branch
* Fix objects not getting marked as dirty in all integrations when #{name}_event is set
* Generate warnings when conflicting state / event names are detected
* Allow fallback to generic state predicates when individual predicates are already defined in the owner class
* Replace :include_failures after_transition option with new after_failure callback
* Provide access to transition context when raising InvalidEvent / InvalidTransition exceptions

## 0.9.4 / 2010-08-01

* Fix validation / save hooks in Sequel 3.14.0+
* Fix integration with dirty attribute tracking on DataMapper 1.0.1+
* Fix DataMapper 1.0.1+ tests producing warnings
* Fix validation error warnings in ActiveModel / ActiveRecord 3.0.0 beta5+
* Fix mass-assignment sanitization breaking in ActiveRecord 3.0.0 beta5+ [Akira Matsuda]

## 0.9.3 / 2010-06-26

* Allow access to human state / event names in transitions and for the current state
* Use human state / event names in error messages
* Fix event names being used inconsistently in error messages
* Allow access to the humanized version of state / event names via human_state_name / human_state_event_name
* Allow MongoMapper 0.8.0+ scopes to be chainable
* Fix i18n deprecation warnings in ActiveModel / ActiveRecord 3.0.0.beta4
* Fix default error message translations overriding existing locales in ActiveModel / ActiveRecord

## 0.9.2 / 2010-05-24

* Fix MongoMapper integration failing in Ruby 1.9.2
* Fix Rakefile not loading in Ruby 1.9.2 [Andrea Longhi]
* Fix nil / false :integration configuration not being respected

## 0.9.1 / 2010-05-02

* Fix ActiveRecord 2.0.0 - 2.2.3 integrations failing if version info isn't already loaded
* Fix integration with dirty attribute tracking on DataMapper 0.10.3
* Fix observers failing in ActiveRecord 3.0.0.beta4+ integrations
* Fix deprecation warning in Rails 3 railtie [Chris Yuan]

## 0.9.0 / 2010-04-12

* Use attribute-based event transitions whenever possible to ensure consistency
* Fix action helpers being defined when the action is **only** defined in the machine's owner class
* Disable attribute-based event transitions in DataMapper 0.9.4 - 0.9.6 when dm-validations is being used
* Add support for DataMapper 0.10.3+
* Add around_transition callbacks
* Fix transition failures during save not being handled correctly in Sequel 2.12.0+
* Fix attribute-based event transitions not hooking in properly in DataMapper 0.10.0+ and Sequel 2.12.0+
* Fix dynamic initial states causing errors in Ruby 1.9+ if no arguments are defined in the block
* Add MongoMapper 0.5.5+ support
* Add ActiveModel 3.0+ support for use with integrations that implement its interface
* Fix DataMapper integration failing when ActiveSupport is loaded in place of Extlib
* Add version dependencies for ruby-graphviz
* Remove app-specific rails / merb rake tasks in favor of always running state_machine:draw
* Add Rails 3 railtie for automatically loading rake tasks when installed as a gem

## 0.8.1 / 2010-03-14

* Release gems via rake-gemcutter instead of rubyforge
* Move rake tasks to lib/tasks
* Dispatch state behavior to the superclass if it's undefined for a particular state [Sandro Turriate and Tim Pope]
* Fix state / event names not supporting i18n in ActiveRecord
* Fix original ActiveRecord::Observer#update not being used for non-state_machine callbacks [Jeremy Wells]
* Add support for ActiveRecord 3.0
* Fix without_{name} scopes not quoting columns in ActiveRecord [Jon Evans]
* Fix without_{name} scopes not scoping columns to the table in ActiveRecord and Sequel [Jon Evans]
* Fix custom state attributes not being marked properly as changed in ActiveRecord
* Fix tracked attributes changes in ActiveRecord / DataMapper integrations not working correctly for non-loopbacks [Joe Lind]
* Fix plural scope names being incorrect for DataMapper 0.9.4 - 0.9.6
* Fix deprecation warnings for ruby-graphviz 0.9.0+
* Add support for ActiveRecord 2.0.*
* Fix nil states being overwritten when they're explicitly set in ORM integrations
* Fix default states not getting set in ORM integrations if the column has a default
* Fix event transitions being kept around while running actions/callbacks, sometimes preventing object marshalling

## 0.8.0 / 2009-08-15

* Add support for DataMapper 0.10.0
* Always interpet nil return values from actions as failed attempts
* Fix loopbacks not causing records to save in ORM integrations if no other fields were changed
* Fix events not failing with useful errors when an object's state is invalid
* Use more friendly NoMethodError messages for state-driven behaviors
* Fix before_transition callbacks getting run twice when using event attributes in ORM integrations
* Add the ability to query for the availability of specific transitions on an object
* Allow after_transition callbacks to be explicitly run on failed attempts
* By default, don't run after_transition callbacks on failed attempts
* Fix not allowing multiple methods to be specified as arguments in callbacks
* Fix initial states being set when loading records from the database in Sequel integration
* Allow static initial states to be set earlier in the initialization of an object
* Use friendly validation errors for nil states
* Fix states not being validated properly when using custom names in ActiveRecord / DataMapper integrations

## 0.7.6 / 2009-06-17

* Allow multiple state machines on the same class to target the same attribute
* Add support for :attribute to customize the attribute target, assuming the name is the first argument of #state_machine
* Simplify reading from / writing to machine-related attributes on objects
* Fix locale for ActiveRecord getting added to the i18n load path multiple times [Reiner Dieterich]
* Fix callbacks, guards, and state-driven behaviors not always working on tainted classes [Brandon Dimcheff]
* Use Ruby 1.9's built-in Object#instance_exec for bound callbacks when it's available
* Improve performance of cached dynamic state lookups by 25%

## 0.7.5 / 2009-05-25

* Add built-in caching for dynamic state values when the value only needs to be generated once
* Fix flawed example for using record ids as state values
* Don't evaluate state values until they're actually used in an object instance
* Make it easier to use event attributes for actions defined in the same class as the state machine
* Fix #save/save! running transitions in ActiveRecord integrations even when a machine's action is not :save

## 0.7.4 / 2009-05-23

* Fix #save! not firing event attributes properly in ActiveRecord integrations
* Fix log files being included in gems

## 0.7.3 / 2009-04-25

* Require DataMapper version be >= 0.9.4
* Explicitly load Sequel's built-in inflector (>= 2.12.0) for scope names
* Don't use qualified name for event attributes
* Fix #valid? being defined for DataMapper resources when dm-validations isn't loaded
* Add auto-validation of values allowed for the state attribute in ORM integrations

## 0.7.2 / 2009-04-08

* Add support for running multiple methods in a callback without using blocks
* Add more flexibility around how callbacks are defined
* Add security documentation around mass-assignment in ORM integrations
* Fix event attribute transitions being publicly accessible

## 0.7.1 / 2009-04-05

* Fix machines failing to generate graphs when run from Merb tasks

## 0.7.0 / 2009-04-04

* Add #{attribute}_event for automatically firing events when the object's action is called
* Make it easier to override state-driven behaviors
* Rollback state changes when the action fails during transitions
* Use :messages instead of :invalid_message for customizing validation errors
* Use more human-readable validation errors
* Add support for more ActiveRecord observer hooks
* Add support for targeting multiple specific state machines in DataMapper observer hooks
* Don't pass the result of the action as an argument to callbacks (access via Transition#result)
* Fix incorrect results being used when running transitions in parallel
* Fix transition args not being set when run in parallel
* Allow callback terminators to be set on an application-wide basis
* Only catch :halt during before / after transition callbacks
* Fix ActiveRecord predicates being overwritten if they're already defined in the class
* Allow machine options to be set on an integration-wide basis
* Turn transactions off by default in DataMapper integrations
* Add support for configuring the use of transactions
* Simplify reading/writing of attributes
* Simplify access to state machines via #state_machine(:attribute) without generating dupes
* Fix assumptions that dm-validations is always available in DataMapper integration
* Automatically define DataMapper properties for machine attributes if they don't exist
* Add Transition#qualified_event, #qualified_from_name, and #qualified_to_name
* Add #fire_events / #fire_events! for running events on multiple state machines in parallel
* Rename next_#{event}_transition to #{event}_transition
* Add #{attribute}_transitions for getting the list of transitions that can be run on an object
* Add #{attribute}_events for getting the list of events that can be fired on an object
* Use generated non-bang event when running bang version so that overriding one affects the other
* Provide access to arguments passed into an event from transition callbacks via Transition#args

## 0.6.3 / 2009-03-10

* Add support for customizing the graph's orientation
* Use the standard visualizations for initial (open arrow) and final (double circle) states
* Highlight final states in GraphViz drawings

## 0.6.2 / 2009-03-08

* Make it easier to override generated instance / class methods

## 0.6.1 / 2009-03-07

* Add i18n support for ActiveRecord validation errors
* Add a validation error when failing to transition for ActiveRecord / DataMapper / Sequel integrations

## 0.6.0 / 2009-03-03

* Allow multiple conditions for callbacks / class behaviors
* Add support for state-driven class behavior with :if/:unless options
* Alias Machine#event as Machine#on
* Fix nil from/to states not being handled properly
* Simplify hooking callbacks into loopbacks
* Add simplified transition/callback requirement syntax

## 0.5.2 / 2009-02-17

* Improve pretty-print of events
* Simplify state/event matching design, improving guard performance by 30%
* Add better error notification when conflicting guard options are defined
* Fix scope name pluralization not being applied correctly

## 0.5.1 / 2009-02-11

* Allow states to be drawn as ellipses to accommodate long names
* Fix rake tasks not being registered in Rails/Merb applications
* Never automatically define machine attribute accessors when using an integration

## 0.5.0 / 2009-01-11

* Add to_name and from_name to transition objects
* Add nicely formatted #inspect for transitions
* Fix ActiveRecord integrations failing when the database doesn't exist yet
* Fix states not being drawn in GraphViz graphs in the correct order
* Add nicely formatted #inspect for states and events
* Simplify machine context-switching
* Store events/states in enumerable node collections
* No longer allow subclasses to change the integration
* Move fire! action logic into the Event class (no longer calls fire action on the object)
* Allow states in subclasses to have different values
* Recommend that all states be referenced as symbols instead of strings
* All states must now be named (and can be associated with other value types)
* Add support for customizing the actual stored value for a state
* Add compatibility with Ruby 1.9+

## 0.4.3 / 2008-12-28

* Allow dm-observer integration to be optional
* Fix non-lambda callbacks not working for DataMapper/Sequel

## 0.4.2 / 2008-12-28

* Fix graphs not being drawn the same way consistently
* Add support for sharing transitions across multiple events
* Add support for state-driven behavior
* Simplify initialize hooks, requiring super to be called instead
* Add :namespace option for generated state predicates / event methods

## 0.4.1 / 2008-12-16

* Fix nil states not being handled properly in guards, known states, or visualizations
* Fix the same node being used for different dynamic states in GraphViz output
* Always include initial state in the list of known states even if it's dynamic
* Use consistent naming scheme for dynamic states in GraphViz output
* Allow blocks to be directly passed into machine class
* Fix attribute predicates not working on attributes that represent columns in ActiveRecord

## 0.4.0 / 2008-12-14

* Remove the PluginAWeek namespace
* Add generic attribute predicate (e.g. "#{attribute}?(state_name)") and state predicates (e.g. "#{state}?")
* Add Sequel support
* Fix aliasing :initialize on ActiveRecord models causing warnings when the environment is reloaded
* Fix ActiveRecord state machines trying to query the database on unmigrated models
* Fix initial states not getting set when the current value is an empty string [Aaron Gibralter]
* Add rake tasks for generating graphviz files for state machines [Nate Murray]
* Fix initial state not being included in list of known states
* Add other_states directive for defining additional states not referenced in transitions or callbacks [Pete Forde]
* Add next_#{event}_transition for getting the next transition that would be performed if the event were invoked
* Add the ability to override the pluralized name of an attribute for creating scopes
* Add the ability to halt callback chains by: throw :halt
* Add support for dynamic to states in transitions (e.g. :to => lambda {Time.now})
* Add support for using real blocks in before_transition/after_transition calls instead of using the :do option
* Add DataMapper support
* Include states referenced in transition callbacks in the list of a machine's known states
* Only generate the known states for a machine on demand, rather than calculating beforehand
* Add the ability to skip state change actions during a transition (e.g. vehicle.ignite(false))
* Add the ability for the state change action (e.g. `save` for ActiveRecord) to be configurable
* Allow state machines to be defined on **any** Ruby class, not just ActiveRecord (removes all external dependencies)
* Refactor transitions, guards, and callbacks for better organization/design
* Use a class containing the transition context in callbacks, rather than an ordered list of each individual attribute
* Add without_#{attribute} named scopes (opposite of the existing with_#{attribute} named scopes) [Sean O'Brien]

## 0.3.1 / 2008-10-26

* Fix the initial state not getting set when the state attribute is mass-assigned but protected
* Change how the base module is included to prevent namespacing conflicts

## 0.3.0 / 2008-09-07

* No longer allow additional arguments to be passed into event actions
* Add support for can_#{event}? for checking whether an event can be fired based on the current state of the record
* Don't use callbacks for performing transitions
* Fix state machines in subclasses not knowing what states/events/transitions were defined by superclasses
* Replace all before/after_exit/enter/loopback callback hooks and :before/:after options for events with before_transition/after_transition callbacks, e.g.
  
  before_transition :from => 'parked', :do => :lock_doors # was before_exit :parked, :lock_doors
  after_transition :on => 'ignite', :do => :turn_on_radio # was event :ignite, :after => :turn_on_radio do
  
* Always save when an event is fired even if it results in a loopback [Jürgen Strobel]
* Ensure initial state callbacks are invoked in the proper order when an event is fired on a new record
* Add before_loopback and after_loopback hooks [Jürgen Strobel]

## 0.2.1 / 2008-07-05

* Add more descriptive exceptions
* Assume the default state attribute is "state" if one is not provided
* Add :except_from option for transitions if you want to blacklist states
* Add PluginAWeek::StateMachine::Machine#states
* Add PluginAWeek::StateMachine::Event#transitions
* Allow creating transitions with no from state (effectively allowing the transition for **any** from state)
* Reduce the number of objects created for each transition

## 0.2.0 / 2008-06-29

* Add a non-bang version of events (e.g. park) that will return a boolean value for success
* Raise an exception if the bang version of events are used (e.g. park!) and no transition is successful
* Change callbacks to act a little more like ActiveRecord
* Avoid using string evaluation for dynamic methods

## 0.1.1 / 2008-06-22

* Remove log files from gems

## 0.1.0 / 2008-05-05

* Completely rewritten from scratch
* Renamed to state_machine
* Removed database dependencies
* Removed models in favor of an attribute-agnostic design
* Use ActiveSupport::Callbacks instead of eval_call
* Remove dry_transaction_rollbacks dependencies
* Added functional tests
* Updated documentation

## 0.0.1 / 2007-09-26

* Add dependency on custom_callbacks
* Move test fixtures out of the test application root directory
* Improve documentation
* Remove the StateExtension module in favor of adding singleton methods to the stateful class
* Convert dos newlines to unix newlines
* Fix error message when a given event can't be found in the database
* Add before_#{action} and #{action} callbacks when an event is performed
* All state and event callbacks can now explicitly return false in order to cancel the action
* Refactor ActiveState callback creation
* Refactor unit tests so that they use mock classes instead of themselves
* Allow force_reload option to be set in the state association
* Don't save the entire model when updating the state_id
* Raise exception if a class tries to define a state more than once
* Add tests for PluginAWeek::Has::States::ActiveState
* Refactor active state/active event creation
* Fix owner_type not being set correctly in active states/events of subclasses
* Allow subclasses to override the initial state
* Fix problem with migrations using default null when column cannot be null
* Moved deadline support into a separate plugin (has_state_deadlines).
* Added many more unit tests.
* Simplified many of the interfaces for maintainability.
* Added support for turning off recording state changes.
* Removed the short_description and long_description columns, in favor of an optional human_name column.
* Fixed not overriding the correct equality methods in the StateTransition class.
* Added to_sym to State and Event.
* State#name and Event#name now return the string version of the name instead of the symbol version.
* Added State#human_name and Event#human_name to automatically figure out what the human name is if it isn't specified in the table.
* Updated manual rollbacks to use the new Rails edge api (ActiveRecord::Rollback exception).
* Moved StateExtension class into a separate file in order to help keep the has_state files clean.
* Renamed InvalidState and InvalidEvent exceptions to StateNotFound and EventNotFound in order to follow the ActiveRecord convention (i.e. RecordNotFound).
* Added StateNotActive and EventNotActive exceptions to help differentiate between states which don't exist and states which weren't defined in the class.
* Added support for defining callbacks like so:
  
  def before_exit_parked
  end
  
  def after_enter_idling
  end

* Added support for defining callbacks using class methods:
  
  before_exit_parked :fasten_seatbelt

* Added event callbacks after the transition has occurred (e.g. after_park)
* State callbacks no longer receive any of the arguments that were provided in the event action
* Updated license to include our names.
