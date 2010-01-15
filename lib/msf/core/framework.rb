require 'msf/core'
require 'msf/util'

module Msf

###
#
# This class is the primary context that modules, scripts, and user
# interfaces interact with.  It ties everything together.
#
###
class Framework

	#
	# Versioning information
	#

	Major    = 3
	Minor    = 3
	Point    = 4
	Release  = "-dev"

	if(Point)
		Version  = "#{Major}.#{Minor}.#{Point}#{Release}"
	else
		Version  = "#{Major}.#{Minor}#{Release}"
	end

	Revision = "$Revision$"


	# Repository information
	RepoRevision        = ::Msf::Util::SVN.revision
	RepoUpdated         = ::Msf::Util::SVN.updated
	RepoUpdatedDays     = ::Msf::Util::SVN.days_since_update
	RepoUpdatedDaysNote = ::Msf::Util::SVN.last_updated_friendly
	RepoUpdatedDate     = ::Msf::Util::SVN.last_updated_date
	RepoRoot            = ::Msf::Util::SVN.root

	# API Version
	APIMajor = 1
	APIMinor = 0

	# Base/API Version
	VersionCore  = Major + (Minor / 10.0)
	VersionAPI   = APIMajor + (APIMinor / 10.0)

	#
	# Mixin meant to be included into all classes that can have instances that
	# should be tied to the framework, such as modules.
	#
	module Offspring

		#
		# A reference to the framework instance from which this offspring was
		# derived.
		#
		attr_accessor :framework
	end

	require 'msf/core/module_manager'
	require 'msf/core/session_manager'
	require 'msf/core/db_manager'
	require 'msf/core/event_dispatcher'

	#
	# Creates an instance of the framework context.
	#
	def initialize(opts={})

		# Allow specific module types to be loaded
		types = opts[:module_types] || MODULE_TYPES

		self.events    = EventDispatcher.new(self)
		self.modules   = ModuleManager.new(self,types)
		self.sessions  = SessionManager.new(self)
		self.datastore = DataStore.new
		self.jobs      = Rex::JobContainer.new
		self.plugins   = PluginManager.new(self)
		self.db        = DBManager.new(self)
		
		subscriber = FrameworkEventSubscriber.new(self)
		events.add_exploit_subscriber(subscriber)
		events.add_session_subscriber(subscriber)
		events.add_general_subscriber(subscriber)
		events.add_db_subscriber(subscriber)
		events.add_ui_subscriber(subscriber)
	end

	def inspect
		"#<Framework (#{sessions.length} sessions, #{jobs.length} jobs, #{plugins.length} plugins#{db.active ? ", #{db.driver} database active" : ""})>"
	end

	#
	# Returns the module set for encoders.
	#
	def encoders
		return modules.encoders
	end

	#
	# Returns the module set for exploits.
	#
	def exploits
		return modules.exploits
	end

	#
	# Returns the module set for nops
	#
	def nops
		return modules.nops
	end

	#
	# Returns the module set for payloads
	#
	def payloads
		return modules.payloads
	end

	#
	# Returns the module set for auxiliary modules
	#
	def auxiliary
		return modules.auxiliary
	end

	#
	# Returns the framework version in Major.Minor format.
	#
	def version
		Version
	end

	#
	# Event management interface for registering event handler subscribers and
	# for interacting with the correlation engine.
	#
	attr_reader   :events
	#
	# Module manager that contains information about all loaded modules,
	# regardless of type.
	#
	attr_reader   :modules
	#
	# Session manager that tracks sessions associated with this framework
	# instance over the course of their lifetime.
	#
	attr_reader   :sessions
	#
	# The global framework datastore that can be used by modules.
	#
	attr_reader   :datastore
	#
	# The framework instance's aux manager.  The aux manager is responsible
	# for collecting and catalogging all aux information that comes in from
	# aux modules.
	#
	attr_reader   :auxmgr
	#
	# Background job management specific to things spawned from this instance
	# of the framework.
	#
	attr_reader   :jobs
	#
	# The framework instance's plugin manager.  The plugin manager is
	# responsible for exposing an interface that allows for the loading and
	# unloading of plugins.
	#
	attr_reader   :plugins
	#
	# The framework instance's db manager. The db manager
	# maintains the database db and handles db events
	#
	attr_reader   :db

protected

	attr_writer   :events # :nodoc:
	attr_writer   :modules # :nodoc:
	attr_writer   :sessions # :nodoc:
	attr_writer   :datastore # :nodoc:
	attr_writer   :auxmgr # :nodoc:
	attr_writer   :jobs # :nodoc:
	attr_writer   :plugins # :nodoc:
	attr_writer   :db # :nodoc:
end

class FrameworkEventSubscriber
	include Framework::Offspring
	def initialize(framework)
		self.framework = framework
	end

	def report_event(data)
		data.merge!(:user => ENV['USER'])
		framework.db.report_event(data)
	end

	include GeneralEventSubscriber
	def on_module_run(instance)
		info = {}
		info[:module_name] = instance.refname
		info[:datastore] = instance.datastore
		report_event(:name => "module_run", :info => info)
	end

	include ::Msf::UiEventSubscriber
	def on_ui_command(command)
		report_event(:name => "ui_command", :info => {:command => command})
	end

	def on_ui_stop()
		report_event(:name => "ui_stop")
	end

	def on_ui_start(rev)
		#
		# The database is not active at startup time, so this event can never
		# be saved to the db.  Might look into storing it in a flat file or
		# something later.
		#
		#info = { :revision => rev }
		#report_event(:name => "ui_start", :info => info)
	end

	require 'msf/core/session'
	include ::Msf::SessionEvent
	def on_session_open(session)
		info = { :session_id => session.sid }
		info[:via_exploit] = session.via_exploit

		# Strip off the port
		address = session.tunnel_peer[0, session.tunnel_peer.rindex(":")]
		host = framework.db.find_or_create_host(:host=>address)

		report_event(:name => "session_open", :info => info, :host_id => host.id)
	end

	def on_session_close(session)
		info = { :session_id => session.sid }

		# Strip off the port
		address = session.tunnel_peer[0, session.tunnel_peer.rindex(":")]
		host = framework.db.find_or_create_host(:host=>address)

		report_event(:name => "session_close", :info => info, :host_id => host.id)
	end

	def on_session_interact(session)
		info = { :session_id => session.sid }

		# Strip off the port
		address = session.tunnel_peer[0, session.tunnel_peer.rindex(":")]
		host = framework.db.find_or_create_host(:host=>address)

		report_event(:name => "session_interact", :info => info, :host_id => host.id)
	end

	def on_session_command(session, command)
		info = { :session_id => session.sid, :command => command }

		# Strip off the port
		address = session.tunnel_peer[0, session.tunnel_peer.rindex(":")]
		host = framework.db.find_or_create_host(:host=>address)

		report_event(:name => "session_command", :info => info, :host_id => host.id)
	end


	# 
	# This is covered by on_module_run and on_session_open, so don't bother
	#
	#require 'msf/core/exploit'
	#include ExploitEvent
	#def on_exploit_success(exploit, session)
	#end

end
end

