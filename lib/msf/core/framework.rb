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
		if framework.db.active
			framework.db.report_event(data)
		end
	end

	include GeneralEventSubscriber

	#
	# Generic handler for module events
	#
	def module_event(name, instance, opts={})
		if framework.db.active
			event = {
				:workspace => framework.db.find_workspace(instance.workspace),
				:name      => name,
				:username  => instance.owner,
				:info => {
					:module_name => instance.fullname,
				}.merge(opts)
			}

			report_event(event)
		end
	end
	def on_module_run(instance)
		opts = { :datastore => instance.datastore.to_h }
		module_event('module_run', instance, opts)
	end

	def on_module_complete(instance)
		module_event('module_complete', instance)
	end

	def on_module_error(instance, exception=nil)
		module_event('module_error', instance, :exception => exception.to_s)
	end

	include ::Msf::UiEventSubscriber
	def on_ui_command(command)
		if framework.db.active
			report_event(:name => "ui_command", :info => {:command => command})
		end
	end

	def on_ui_stop()
		if framework.db.active
			report_event(:name => "ui_stop")
		end
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

	#
	# Generic handler for session events
	#
	def session_event(name, session, opts={})
		if session.respond_to? :peerhost
			address = session.peerhost
		elsif session.respond_to? :tunnel_peer
			address = session.tunnel_peer[0, session.tunnel_peer.rindex(":") || session.tunnel_peer.length ]
		elsif session.respond_to? :target_host
			address = session.target_host
		else
			elog("Session with no peerhost/tunnel_peer")
			dlog("#{session.inspect}", LEV_3)
			return
		end

		if framework.db.active
			ws = framework.db.find_workspace(session.workspace)
			event = {
				:workspace => ws,
				:username  => session.username,
				:name => name,
				:host => address,
				:info => {
					:session_id   => session.sid,
					:session_info => session.info,
					:session_uuid => session.uuid,
					:session_type => session.type,
					:username     => session.username,
					:target_host  => session.target_host,
					:via_exploit  => session.via_exploit,
					:via_payload  => session.via_payload
				}.merge(opts)
			}
			report_event(event)
		end
	end

	require 'msf/core/session'
	include ::Msf::SessionEvent
	def on_session_open(session)
		opts = { :datastore => session.exploit_datastore.to_h, :critical => true }
		session_event('session_open', session, opts)
		if framework.db.active
			# Copy/paste ftw
			if session.respond_to? :peerhost
				address = session.peerhost
			elsif session.respond_to? :tunnel_peer
				address = session.tunnel_peer[0, session.tunnel_peer.rindex(":") || session.tunnel_peer.length ]
			elsif session.respond_to? :target_host
				address = session.target_host
			else
				elog("Session with no peerhost/tunnel_peer")
				dlog("#{session.inspect}", LEV_3)
				return
			end
			# Since we got a session, we know the host is vulnerable to something.
			# If the exploit used was multi/handler, though, we don't know what
			# it's vulnerable to, so it isn't really useful to save it.
			if session.via_exploit and session.via_exploit != "exploit/multi/handler"
				mod = framework.modules.create(session.via_exploit)
				info = {
					:host => address,
					:name => session.via_exploit,
					:refs => mod.references,
					:workspace => framework.db.find_workspace(session.workspace)
				}
				framework.db.report_vuln(info)
			end
		end
	end

	def on_session_close(session, reason='')
		session_event('session_close', session)
	end

	def on_session_interact(session)
		session_event('session_interact', session)
	end

	def on_session_command(session, command)
		session_event('session_command', session, :command => command)
	end

	def on_session_output(session, output)
		# Break up the output into chunks that will fit into the database.
		buff = output.dup
		chunks = []
		if buff.length > 1024
			while buff.length > 0
				chunks << buff.slice!(0,1024)
			end
		else
			chunks << buff
		end
		chunks.each { |chunk|
			session_event('session_output', session, :output => chunk)
		}
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

