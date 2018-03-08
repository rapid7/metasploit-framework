module Msf

module Auxiliary::PipeAudit
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super
	#register_options([
	#		OptString.new('RPORT', [true, 'The Target port', 445])
	#	], Msf::Auxiliary::PIPEAudit)
  end

  def connect_to_pipe()
		  accessible_pipes||=[]
	          a_pipe_handles||=[]
		  target_pipes = [
                'netlogon',
                'lsarpc',
                'samr',
                'browser',
                'atsvc',
                'DAV RPC SERVICE',
                'epmapper',
                'eventlog',
                'InitShutdown',
                'keysvc',
                'lsass',
                'LSM_API_service',
                'ntsvcs',
                'plugplay',
                'protected_storage',
                'router',
                'SapiServerPipeS-1-5-5-0-70123',
                'scerpc',
                'srvsvc',
                'tapsrv',
                'trkwks',
                'W32TIME_ALT',
                'wkssvc',
                'PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER',
                'db2remotecmd'
        ]
		
		target_pipes.each do |pipe|
		     begin
				pipe_name = "#{pipe}"
				pipe_handle = self.simple.create_pipe(pipe_name, 'o')
				accessible_pipes << pipe_name
			        a_pipe_handles << pipe_handle
		     end
      end
		return accessible_pipes[0], pipe_handle[0] 
  end
end
end

