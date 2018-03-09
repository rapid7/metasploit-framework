module Msf

module Exploit::Remote::SMB::Client::PipeAudit
  include Msf::Exploit::Remote::SMB::Client

  def initialize(info = {})
    super
	register_options(
      [
        OptPath.new('NAMED_PIPES_FILE', [ true, "List of known named pipes",
          File.join(Msf::Config.data_directory, "wordlists", "namedpipes.txt")]),
      ])
  end

  def connect_to_pipe()
    accessible_pipes||=[]
    a_pipe_handles||=[]
    target_pipes = []
	pipe_file = datastore['NAMED_PIPES_FILE']
	if (!pipe_file)
       print_error("File with named pipes is needed")
    end
	File.open(pipe_file, 'rb') { |f| target_pipes += f.readlines.split("\n")[0] }
    target_pipes.each do |pipe|
       begin
         pipe_name = "#{pipe}"
         pipe_handle = self.simple.create_pipe(pipe_name, 'o')
         print_status("Accessible pipe found: #{pipe_name}")
	 pipe_found = 1
	 ret_pipe = pipe_name
	 accessible_pipes << pipe_name
       rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
	 vprint_status("Inaccessible named pipe #{pipe_name} - #{e.message}")
       
       end
       if pipe_found == 1
	       vprint_status("Returning #{ret_pipe} with handle #{pipe_handle.to_s}to exploit")
	       return ret_pipe, pipe_handle
       end
    end
  end
end
end

