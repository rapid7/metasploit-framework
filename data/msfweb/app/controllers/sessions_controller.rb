#
# Author: Metasploit LLC
# Description: The AJAX console controller of msfweb
#

class SessionsController < ApplicationController
  layout 'windows'
  
  def list
    @sessions = Session.find_all()
  end

  def stop
  end

  def interact
		# Work around rails stupidity
		if(not $webrick_hooked_session)

			$webrick.mount_proc("/_session") do |req, res|

				res['Content-Type'] = "text/javascript"

				m = req.path_info.match(/cid=(\d+)/)
				if (m and m[1] and $msfweb.sessions[m[1].to_i])
					cid = m[1].to_i

					$msfweb.connect_session(cid)
					
					out = ''
					tsp = Time.now.to_i

					# Poll the session output for 15 seconds
					while( tsp + 15 > Time.now.to_i and out.length == 0)
						out = $msfweb.read_session(cid)
						select(nil, nil, nil, 0.10)
					end

					out = out.unpack('C*').map{|c| sprintf("%%%.2x", c)}.join

					script =  "// Metasploit Web Session Data\n"
					script += "var ses_update = unescape('#{out}');\n"

					res.body = script
				else
					res.body = '// Invalid session ID'
				end
			end

			$webrick_hooked_session = true
		end

		cid = params[:id].to_i
		$msfweb.connect_session(cid)

		if(params[:cmd])

			if (params[:cmd].strip.length > 0)
				$msfweb.write_session(cid, params[:cmd] + "\n")
			end

			script =  "// Metasploit Web Session Data\n"
			script += "var ses_update = unescape('');\n"

			send_data(script, :type => "text/javascript")
		end

	end
end

