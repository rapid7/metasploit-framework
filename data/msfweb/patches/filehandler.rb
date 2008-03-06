#
# Monkey patch the webrick vulnerability
#

$stderr.puts "[*] WEBrick directory traversal patch loaded"

module WEBrick
  module HTTPServlet

    class FileHandler < AbstractServlet

      def service(req, res)
        # if this class is mounted on "/" and /~username is requested.
        # we're going to override path informations before invoking service.
        if defined?(Etc) && @options[:UserDir] && req.script_name.empty?
          if %r|^(/~([^/]+))| =~ req.path_info
            script_name, user = $1, $2
            path_info = $'
            begin
              passwd = Etc::getpwnam(user)
              @root = File::join(passwd.dir, @options[:UserDir])
              req.script_name = script_name
              req.path_info = path_info
            rescue
              @logger.debug "#{self.class}#do_GET: getpwnam(#{user}) failed"
            end
          end
        end
        prevent_directory_traversal(req, res)
        super(req, res)
      end
	  
      private

      def prevent_directory_traversal(req, res)
        # Preventing directory traversal on DOSISH platforms;
        # Backslashes (0x5c) in path_info are not interpreted as special
        # character in URI notation. So the value of path_info should be
        # normalize before accessing to the filesystem.
        if File::ALT_SEPARATOR
          # File.expand_path removes the trailing path separator.
          # Adding a character is a workaround to save it.
          #  File.expand_path("/aaa/")        #=> "/aaa"
          #  File.expand_path("/aaa/" + "x")  #=> "/aaa/x"
          expanded = File.expand_path(req.path_info + "x")
          expanded[-1, 1] = ""  # remove trailing "x"
          req.path_info = expanded
        end
      end

      def check_filename(req, res, name)
        @options[:NondisclosureName].each{|pattern|
          if File.fnmatch("/#{pattern}", name, File::FNM_CASEFOLD)
            @logger.warn("the request refers nondisclosure name `#{name}'.")
            raise HTTPStatus::NotFound, "`#{req.path}' not found."
          end
        }
      end

      def nondisclosure_name?(name)
        @options[:NondisclosureName].each{|pattern|
          if File.fnmatch(pattern, name, File::FNM_CASEFOLD)
            return true
          end
        }
        return false
      end
	  
    end
  end
end
