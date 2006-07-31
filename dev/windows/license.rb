#!/usr/bin/env ruby


exit(0) if (File.exists?(".LICENSED"))

while (true)
	$stdout.puts "You must agree to the license terms before using this software."
	$stdout.write "Press enter to continue."
	$stdin.gets

	system("less -e LICENSE")
	$stdout.puts ""

	$stdout.write "Accept this license? (yes/no) > "
	$stdout.flush
	answer = $stdin.gets

	$stdout.puts ""

	if (answer and answer =~ /^yes/i)
		fd = File.open(".LICENSED", "w")
		fd.write(answer)
		fd.close
		exit(0)
	end

	if (answer and answer =~ /^no/i)
		$stdout.puts ""
		$stdout.puts "Sorry, you must accept the license to use this software."
		$stdout.puts "Press enter to quit."
		$stdin.gets
		exit(1)	
	end

	if (! answer)
		exit(1)
	end
end
