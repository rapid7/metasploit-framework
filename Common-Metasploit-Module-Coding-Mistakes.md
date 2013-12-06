This is a collection of all the bad code we often see in Metasploit modules.  You should avoid them, too.

Note: Some of these examples use puts() for demo purposes, but you should always use print_status / print_error when writing a module.

### Bad Examples You Shouldn't Follow:

1. Not checking the return value of a Metasploit API
2. Ruby 1.9.3 vs 1.8.7... gotcha!
3. Not checking the return value when using match()
4. Not checking nil before accessing a method
5. Using exception handling to shut an error up
6. Not taking advantage of the 'ensure' block
7. Adding the 'VERBOSE' option
8. Avoid using 'vars_post' for send_request_cgi() when crafting a POST request
9. Bad variable naming style
10. Using global variables

**1. Not checking the return value of a Metasploit API**
```ruby
	res = send_request_cgi({
		'method' => 'GET',
		'uri' => '/app/index.php'
	})

	# There's a bug here, because res can return nil (due to a timeout or other reasons)
	# If that happens, you will hit a "undefined method `code' for nil:NilClass" error.
	# The correct way should be: if res and res.code == 200
	if res.code == 200
		print_status("Response looks good")
	else
		print_error("Unexpected response")
	end
```
**2. Ruby 1.9.3 vs 1.8.7... gotcha!**
```ruby
	some_string = "ABC"

	# This can cause unexpected results to your module.
	# Better to always do: char = some_string[1, 1]
	char = some_string[1]

	if char == 'B'
		puts "You will see this message in Ruby 1.9.3"
	elsif char == 66
		puts "You will see this message in Ruby 1.8.7"
	end
```
```ruby
	# 1.9 allows a comma after the last argument when calling 
	# a method while 1.8 does not.  The most common place to 
	# see this error is in the update_info() section in a
	# module's constructor.
	some_method(
		"arg1",
		"arg2",  # <-- This comma is a syntax error on 1.8.x
	)
```

**3. Not checking the return value when using match()**
```ruby
	str = "dragon! drag on! Not lizard, I don't do that tongue thing"

	# This tries to print "Not snake", but it's not in the string,
	# so you'll get this error: "undefined method `[]' for nil:NilClass"
	puts str.match(/(Not snake)/)[0]
```
```ruby
	# The above is better written as:
	if (str =~ /(Not snake)/)
		puts $1
	end
```

**4. Not checking nil first before accessing a method**
```ruby
	str = "These things are round and tasty, let's call them... tastycles!"

	food = str.scan(/donut holes/)[0]

	# food is nil, and nil has no method called "empty".
	# This will throw an error: "undefined method `empty?' for nil:NilClass"
	if food.empty? or food.nil?
		puts "I don't know what it's called"
	end
```
**5. Using exception handling to shut an error up**
```ruby
	begin
		# This block has 2 issues:
		# Issue #1: sample() is not a method in 1.8.7
		# Issue #2: Divided by 0 (race condition)
		n = [0, 1, 2, 3, 4, 5].sample
		1/n

	rescue
		# If the user reports a bug saying this code isn't
		# working, it can be hard to debug exactly what went
		# wrong for the user without a backtrace.
		# When you do this, the error also won't be logged in
		# framework.log, either.
		# Note that rescuing ::Exception is especially harmful
		# because it can even hide syntax errors.
	end
```
**6. Not taking advantage of the 'ensure' block**
```ruby
	# You should use the ensure block to make sure x always has a value,
	# which also avoids repeating code
	begin
		n = [0, 1, 2].sample
		x = 1/n
	rescue ZeroDivisionError => e
		puts "Are you smarter than a 5th grader? #{e.message}"
		x = 0  # Can put this in the ensure block
	rescue NoMethodError
		puts "You must be using an older Ruby"
		x = 0 # Can put this in the ensure block
	end

	puts "Value is #{x.to_s}"
```
**7. Adding the 'VERBOSE' option**
```ruby
	register_options(
		[
			# You already have this. Just type 'show advanced' and you'll see it.
			# So no need to register again
			OptBool.new("VERBOSE", [false, 'Enable detailed status messages', false])
		], self.class)
```
**8. Avoid using send_request_cgi()'s vars_get or vars_get when crafting a POST/GET request**
```ruby
	data_post = 'user=jsmith&pass=hello123'

	# You should use the 'vars_post' key instead of 'data',
	# unless you're trying to avoid the API escaping your
	# parameter names
	send_request_cgi({
		'method' => 'POST',
		'uri'    => '/',
		'data'   => data_post
	})
```
**9. Bad variable naming style**
```ruby
	# What's this, Java?
	# The proper naming style in this case should be: my_string
	myString = "hello, world"
```

**10. Using global variables**
```ruby
	# $msg is a global variable that can be accessed anywhere within the program.
	# This can induce bugs to other modules or mixins that are hard to debug.
	# Use @instance variables instead.
	# This is also mentioned in your HACKING file :-)

	class Opinion
		def initialize
			# This variable shouldn't be shared with other classes
			$msg = "It's called the Freedom of Information Act. The Hippies finally got something right."
		end
	end

	class Metasploit3
		def initialize
			puts $msg
		end
	end

	Opinion.new
	Metasploit3.new


```