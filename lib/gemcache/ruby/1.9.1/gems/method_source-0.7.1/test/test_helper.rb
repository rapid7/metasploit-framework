def is_rbx?
  defined?(RUBY_ENGINE) && RUBY_ENGINE =~ /rbx/
end

def jruby?
  defined?(RUBY_ENGINE) && RUBY_ENGINE =~ /jruby/
end


module M
  def hello; :hello_module; end
end

$o = Object.new
def $o.hello; :hello_singleton; end

# A comment for hello

  # It spans two lines and is indented by 2 spaces
def hello; :hello; end

# a
# b
def comment_test1; end

 # a
 # b
def comment_test2; end

# a
#
# b
def comment_test3; end

# a

# b
def comment_test4; end


# a
  # b
    # c
# d
def comment_test5; end

# This is a comment for MyLambda
MyLambda = lambda { :lambda }
MyProc = Proc.new { :proc }

