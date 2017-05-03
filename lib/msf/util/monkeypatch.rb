# Monkeypatches to core Ruby libraries. Please use sparingly

# NilClass should respond to empty?() and return true. The
# justification for this is that when people test for
# variable emptiness, you usually have to check twice:
#
#    var.nil? or var.empty?
# 
# This seems wasteful and it's a pretty common bug to 
# simply check for var.empty? without first checking for
# nil -- which seems to imply that the (lazy) idiom is
# just check empty?()
#
# I can contrive examples where a user might want to:
#
#    case var
#      when nil ; do_a_nil_thing()
#      when ""  ; do_a_blank_thing()
#      else     ; do_another_thing)
#    end
#
# But I can't recall ever seeing that in real life.
class NilClass
	def empty?
		true
	end
end
