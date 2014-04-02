#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# searches an object in the attributes of another
# anyobj.scan_for([obj])  =>  "anyobj.someattr[42]['blabla']"

class Object
	def scan_iter
		case self
		when ::Array
			length.times { |i| yield self[i], "[#{i}]" }
		when ::Hash
			each { |k, v| yield v, "[#{k.inspect}]" ; yield k, "(key)" }
		else
			instance_variables.each { |i| yield instance_variable_get(i), ".#{i[1..-1]}" }
		end
	end

	# dumps to stdout the path to find some targets ( array of objects to match with == )
	def scan_for(targets, path='', done={})
		done[object_id] = self if done.empty?
		if t = targets.find { |t_| self == t_ }
			puts "found #{t} at #{path}"
		end
		scan_iter { |v, p|
			case v
			when Fixnum, Symbol; next
			end
			p = path+p
			if done[v.object_id]
				puts "loop #{p} -> #{done[v.object_id]}" if $VERBOSE
			else
				done[v.object_id] = p
				v.scan_for(targets, p, done)
			end
		}
	end
end
