#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# This sample hacks in the ruby interpreter to allow dynamic loading of shellcodes as object methods
# Also it allows raw modifications to the ruby interpreter memory, for all kind of purposes
# Includes methods to dump the ruby parser AST from the interpreter memory
# elf/linux/x86 only

require 'metasm'


module Metasm
module RubyHack
	CACHEDIR = File.expand_path('~/.metasm/jit_cache/')
	# basic C defs for ruby internals - 1.8 only !
	RUBY_H = <<EOS
typedef unsigned long VALUE;

struct st_table;

struct klass {
	long flags;
	VALUE klass;
	struct st_table *iv_tbl;
	struct st_table *m_tbl;
	VALUE super;
};
#define RClass(x) ((struct klass *)(x))
#define RModule RClass

struct string {
	long flags;
	VALUE klass;
	long len;
	char *ptr;
	union {
		long capa;
		VALUE shared;
	} aux;
};
#define RString(x) ((struct string *)(x))

struct node {
	long flags;
	char *file;
	long a1;
	long a2;
	long a3;
};
#define FL_USHIFT 11
#define nd_type(n) ((((struct node*)n)->flags >> FL_USHIFT) & 0xff)

extern VALUE rb_cObject;
extern VALUE rb_eRuntimeError;
#define Qfalse ((VALUE)0)
#define Qtrue  ((VALUE)2)
#define Qnil   ((VALUE)4)
#define FIX2LONG(x) (((long)x) >> 1)

VALUE rb_uint2inum(unsigned long);
unsigned long rb_num2ulong(VALUE);

VALUE rb_str_new(const char* ptr, long len);	// alloc + memcpy + 0term

int rb_intern(char *);
VALUE rb_funcall(VALUE recv, int id, int nargs, ...);
VALUE rb_const_get(VALUE, int);
VALUE rb_raise(VALUE, char*);
void rb_define_method(VALUE, char *, VALUE (*)(), int);
void rb_define_singleton_method(VALUE, char *, VALUE (*)(), int);
int rb_to_id(VALUE);
struct node* rb_method_node(VALUE klass, int id);
VALUE rb_str_new(char*, int);


// TODO setup those vars auto or define a standard .import/.export (elf/pe/macho)
#ifdef METASM_TARGET_ELF
asm .global "rb_cObject" undef type=NOTYPE;		// TODO fix elf encoder to not need this
asm .global "rb_eRuntimeError" undef type=NOTYPE;
#endif
EOS
        NODETYPE = [
		:method, :fbody, :cfunc, :scope, :block,
		:if, :case, :when, :opt_n, :while,
		:until, :iter, :for, :break, :next,
		:redo, :retry, :begin, :rescue, :resbody,
		:ensure, :and, :or, :not, :masgn,
		:lasgn, :dasgn, :dasgn_curr, :gasgn, :iasgn,
		:cdecl, :cvasgn, :cvdecl, :op_asgn1, :op_asgn2,
		:op_asgn_and, :op_asgn_or, :call, :fcall, :vcall,
		:super, :zsuper, :array, :zarray, :hash,
		:return, :yield, :lvar, :dvar, :gvar, # 50
		:ivar, :const, :cvar, :nth_ref, :back_ref,
		:match, :match2, :match3, :lit, :str,
		:dstr, :xstr, :dxstr, :evstr, :dregx,
		:dregx_once, :args, :argscat, :argspush, :splat,
		:to_ary, :svalue, :block_arg, :block_pass, :defn,
		:defs, :alias, :valias, :undef, :class,
		:module, :sclass, :colon2, :colon3, :cref,
		:dot2, :dot3, :flip2, :flip3, :attrset,
		:self, :nil, :true, :false, :defined,
		:newline, :postexe, :alloca, :dmethod, :bmethod, # 100
		:memo, :ifunc, :dsym, :attrasgn, :last
	]


	# create and load a ruby module that allows
	# to use a ruby string as the binary code implementing a ruby method
	# enable the use of .load_binary_method(class, methodname, string)
	def self.load_bootstrap
		c_source = <<EOS
#define METASM_TARGET_ELF

#{RUBY_H}

void mprotect(int, int, int);
asm .global mprotect undef;

static VALUE set_class_method_raw(VALUE self, VALUE klass, VALUE methname, VALUE rawcode, VALUE nparams)
{
	int raw = (int)RString(rawcode)->ptr;
	mprotect(raw & 0xfffff000, ((raw+RString(rawcode)->len+0xfff) & 0xfffff000) - (raw&0xfffff000), 7);	// RWX
	rb_define_method(klass, RString(methname)->ptr, RString(rawcode)->ptr, FIX2LONG(nparams));
	return Qtrue;
}

static VALUE memory_read(VALUE self, VALUE addr, VALUE len)
{
	return rb_str_new((char*)rb_num2ulong(addr), (int)rb_num2ulong(len));
}

static VALUE memory_write(VALUE self, VALUE addr, VALUE val)
{
	char *src = RString(val)->ptr;
	char *dst = (char*)rb_num2ulong(addr);
	int len = RString(val)->len;
	while (len--)
		*dst++ = *src++;
	return val;
}

static VALUE memory_read_int(VALUE self, VALUE addr)
{
	return rb_uint2inum(*(unsigned long*)rb_num2ulong(addr));
}

static VALUE memory_write_int(VALUE self, VALUE addr, VALUE val)
{
	*(unsigned long*)rb_num2ulong(addr) = rb_num2ulong(val);
	return val;
}

extern void *dlsym(int handle, char *symname);
#define RTLD_DEFAULT 0
asm .global dlsym undef;

static VALUE dl_dlsym(VALUE self, VALUE symname)
{
	return rb_uint2inum((unsigned)dlsym(RTLD_DEFAULT, RString(symname)->ptr));
}

static VALUE get_method_node_ptr(VALUE self, VALUE klass, VALUE id)
{
	return rb_uint2inum((unsigned)rb_method_node(klass, rb_to_id(id)));
}

static VALUE id2ref(VALUE self, VALUE id)
{
	return rb_num2ulong(id);
}

int Init_metasm_binload(void)
{
	VALUE metasm = rb_const_get(rb_cObject, rb_intern("Metasm"));
	VALUE rubyhack = rb_const_get(metasm, rb_intern("RubyHack"));
	rb_define_singleton_method(rubyhack, "set_class_method_raw", set_class_method_raw, 4);
	rb_define_singleton_method(rubyhack, "memory_read", memory_read, 2);
	rb_define_singleton_method(rubyhack, "memory_write", memory_write, 2);
	rb_define_singleton_method(rubyhack, "memory_read_int", memory_read_int, 1);
	rb_define_singleton_method(rubyhack, "memory_write_int", memory_write_int, 2);
	rb_define_singleton_method(rubyhack, "get_method_node_ptr", get_method_node_ptr, 2);
	rb_define_singleton_method(rubyhack, "dlsym", dl_dlsym, 1);
	rb_define_singleton_method(rubyhack, "id2ref", id2ref, 1);
	return 0;
}
asm .global Init_metasm_binload;

asm .soname "metasm_binload";
asm .nointerp;
asm .pt_gnu_stack rw;
EOS
		
		`mkdir -p #{CACHEDIR}` if not File.directory? CACHEDIR
		stat = File.stat(__FILE__)	# may be relative, do it before chdir
		Dir.chdir(CACHEDIR) {
			if not File.exist? 'metasm_binload.so' or File.stat('metasm_binload.so').mtime < stat.mtime
				compile_c(c_source, ELF).encode_file('metasm_binload.so')
			end
			require 'metasm_binload'
		}
		# TODO Windows support
		# TODO PaX support (write + mmap, in user-configurable dir?)
	end

	def self.cpu
		# TODO check runtime environment etc
		@cpu ||= Ia32.new
	end

	def self.compile_c(c_src, exeformat=Shellcode)
		exeformat.compile_c(cpu, c_src)
	end

	load_bootstrap

	# sets up rawopcodes as the method implementation for class klass
	# rawopcodes must implement the expected ABI or things will break horribly
	# this method is VERY UNSAFE, and breaks everything put in place by the ruby interpreter
	# use with EXTREME CAUTION
	# nargs  arglist
	# -2     self, arg_ary
	# -1     argc, VALUE*argv, self
	# >=0    self, arg0, arg1..
	def self.set_method_binary(klass, methodname, raw, nargs=-2)
		if raw.kind_of? EncodedData
			baseaddr = memory_read_int((raw.data.object_id << 1) + 12)
			bd = raw.binding(baseaddr)
			raw.reloc_externals.uniq.each { |ext| bd[ext] = dlsym(ext) or raise "unknown symbol #{ext}" }
			raw.fixup(bd)
			raw = raw.data
		end
		(@@prevent_gc ||= {})[[klass, methodname]] = raw
		set_class_method_raw(klass, methodname.to_s, raw, nargs)
	end

	# same as load_binary_method but with an object and not a class
	def self.set_object_method_binary(obj, *a)
		set_method_binary((class << obj ; self ; end), *a)
	end

	def self.object_pointer(obj)
		(obj.object_id << 1) & 0xffffffff
	end

	def self.read_node(ptr, cur=nil)
		return if ptr == 0


		type = NODETYPE[(memory_read_int(ptr) >> 11) & 0xff]
		v1 = memory_read_int(ptr+8)
		v2 = memory_read_int(ptr+12)
		v3 = memory_read_int(ptr+16)

		case type
		when :block, :array, :hash
			cur = nil if cur and cur[0] != type
			cur ||= [type]
			cur << read_node(v1)
			n = read_node(v3, cur)
			raise "block->next = #{n.inspect}" if n and n[0] != type
			cur
		when :newline
			read_node(v3)	# debug/trace usage only
		when :if
			[type, read_node(v1), read_node(v2), read_node(v3)]
		when :cfunc
			[type, {:fptr => v1,	# c func pointer
				:arity => v2}]
		when :scope
			[type, {:localnr => memory_read_int(v1),	# nr of local vars (+2 for $_/$~)
				:cref => v2},	# node, starting point for const resolution
				read_node(v3)]
		when :call, :fcall, :vcall
			# TODO check fcall/vcall
			ret = [type, read_node(v1), v2.id2name]
			if args = read_node(v3)
				raise "#{ret.inspect} with args != array: #{args.inspect}" if args[0] != :array
				ret.concat args[1..-1]
			end
			ret
		when :zarray
			[:array, []]
		when :lasgn
			[type, v3, read_node(v2)]
		when :iasgn, :dasgn, :dasgn_curr, :gasgn, :cvasgn
			[type, v1.id2name, read_node(v2)]
		when :masgn
			[type, read_node(v1), read_node(v2)]	# multiple assignment: a, b = 42 / lambda { |x, y| }.call(1, 2)
		when :attrasgn
			[type, ((v1 == 1) ? :self : read_node(v1)), v2.id2name, read_node(v3)]
		when :lvar
			[type, v3]
		when :ivar, :dvar, :gvar, :cvar, :const
			[type, v1.id2name]
		when :str
			# cannot use _id2ref here, probably the parser does not use standard alloced objects
			s = memory_read(memory_read_int(v1+12), memory_read_int(v1+16))
			[type, s]
		when :lit
			[type, id2ref(v1)]
		when :args	# specialcased by rb_call0, invalid in rb_eval
			cnt = v3	# nr of required args, copied directly to local_vars
			opt = read_node(v1)	# :block to execute for each missing arg / with N optargs specified, skip N 1st statements
			rest = read_node(v2)	# catchall arg in def foo(rq1, rq2, *rest)
			[type, cnt, opt, rest]
		when :and, :or
			[type, read_node(v1), read_node(v2)]	# shortcircuit
		when :not
			[type, read_node(v2)]
		when :nil, :true, :false, :self
			[type]
		when :redo, :retry
			[type]
		when :case, :when
			[type, read_node(v1), read_node(v2), read_node(v3)]
		when :iter
			# save a block for the following funcall
			args = read_node(v1)	# assignments with nil, not realized, just to store the arg list (multi args -> :masgn)
			body = read_node(v2)	# the body statements (multi -> :block)
			subj = read_node(v3)	# the stuff which is passed the block, probably a :call
			[type, args, body, subj]
		when :while
			[type, read_node(v1), read_node(v2), v3]
		when :return, :break, :next
			[type, read_node(v1)]
		when :colon3	# ::Stuff
			[type, v2.id2name]
		else
			puts "unhandled #{type.inspect}"
			[type, v1, v2, v3]
		end
	end

	def self.[](a, l=nil)
		if a.kind_of? Range
			memory_read(a.begin, a.end-a.begin+(a.exclude_end? ? 0 : 1))
		elsif l
			memory_read(a, l)
		else
			memory_read_int(a)
		end
	end

	def self.[]=(a, l, v=nil)
		l, v = v, l if not v
		if a.kind_of? Range
			memory_write(a.begin, v)
		elsif l
			memory_write(a, v)
		else
			memory_write_int(a, v)
		end
	end

	def self.compile_ruby(klass, meth)
		ptr = get_method_node_ptr(klass, meth)
		ast = read_node(ptr)
		require 'pp'
		pp ast
		return if not c = ruby_ast_to_c(ast)
		puts c
		raw = compile_c(c).encoded
		set_method_binary(klass, meth, raw, klass.instance_method(meth).arity)
	end

	def self.ruby_ast_to_c(ast)
		return if ast[0] != :scope
		cp = cpu.new_cparser
		cp.parse RUBY_H
		cp.parse 'void meth(VALUE self) { }'
		cp.toplevel.symbol['meth'].type.type = cp.toplevel.symbol['VALUE']
		scope = cp.toplevel.symbol['meth'].initializer
		RubyCompiler.new(cp).compile(ast, scope)
		cp.dump_definition('meth')
	end
end

class RubyCompiler
	def initialize(cp)
		@cp = cp
	end

	def compile(ast, scope)
		@scope = scope
		ast[1][:localnr].times { |lnr|
			next if lnr < 2	# TODO check usage of $~ / $_
			# TODO args
			# TODO analyse to find numeric locals (to avoid useless INT2FIX)
			l = C::Variable.new("local_#{lnr}", value)
			l.initializer = C::CExpression[[nil.object_id], l.type]
			scope.symbol[l.name] = l
			scope.statements << C::Declaration.new(l)
		}
		scope.statements << C::Return.new(ast_to_c(ast[2], scope))
	end

	def value
		@cp.toplevel.symbol['VALUE']
	end

	def local(n)
		@scope.symbol["local_#{n}"]
	end

	def rb_intern(n)
		C::CExpression[@cp.toplevel.symbol['rb_intern'], :funcall, [n]]
	end

	def rb_funcall(recv, meth, *args)
		C::CExpression[@cp.toplevel.symbol['rb_funcall'], :funcall, [recv, rb_intern(meth), [args.length], *args]]
	end

	def ast_to_c(ast, scope)
		ret = 
		case ast.to_a[0]
		when :block
			ast[1..-1].map { |a| ast_to_c(a, scope) }.last
		when :lasgn
			l = local(ast[1])
			scope.statements << C::CExpression[l, :'=', ast_to_c(ast[2], scope)]
			l
		when :lvar
			local(ast[1])
		when :lit
			case ast[1]
			when Symbol
				rb_intern(ast[1])
			else	# true/false/nil/fixnum
				ast[1].object_id
			end
		when :str
			C::CExpression[@cp.toplevel.symbol['rb_str_new'], :funcall, [ast[1], [ast[1].length]]]
		when :iter
			b_args, b_body, b_recv = ast[1, 3]
			if b_recv[0] == :call and b_recv[2] == 'times'	# TODO check its Fixnum#times
				recv = ast_to_c(b_recv[1], scope)
				cntr = C::Variable.new("cntr", C::BaseType.new(:int))	# TODO uniq name etc
				cntr.initializer = C::CExpression[[0]]
				init = C::Block.new(scope)
				init.symbol[cntr.name] = cntr
				body = C::Block.new(init)
				scope.statements << C::For.new(init, C::CExpression[cntr, :<, [recv, :>>, 1]], C::CExpression[:'++', cntr], body)
				body.symbol[cntr.name] = cntr
				ast_to_c(b_body, body)
				recv
			else
				puts "unsupported #{ast.inspect}"
				nil.object_id
			end
		when :call
			f = rb_funcall(ast_to_c(ast[1], scope), ast[2], *ast[3..-1].map { |a| ast_to_c(a, scope) })
			case ast[2]
			when '+', '-'
				tmp = C::Variable.new('tmp', value)
				if not scope.symbol_ancestors['tmp']
					scope.symbol['tmp'] = tmp
					scope.statements << C::Declaration.new(tmp)
				end
				a1 = [ast_to_c(ast[1], scope), C::BaseType.new(:int)]
				a3 = [ast_to_c(ast[3], scope), C::BaseType.new(:int)]
				scope.statements <<
				C::If.new(C::CExpression[[a1, :&, a3], :&, 1],	# XXX overflow to Bignum
					  C::CExpression[tmp, :'=', [a1, ast[2].to_sym, [a3, :-, [1]]]],
					  C::CExpression[tmp, :'=', f])
				tmp
			else
				f
			end
		when nil, :nil, :args
			nil.object_id
		else
			puts "unsupported #{ast.inspect}"
			nil.object_id
		end
		ret = [ret] if ret.kind_of? Integer
		C::CExpression[ret, value]
	end
end
end




if __FILE__ == $0

demo = ARGV.empty? ? :test_jit : :dump_ruby_ast

case demo	# chose your use case !
when :inlineasm

# cnt.times { sys_write str }
src_asm = <<EOS
mov ecx, [ebp+8]
again:
push ecx
mov eax, 4
mov ebx, 1
mov ecx, [ebp+12]
mov edx, [ebp+16]
int 80h
pop ecx
loop again
EOS

src = <<EOS

#{Metasm::RubyHack::RUBY_H}

void doit(int, char*, int);
VALUE foo(VALUE self, VALUE count, VALUE str) {
	doit(FIX2LONG(count), RString(str)->ptr, RString(str)->len);
	return count;
}

void doit(int count, char *str, int strlen) {
	asm(#{src_asm.inspect});
}
EOS

m = Metasm::RubyHack.compile_c(src).encode_string

o = Object.new
Metasm::RubyHack.set_object_method_binary(o, 'bar', m, 2)

puts "test1"
o.bar(4, "blabla\n")
puts "test2"
o.bar(2, "foo\n")



when :dump_ruby_ast

abort 'need <class> <method> args' if ARGV.length != 2
c = Metasm.const_get(ARGV.shift)
m = ARGV.shift
ptr = Metasm::RubyHack.get_method_node_ptr(c, m)
require 'pp'
pp Metasm::RubyHack.read_node(ptr)

when :test_jit


class Foo
	def bla
		i = 0
		20_000_000.times { i += 1 }
		i
	end
end

t0 = Time.now
Metasm::RubyHack.compile_ruby(Foo, :bla)
t1 = Time.now
p Foo.new.bla
t2 = Time.now

puts "compile %.3fs  run %.3fs" % [t1-t0, t2-t1]
end

end
