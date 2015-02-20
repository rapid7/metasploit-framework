#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# This sample creates the dynldr.so ruby shared object that allows interaction with
# native libraries
# x86 only for now

module Metasm
class DynLdr
  # basic C defs for ruby internals - 1.8 and 1.9 compat - x86/x64
  RUBY_H = <<EOS
#line #{__LINE__}
typedef uintptr_t VALUE;

#if defined(__PE__) && defined(__x86_64__)
 // sonovabeep
 #define INT2VAL(v) rb_ull2inum(v)
 #define VAL2INT(v) rb_num2ull(v)
#else
 #define INT2VAL(v) rb_uint2inum(v)
 #define VAL2INT(v) rb_num2ulong(v)
#endif

struct rb_string_t {
  VALUE flags;
  VALUE klass;
  VALUE len;
  char *ptr;
  union {
    long capa;
    VALUE shared;
  } aux;
};
#define RString(x) ((struct rb_string_t *)(x))

struct rb_array_t {
  VALUE flags;
  VALUE klass;
  VALUE len;
  union {
    long capa;
    VALUE shared;
  } aux;
  VALUE *ptr;
};
#define RArray(x) ((struct rb_array_t *)(x))

// TODO improve autoimport to handle data imports correctly
extern VALUE *rb_cObject __attribute__((import));
extern VALUE *rb_eRuntimeError __attribute__((import));
extern VALUE *rb_eArgError __attribute__((import));

// allows generating a ruby1.9 dynldr.so from ruby1.8
#ifndef DYNLDR_RUBY_19
#define DYNLDR_RUBY_19 #{RUBY_VERSION >= '1.9' ? 1 : 0}
#endif

#if #{RUBY_VERSION >= '2.0' ? 1 : 0}
// flonums. WHY?
// also breaks Qtrue/Qnil
#define rb_float_new rb_float_new_in_heap
#endif

#if DYNLDR_RUBY_19
 #define T_STRING 0x05
 #define T_ARRAY  0x07
 #define T_FIXNUM 0x15
 #define T_MASK   0x1f
 #define RSTRING_NOEMBED (1<<13)
 #define STR_PTR(o) ((RString(o)->flags & RSTRING_NOEMBED) ? RString(o)->ptr : (char*)&RString(o)->len)
 #define STR_LEN(o) ((RString(o)->flags & RSTRING_NOEMBED) ? RString(o)->len : (RString(o)->flags >> 14) & 0x1f)
 #define RARRAY_EMBED (1<<13)
 #define ARY_PTR(o) ((RArray(o)->flags & RARRAY_EMBED) ? (VALUE*)&RArray(o)->len : RArray(o)->ptr)
 #define ARY_LEN(o) ((RArray(o)->flags & RARRAY_EMBED) ? ((RArray(o)->flags >> 15) & 3) : RArray(o)->len)
#else
 #define T_STRING 0x07
 #define T_ARRAY  0x09
 #define T_FIXNUM 0x0a
 #define T_MASK   0x3f
 #define STR_PTR(o) (RString(o)->ptr)
 #define STR_LEN(o) (RString(o)->len)
 #define ARY_PTR(o) (RArray(o)->ptr)
 #define ARY_LEN(o) (RArray(o)->len)
#endif

#define TYPE(x) (((VALUE)(x) & 1) ? T_FIXNUM : (((VALUE)(x) & 3) || ((VALUE)(x) < 7)) ? 0x40 : RString(x)->flags & T_MASK)

VALUE rb_uint2inum(VALUE);
VALUE rb_ull2inum(unsigned long long);
VALUE rb_num2ulong(VALUE);
unsigned long long rb_num2ull(VALUE);
VALUE rb_str_new(const char* ptr, long len);	// alloc + memcpy + 0term
VALUE rb_ary_new2(int len);
VALUE rb_float_new(double);

VALUE rb_intern(char *);
VALUE rb_funcall(VALUE recv, VALUE id, int nargs, ...);
VALUE rb_const_get(VALUE, VALUE);
VALUE rb_raise(VALUE, char*, ...);
void rb_define_const(VALUE, char *, VALUE);
void rb_define_method(VALUE, char *, VALUE (*)(), int);
void rb_define_singleton_method(VALUE, char *, VALUE (*)(), int);

EOS

  # generic C source for the native component, ruby glue
  DYNLDR_C = <<EOS
#{RUBY_H}
#line #{__LINE__}

#ifdef __PE__
 __stdcall uintptr_t LoadLibraryA(char *);
 __stdcall uintptr_t GetProcAddress(uintptr_t, char *);

 #define os_load_lib(l) LoadLibraryA(l)
 #define os_load_sym(l, s) GetProcAddress(l, s)
 #define os_load_sym_ord(l, s) GetProcAddress(l, (char*)s)
#endif

#ifdef __ELF__
 asm(".pt_gnu_stack rw");

 #define RTLD_LAZY 1
 uintptr_t dlopen(char*, int);
 uintptr_t dlsym(uintptr_t, char*);

 #define os_load_lib(l) dlopen(l, RTLD_LAZY)
 #define os_load_sym(l, s) dlsym(l, s)
 #define os_load_sym_ord(l, s) 0U
#endif

extern int *cb_ret_table;
extern void *callback_handler;
extern void *callback_id_0;
extern void *callback_id_1;

static VALUE dynldr;


static VALUE memory_read(VALUE self, VALUE addr, VALUE len)
{
  return rb_str_new((char*)VAL2INT(addr), (long)VAL2INT(len));
}

static VALUE memory_read_int(VALUE self, VALUE addr)
{
  return INT2VAL(*(uintptr_t*)VAL2INT(addr));
}

static VALUE memory_write(VALUE self, VALUE addr, VALUE val)
{
  if (TYPE(val) != T_STRING)
    rb_raise(*rb_eArgError, "mem_write needs a String");

  char *src = STR_PTR(val);
  char *dst = (char*)VAL2INT(addr);
  unsigned len = (unsigned)STR_LEN(val);
  while (len--)
    *dst++ = *src++;
  return val;
}

static VALUE memory_write_int(VALUE self, VALUE addr, VALUE val)
{
  *(uintptr_t *)VAL2INT(addr) = VAL2INT(val);
  return 1;
}

static VALUE str_ptr(VALUE self, VALUE str)
{
  if (TYPE(str) != T_STRING)
    rb_raise(*rb_eArgError, "Invalid ptr");
  return INT2VAL((uintptr_t)STR_PTR(str));
}

// return the VALUE of an object (different of .object_id for Symbols, maybe others)
static VALUE rb_obj_to_value(VALUE self, VALUE obj)
{
  return INT2VAL((uintptr_t)obj);
}

// return the ruby object at VALUE
// USE WITH CAUTION, passing invalid values will segfault the interpreter/GC
static VALUE rb_value_to_obj(VALUE self, VALUE val)
{
  return VAL2INT(val);
}

// load a symbol from a lib byname, byordinal if integral
static VALUE sym_addr(VALUE self, VALUE lib, VALUE func)
{
  uintptr_t h, p;

  if (TYPE(lib) == T_STRING)
    h = os_load_lib(STR_PTR(lib));
  else if (TYPE(lib) == T_FIXNUM)
    h = VAL2INT(lib);
  else
    rb_raise(*rb_eArgError, "Invalid lib");

  if (TYPE(func) != T_STRING && TYPE(func) != T_FIXNUM)
    rb_raise(*rb_eArgError, "Invalid func");

  if (TYPE(func) == T_FIXNUM)
    p = os_load_sym_ord(h, VAL2INT(func));
  else
    p = os_load_sym(h, STR_PTR(func));

  return INT2VAL(p);
}

#ifdef __i386__

__int64 do_invoke_stdcall(unsigned, unsigned, unsigned*);
__int64 do_invoke_fastcall(unsigned, unsigned, unsigned*);
__int64 do_invoke(unsigned, unsigned, unsigned*);
double fake_float(void);

// invoke a symbol
// args is an array of Integers
// flags: 1 stdcall  2 fastcall  4 ret_64bits  8 ret_float
// TODO float args
static VALUE invoke(VALUE self, VALUE ptr, VALUE args, VALUE flags)
{
  if (TYPE(args) != T_ARRAY || ARY_LEN(args) > 64)
    rb_raise(*rb_eArgError, "bad args");

  uintptr_t flags_v = VAL2INT(flags);
  uintptr_t ptr_v = VAL2INT(ptr);
  unsigned i, argsz;
  uintptr_t args_c[64];
  __int64 ret;

  argsz = ARY_LEN(args);
  for (i=0U ; i<argsz ; ++i)
    args_c[i] = VAL2INT(ARY_PTR(args)[i]);

  if (flags_v & 2)
    ret = do_invoke_fastcall(ptr_v, argsz, args_c);	// supercedes stdcall
  else if (flags_v & 1)
    ret = do_invoke_stdcall(ptr_v, argsz, args_c);
  else
    ret = do_invoke(ptr_v, argsz, args_c);

  if (flags_v & 4)
    return rb_ull2inum((unsigned __int64)ret);
  else if (flags_v & 8)
    // fake_float does nothing, to allow the compiler to use ST(0)
    // which was in fact set by ptr_v()
    return rb_float_new(fake_float());

  return INT2VAL((unsigned)ret);
}

// this is the function that is called on behalf of all callbacks
// we're called through callback_handler (asm), itself called from the unique
// callback generated by callback_alloc
// heavy stack magick at work here !
// TODO float args / float retval / ret __int64
uintptr_t do_callback_handler(uintptr_t ori_retaddr, uintptr_t caller_id, uintptr_t arg0, uintptr_t arg_ecx __attribute__((register(ecx))), uintptr_t arg_edx __attribute__((register(edx))))
{
  uintptr_t *addr = &arg0;
  unsigned i, ret;
  VALUE args = rb_ary_new2(10);

  // __fastcall callback args
  ARY_PTR(args)[0] = INT2VAL(arg_ecx);
  ARY_PTR(args)[1] = INT2VAL(arg_edx);

  // copy our args to a ruby-accessible buffer
  for (i=2U ; i<10U ; ++i)
    ARY_PTR(args)[i] = INT2VAL(*addr++);
  RArray(args)->len = 10U;	// len == 10, no need to ARY_LEN/EMBED stuff

  ret = rb_funcall(dynldr, rb_intern("callback_run"), 2, INT2VAL(caller_id), args);

  // dynldr.callback will give us the arity (in bytes) of the callback in args[0]
  // we just put the stack lifting offset in caller_id for the asm stub to use
  caller_id = VAL2INT(ARY_PTR(args)[0]);

  return VAL2INT(ret);
}

#elif defined __amd64__

uintptr_t do_invoke(uintptr_t, uintptr_t, uintptr_t*);
double fake_float(void);

// invoke a symbol
// args is an array of Integers
// flags: 1 stdcall  2 fastcall  4 ret_64bits  8 ret_float
// TODO float args
static VALUE invoke(VALUE self, VALUE ptr, VALUE args, VALUE flags)
{
  if (TYPE(args) != T_ARRAY || ARY_LEN(args) > 16)
    rb_raise(*rb_eArgError, "bad args");

  uintptr_t flags_v = VAL2INT(flags);
  uintptr_t ptr_v = VAL2INT(ptr);
  int i, argsz;
  uintptr_t args_c[16];
  uintptr_t ret;
  uintptr_t (*ptr_f)(uintptr_t, ...) = (void*)ptr_v;

  argsz = (int)ARY_LEN(args);
  for (i=0 ; i<argsz ; ++i)
    args_c[i] = VAL2INT(ARY_PTR(args)[i]);

  for (i=argsz ; i<16 ; ++i)
    args_c[i] = 0;

  if (argsz <= 4)
    ret = ptr_f(args_c[0], args_c[1], args_c[2], args_c[3]);
  else
    ret = ptr_f(args_c[0],  args_c[1],  args_c[2],  args_c[3],
          args_c[4],  args_c[5],  args_c[6],  args_c[7],
          args_c[8],  args_c[9],  args_c[10], args_c[11],
          args_c[12], args_c[13], args_c[14], args_c[15]);

  if (flags_v & 8)
    return rb_float_new(fake_float());

  return INT2VAL(ret);
}

uintptr_t do_callback_handler(uintptr_t cb_id __attribute__((register(rax))),
    uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
    uintptr_t arg4, uintptr_t arg5, uintptr_t arg6, uintptr_t arg7)
{
  uintptr_t ret;
  VALUE args = rb_ary_new2(8);
  VALUE *ptr = ARY_PTR(args);

  RArray(args)->len = 8;
  ptr[0] = INT2VAL(arg0);
  ptr[1] = INT2VAL(arg1);
  ptr[2] = INT2VAL(arg2);
  ptr[3] = INT2VAL(arg3);
  ptr[4] = INT2VAL(arg4);
  ptr[5] = INT2VAL(arg5);
  ptr[6] = INT2VAL(arg6);
  ptr[7] = INT2VAL(arg7);

  ret = rb_funcall(dynldr, rb_intern("callback_run"), 2, INT2VAL(cb_id), args);

  return VAL2INT(ret);
}
#endif

int Init_dynldr(void) __attribute__((export_as(Init_<insertfilenamehere>)))	// to patch before parsing to match the .so name
{
  dynldr = rb_const_get(rb_const_get(*rb_cObject, rb_intern("Metasm")), rb_intern("DynLdr"));
  rb_define_singleton_method(dynldr, "memory_read",  memory_read, 2);
  rb_define_singleton_method(dynldr, "memory_read_int",  memory_read_int, 1);
  rb_define_singleton_method(dynldr, "memory_write", memory_write, 2);
  rb_define_singleton_method(dynldr, "memory_write_int", memory_write_int, 2);
  rb_define_singleton_method(dynldr, "str_ptr", str_ptr, 1);
  rb_define_singleton_method(dynldr, "rb_obj_to_value", rb_obj_to_value, 1);
  rb_define_singleton_method(dynldr, "rb_value_to_obj", rb_value_to_obj, 1);
  rb_define_singleton_method(dynldr, "sym_addr", sym_addr, 2);
  rb_define_singleton_method(dynldr, "raw_invoke", invoke, 3);
  rb_define_const(dynldr, "CALLBACK_TARGET",
#ifdef __i386__
      INT2VAL((VALUE)&callback_handler));
#elif defined __amd64__
      INT2VAL((VALUE)&do_callback_handler));
#endif
  rb_define_const(dynldr, "CALLBACK_ID_0", INT2VAL((VALUE)&callback_id_0));
  rb_define_const(dynldr, "CALLBACK_ID_1", INT2VAL((VALUE)&callback_id_1));
  return 0;
}
EOS

  # see the note in compile_bin_module
  # this is a dynamic resolver for the ruby symbols we use
  DYNLDR_C_PE_HACK = <<EOS
#line #{__LINE__}

void* get_peb(void);

// check if the wstr s1 contains 'ruby' (case-insensitive)
static void *wstrcaseruby(short *s1, int len)
{
  int i = 0;
  int match = 0;
  char *want = "ruby";	// cant contain the same letter twice

  while (i < len) {
    if (want[match] == (s1[i] | 0x20)) {	// downcase cmp
      if (match == 3)
        return s1+i-match;
    } else
      match = 0;
    if (want[match] == (s1[i] | 0x20))
      ++match;
    ++i;
  }

  return 0;
}

asm(".text");	// TODO fix compiler
#ifdef __x86_64__
asm("get_peb: mov rax, gs:[60h] ret");
#endif
#ifdef __i386__
asm("get_peb: mov eax, fs:[30h] ret");

// 1st arg for ld_rb_imp == Init retaddr
asm("Init_dynldr: call load_ruby_imports jmp Init_dynldr_real");
#endif

struct _lmodule {
  struct _lmodule *next;	// list_head
  void *; void *; void*; void*; void*;
  uintptr_t base, entry, size;
  short; short; short*;
  short len, maxlen;
  short *basename;
};

struct _peb {
  void*; void*; void*;
  struct {
    int; int; void*;
    struct _lmodule *inloadorder; // list_head
  } *ldr;
};

// find the ruby library in the loaded modules list of the interpreter through the PEB
static uintptr_t find_ruby_module_peb(void)
{
  struct _lmodule *ptr;
  void *base;
  struct _peb *peb = get_peb();

  base = &peb->ldr->inloadorder;
  ptr = ((struct _lmodule *)base)->next;
  ptr = ptr->next;	// skip the first entry = ruby.exe
  while (ptr != base) {
    if (wstrcaseruby(ptr->basename, ptr->len/2))
      return ptr->base;
    ptr = ptr->next;
  }

  return 0;
}

// find the ruby library from an address in the ruby module (Init_dynldr retaddr)
static uintptr_t find_ruby_module_mem(uintptr_t someaddr)
{
  // could __try{}, but with no imports we're useless anyway.
  uintptr_t ptr = someaddr & (-0x10000);
  while (*((unsigned __int16 *)ptr) != 'ZM')	// XXX too weak?
    ptr -= 0x10000;
  return ptr;
}

// a table of string offsets, base = the table itself
// each entry is a ruby function, whose address is to be put inplace in the table
// last entry == 0
extern void *ruby_import_table;

__stdcall uintptr_t GetProcAddress(uintptr_t, char *);
// resolve the ruby imports found by offset in ruby_import_table
int load_ruby_imports(uintptr_t rbaddr)
{
  uintptr_t ruby_module;
  uintptr_t *ptr;
  char *table;

  static int loaded_ruby_imports = 0;
  if (loaded_ruby_imports)
    return 0;
  loaded_ruby_imports = 1;

  if (rbaddr)
    ruby_module = find_ruby_module_mem(rbaddr);
  else
    ruby_module = find_ruby_module_peb();

  if (!ruby_module)
    return 0;

  ptr = &ruby_import_table;
  table = (char*)ptr;

  while (*ptr) {
    if (!(*ptr = GetProcAddress(ruby_module, table+*ptr)))
      // TODO warning or something
      return 0;
    ptr++;
  }

  return 1;
}

#ifdef __x86_64__
#define DLL_PROCESS_ATTACH 1
int DllMain(void *handle, int reason, void *res)
{
  if (reason == DLL_PROCESS_ATTACH)
    return load_ruby_imports(0);
  return 1;
}
#endif
EOS

  # ia32 asm source for the native component: handles ABI stuff
  DYNLDR_ASM_IA32 = <<EOS
.text
do_invoke_fastcall:
  push ebp
  mov ebp, esp

  // load ecx/edx, fix arg/argcount
  mov eax, [ebp+16]
  mov ecx, [eax]
  mov edx, [eax+4]
  add eax, 8
  mov [ebp+16], eax

  mov eax, [ebp+12]
  sub eax, 2
  jb _do_invoke_call
  jmp _do_invoke_copy

do_invoke:
do_invoke_stdcall:
  push ebp
  mov ebp, esp
  mov eax, [ebp+12]
_do_invoke_copy:
  // make room for args
  shl eax, 2
  jz _do_invoke_call
  sub esp, eax
  // copy args
  push esi
  push edi
  push ecx
  mov ecx, [ebp+12]
  mov esi, [ebp+16]
  mov edi, esp
  add edi, 12
  rep movsd
  pop ecx
  pop edi
  pop esi
  // go
_do_invoke_call:
  call dword ptr [ebp+8]
  leave
fake_float:
  ret

// entrypoint for callbacks: to the native api, give the addr of some code
//  that will push a unique cb_identifier and jmp here
callback_handler:
  // stack here: cb_id_retaddr, cb_native_retaddr, cb_native_arg0, ...
  // swap caller retaddr & cb_identifier, fix cb_identifier from the stub
  pop eax		// stuff pushed by the stub
  sub eax, callback_id_1 - callback_id_0	// fixup cb_id_retaddr to get a cb id
  xchg eax, [esp]	// put on stack, retrieve original retaddr
  push eax	// push intended cb retaddr
  call do_callback_handler
  // do_cb_handler puts the nr of bytes we have to pop from the stack in its 1st arg (eg [esp+4] here)
  // stack here: cb_native_retaddr, ruby_popcount, cb_native_arg0, ...
  pop ecx		// get retaddr w/o interfering with retval (incl 64bits eax+edx)
  add esp, [esp]	// pop cb args if stdcall
  add esp, 4	// pop cb_id/popcount
  jmp ecx		// return

// those are valid callback id
// most of the time only 2 cb is used (source: meearse)
// so this prevents dynamic allocation of a whole page for the most common case
callback_id_0: call callback_handler
callback_id_1: call callback_handler
EOS

  # ia32 asm source for the native component: handles ABI stuff
  DYNLDR_ASM_X86_64 = <<EOS
.text
fake_float:
  ret

// entrypoint for callbacks: to the native api, give the addr of some code
//  that will save its address in rax and jump to do_cb_h
callback_id_0:
  lea rax, [rip-$_+callback_id_0]
  jmp do_callback_handler
callback_id_1:
  lea rax, [rip-$_+callback_id_1]
  jmp do_callback_handler
EOS

  # initialization
  # load (build if needed) the binary module
  def self.start
    # callbacks are really just a list of asm 'call', so we share them among subclasses of DynLdr
    @@callback_addrs = []	# list of all allocated callback addrs (in use or not)
    @@callback_table = {}	# addr -> cb structure (inuse only)

    binmodule = find_bin_path

    if not File.exists?(binmodule) or File.stat(binmodule).mtime < File.stat(__FILE__).mtime
      compile_binary_module(host_exe, host_cpu, binmodule)
    end

    require binmodule

    @@callback_addrs << CALLBACK_ID_0 << CALLBACK_ID_1
  end

  # compile the dynldr binary ruby module for a specific arch/cpu/modulename
  def self.compile_binary_module(exe, cpu, modulename)
    bin = exe.new(cpu)
    # compile the C code, but patch the Init_ export name, which must match the string used in 'require'
    module_c_src = DYNLDR_C.gsub('<insertfilenamehere>', File.basename(modulename, '.so'))
    bin.compile_c module_c_src
    # compile the Asm stuff according to the target architecture
    bin.assemble  case cpu.shortname
                  when 'ia32'; DYNLDR_ASM_IA32
                  when 'x64'; DYNLDR_ASM_X86_64
            end

    # tweak the resulting binary linkage procedures if needed
    compile_binary_module_hack(bin)

    # save the shared library
    bin.encode_file(modulename, :lib)
  end

  def self.compile_binary_module_hack(bin)
    # this is a hack
    # we need the module to use ruby symbols
    # but we don't know the actual ruby lib filename (depends on ruby version, # platform, ...)
    case bin.shortname
    when 'elf'
      # we know the lib is already loaded by the main ruby executable, no DT_NEEDED needed
      class << bin
        def automagic_symbols(*a)
          # do the plt generation
          super(*a)
          # but remove the specific lib names
          @tag.delete 'NEEDED'
        end
      end
      return
    when 'coff'
      # the hard part, see below
    else
      # unhandled arch, dont tweak
      return
    end

    # we remove the PE IAT section related to ruby symbols, and make
    # a manual symbol resolution on module loading.

    # populate the ruby import table ourselves on module loading
    bin.imports.delete_if { |id| id.libname =~ /ruby/ }

    # we generate something like:
    #  .data
    #  ruby_import_table:
    #  rb_cObject dd str_rb_cObject - ruby_import_table
    #  riat_rb_intern dd str_rb_intern - ruby_import_table
    #  dd 0
    #
    #  .rodata
    #  str_rb_cObject db "rb_cObject", 0
    #  str_rb_intern db "rb_intern", 0
    #
    #  .text
    #  rb_intern: jmp [riat_rb_intern]
    #
    # the PE_HACK code will parse ruby_import_table and make the symbol resolution on startup

    # setup the string table and the thunks
    text = bin.sections.find { |s| s.name == '.text' }.encoded
    rb_syms = text.reloc_externals.grep(/^rb_/)

    dd = (bin.cpu.size == 64 ? 'dq' : 'dd')

    init_symbol = text.export.keys.grep(/^Init_/).first
    raise 'no Init_mname symbol found' if not init_symbol
    if bin.cpu.size == 32
      # hax to find the base of libruby under Win98 (peb sux)
      text.export[init_symbol + '_real'] = text.export.delete(init_symbol)
      bin.unique_labels_cache.delete(init_symbol)
    end

    # the C glue: getprocaddress etc
    bin.compile_c DYNLDR_C_PE_HACK.gsub('Init_dynldr', init_symbol)

    # the IAT, initialized with relative offsets to symbol names
    asm_table = ['.data', '.align 8', 'ruby_import_table:']
    # strings will be in .rodata
    bin.parse('.rodata')
    rb_syms.each { |sym|
      # raw symbol name
      str_label = bin.parse_new_label('str', "db #{sym.inspect}, 0")

      if sym !~ /^rb_[ce][A-Z]/
        # if we dont reference a data import (rb_cClass / rb_eException),
        # then create a function thunk
        i = PE::ImportDirectory::Import.new
        i.thunk = sym
        sym = i.target = 'riat_' + str_label
        bin.arch_encode_thunk(text, i)	# encode a jmp [importtable]
      end

      # update the IAT
      asm_table << "#{sym} #{dd} #{str_label} - ruby_import_table"
    }
    # IAT null-terminated
    asm_table << "#{dd} 0"

    # now parse & assemble the IAT in .data
    bin.assemble asm_table.join("\n")
  end

  # find the path of the binary module
  # if none exists, create a path writeable by the current user
  def self.find_bin_path
    fname = ['dynldr', host_arch, host_cpu.shortname,
       ('19' if RUBY_VERSION >= '1.9')].compact.join('-') + '.so'
    dir = File.dirname(__FILE__)
    binmodule = File.join(dir, fname)
    if not File.exists? binmodule or File.stat(binmodule).mtime < File.stat(__FILE__).mtime
      if not dir = find_write_dir
        raise LoadError, "no writable dir to put the DynLdr ruby module, try to run as root"
      end
      binmodule = File.join(dir, fname)
    end
    binmodule
  end

  # find a writeable directory
  # searches this script directory, $HOME / %APPDATA% / %USERPROFILE%, or $TMP
  def self.find_write_dir
    writable = lambda { |d|
      begin
        foo = '/_test_write_' + rand(1<<32).to_s
        true if File.writable?(d) and
        File.open(d+foo, 'w') { true } and
        File.unlink(d+foo)
      rescue
      end
    }
    dir = File.dirname(__FILE__)
    return dir if writable[dir]
    dir = ENV['HOME'] || ENV['APPDATA'] || ENV['USERPROFILE']
    if writable[dir]
      dir = File.join(dir, '.metasm')
      Dir.mkdir dir if not File.directory? dir
      return dir
    end
    ENV['TMP'] || ENV['TEMP'] || '.'
  end

  # CPU suitable for compiling code for the current running host
  def self.host_cpu
    @cpu ||=
    case RUBY_PLATFORM
    when /i[3-6]86/; Ia32.new
    when /x86_64|x64/i; X86_64.new
    else raise LoadError, "Unsupported host platform #{RUBY_PLATFORM}"
    end
  end

  # returns whether we run on linux or windows
  def self.host_arch
    case RUBY_PLATFORM
    when /linux/i; :linux
    when /mswin|mingw|cygwin/i; :windows
    else raise LoadError, "Unsupported host platform #{RUBY_PLATFORM}"
    end
  end

  # ExeFormat suitable as current running host native module
  def self.host_exe
    case host_arch
    when :linux; ELF
    when :windows; PE
    end
  end

  # parse a C string into the @cp parser, create it if needed
  def self.parse_c(src)
    cp.parse(src)
  end

  # compile a C fragment into a Shellcode_RWX, honors the host ABI
  def self.compile_c(src)
    # XXX could we reuse self.cp ? (for its macros etc)
    cp = C::Parser.new(host_exe.new(host_cpu))
    cp.parse(src)
    sc = Shellcode_RWX.new(host_cpu)
    asm = host_cpu.new_ccompiler(cp, sc).compile
    sc.assemble(asm)
  end

  # maps a Shellcode_RWX in memory, fixup stdlib relocations
  # returns the Shellcode_RWX, with the base_r/w/x initialized to the allocated memory
  def self.sc_map_resolve(sc)
    sc_map_resolve_addthunks(sc)

    sc.base_r = memory_alloc(sc.encoded_r.length) if sc.encoded_r.length > 0
    sc.base_w = memory_alloc(sc.encoded_w.length) if sc.encoded_w.length > 0
    sc.base_x = memory_alloc(sc.encoded_x.length) if sc.encoded_x.length > 0

    locals = sc.encoded_r.export.keys | sc.encoded_w.export.keys | sc.encoded_x.export.keys
    exts = sc.encoded_r.reloc_externals(locals) | sc.encoded_w.reloc_externals(locals) | sc.encoded_x.reloc_externals(locals)
    bd = {}
    exts.uniq.each { |ext| bd[ext] = sym_addr(lib_from_sym(ext), ext) or raise rescue raise "unknown symbol #{ext.inspect}" }
    sc.fixup_check(bd)

    memory_write sc.base_r, sc.encoded_r.data if sc.encoded_r.length > 0
    memory_write sc.base_w, sc.encoded_w.data if sc.encoded_w.length > 0
    memory_write sc.base_x, sc.encoded_x.data if sc.encoded_x.length > 0

    memory_perm sc.base_r, sc.encoded_r.length, 'r'  if sc.encoded_r.length > 0
    memory_perm sc.base_w, sc.encoded_w.length, 'rw' if sc.encoded_w.length > 0
    memory_perm sc.base_x, sc.encoded_x.length, 'rx' if sc.encoded_x.length > 0

    sc
  end

  def self.sc_map_resolve_addthunks(sc)
    case host_cpu.shortname
    when 'x64'
      # patch 'call moo' into 'call thunk; thunk: jmp qword [moo_ptr]'
      # this is similar to ELF PLT section, allowing code to call
      # into a library mapped more than 4G away
      # XXX handles only 'call extern', not 'lea reg, extern' or anything else
      # in this case, the linker will still raise an 'immediate overflow'
      # during fixup_check in sc_map_resolve
      [sc.encoded_r, sc.encoded_w, sc.encoded_x].each { |edata|
        edata.reloc.dup.each { |off, rel|
          # target only call extern / jmp.i32 extern
          next if rel.type != :i32
          next if rel.target.op != :-
          next if edata.export[rel.target.rexpr] != off+4
          next if edata.export[rel.target.lexpr]
          opc = edata.data[off-1, 1].unpack('C')[0]
          next if opc != 0xe8 and opc != 0xe9

          thunk_sc = Shellcode.new(host_cpu).share_namespace(sc)
          thunk = thunk_sc.assemble(<<EOS).encoded
1: jmp qword [rip]
dq #{rel.target.lexpr}
EOS
          edata << thunk
          rel.target.lexpr = thunk.inv_export[0]
        }
      }
    end
  end

  # retrieve the library where a symbol is to be found (uses AutoImport)
  def self.lib_from_sym(symname)
    case host_arch
    when :linux; GNUExports::EXPORT
    when :windows; WindowsExports::EXPORT
    end[symname]
  end

  # reads a bunch of C code, creates binding for those according to the prototypes
  # handles enum/defines to define constants
  # For each toplevel method prototype, it generates a ruby method in this module, the name is lowercased
  # For each numeric macro/enum, it also generates an uppercase named constant
  # When such a function is called with a lambda as argument, a callback is created for the duration of the call
  # and destroyed afterwards ; use callback_alloc_c to get a callback id with longer life span
  def self.new_api_c(proto, fromlib=nil)
    proto += "\n;"	# allow 'int foo()' and '#include <bar>'
    parse_c(proto)

    cp.toplevel.symbol.dup.each_value { |v|
      next if not v.kind_of? C::Variable	# enums
      cp.toplevel.symbol.delete v.name
      lib = fromlib || lib_from_sym(v.name)
      addr = sym_addr(lib, v.name)
      if addr == 0 or addr == -1 or addr == 0xffff_ffff or addr == 0xffffffff_ffffffff
        api_not_found(lib, v)
        next
      end

      rbname = c_func_name_to_rb(v.name)
      if not v.type.kind_of? C::Function
        # not a function, simply return the symbol address
        # TODO struct/table access through hash/array ?
        class << self ; self ; end.send(:define_method, rbname) { addr }
        next
      end
      next if v.initializer	# inline & stuff
      puts "new_api_c: load method #{rbname} from #{lib}" if $DEBUG

      new_caller_for(v, rbname, addr)
    }

    # predeclare constants from enums
    # macros are handled in const_missing (too slow to (re)do here everytime)
    # TODO #define FOO(v) (v<<1)|1   =>  create ruby counterpart
    cexist = constants.inject({}) { |h, c| h.update c.to_s => true }
    cp.toplevel.symbol.each { |k, v|
      if v.kind_of? ::Integer
        n = c_const_name_to_rb(k)
        const_set(n, v) if v.kind_of? Integer and not cexist[n]
      end
    }

    # avoid WTF rb warning: toplevel const TRUE referenced by WinAPI::TRUE
    cp.lexer.definition.each_key { |k|
      n = c_const_name_to_rb(k)
      if not cexist[n] and Object.const_defined?(n) and v = @cp.macro_numeric(n)
        const_set(n, v)
      end
    }
  end

  # const_missing handler: will try to find a matching #define
  def self.const_missing(c)
    # infinite loop on autorequire C..
    return super(c) if not defined? @cp or not @cp

    cs = c.to_s
    if @cp.lexer.definition[cs]
      m = cs
    else
      m = @cp.lexer.definition.keys.find { |k| c_const_name_to_rb(k) == cs }
    end

    if m and v = @cp.macro_numeric(m)
      const_set(c, v)
      v
    else
      super(c)
    end
  end

  # when defining ruby wrapper for C methods, the ruby method name is the string returned by this function from the C name
  def self.c_func_name_to_rb(name)
    n = name.to_s.gsub(/[^a-z0-9_]/i) { |c| c.unpack('H*')[0] }.downcase
    n = "m#{n}" if n !~ /^[a-z]/
    n
  end

  # when defining ruby wrapper for C constants (numeric define/enum), the ruby const name is
  # the string returned by this function from the C name. It should follow ruby standards (1st letter upcase)
  def self.c_const_name_to_rb(name)
    n = name.to_s.gsub(/[^a-z0-9_]/i) { |c| c.unpack('H*')[0] }.upcase
    n = "C#{n}" if n !~ /^[A-Z]/
    n
  end

  def self.api_not_found(lib, func)
    raise "could not find symbol #{func.name.inspect} in #{lib.inspect}"
  end

  # called whenever a native API is called through new_api_c/new_func_c/etc
  def self.trace_invoke(api, args)
    #p api
  end

  # define a new method 'name' in the current module to invoke the raw method at addr addr
  # translates ruby args to raw args using the specified prototype
  def self.new_caller_for(proto, name, addr)
    flags = 0
    flags |= 1 if proto.has_attribute('stdcall')
    flags |= 2 if proto.has_attribute('fastcall')
    flags |= 4 if proto.type.type.integral? and cp.sizeof(nil, proto.type.type) == 8
    flags |= 8 if proto.type.type.float?
    class << self ; self ; end.send(:define_method, name) { |*a|
      raise ArgumentError, "bad arg count for #{name}: #{a.length} for #{proto.type.args.to_a.length}" if a.length != proto.type.args.to_a.length and not proto.type.varargs

      # convert the arglist suitably for raw_invoke
      auto_cb = []	# list of automatic C callbacks generated from lambdas
      a = a.zip(proto.type.args.to_a).map { |ra, fa|
        aa = convert_rb2c(fa, ra, :cb_list => auto_cb)
        if fa and fa.type.integral? and cp.sizeof(fa) == 8 and host_cpu.size == 32
          aa = [aa & 0xffff_ffff, (aa >> 32) & 0xffff_ffff]
          aa.reverse! if host_cpu.endianness != :little
        end
        aa
      }.flatten

      trace_invoke(name, a)
      # do it
      ret = raw_invoke(addr, a, flags)

      # cleanup autogenerated callbacks
      auto_cb.each { |cb| callback_free(cb) }

      # interpret return value
      ret = convert_ret_c2rb(proto, ret)
    }
  end

  # ruby object -> integer suitable as arg for raw_invoke
  def self.convert_rb2c(formal, val, opts=nil)
    case val
    when String; str_ptr(val)
    when Proc; cb = callback_alloc_cobj(formal, val) ; (opts[:cb_list] << cb if opts and opts[:cb_list]) ; cb
    when C::AllocCStruct; str_ptr(val.str) + val.stroff
    when Hash
      if not formal.type.pointed.kind_of?(C::Struct)
        raise "invalid argument #{val.inspect} for #{formal}, need a struct*"
      end
      buf = cp.alloc_c_struct(formal, val)
      val.instance_variable_set('@rb2c', buf)	# GC trick: lifetime(buf) >= lifetime(hash) (XXX or until next call to convert_rb2c)
      str_ptr(buf.str)
    #when Float; val	# TODO handle that in raw_invoke C code
    else
           v = val.to_i rescue 0	# NaN, Infinity, etc
           v = -v if v == -(1<<(cp.typesize[:ptr]*8-1))	# ruby bug... raise -0x8000_0000: out of ulong range
           v
    end
  end

  # this method is called from the C part to run the ruby code corresponding to
  # a given C callback allocated by callback_alloc_c
  def self.callback_run(id, args)
    cb = @@callback_table[id]
    raise "invalid callback #{'%x' % id} not in #{@@callback_table.keys.map { |c| c.to_s(16) }}" if not cb

    rawargs = args.dup
    if host_cpu.shortname == 'ia32' and (not cb[:proto_ori] or not cb[:proto_ori].has_attribute('fastcall'))
      rawargs.shift
      rawargs.shift
    end
    ra = cb[:proto] ? cb[:proto].args.map { |fa| convert_cbargs_c2rb(fa, rawargs) } : []

    # run it
    ret = cb[:proc].call(*ra)

    # the C code expects to find in args[0] the amount of stack fixing needed for __stdcall callbacks
    args[0] = cb[:abi_stackfix] || 0
    ret
  end

  # C raw cb arg -> ruby object
  # will combine 2 32bit values for 1 64bit arg
  def self.convert_cbargs_c2rb(formal, rawargs)
    val = rawargs.shift
    if formal.type.integral? and cp.sizeof(formal) == 8 and host_cpu.size == 32
      if host.cpu.endianness == :little
        val |= rawargs.shift << 32
      else
        val = (val << 32) | rawargs.shift
      end
    end

    convert_c2rb(formal, val)
  end

  # interpret a raw decoded C value to a ruby value according to the C prototype
  # handles signedness etc
  # XXX val is an integer, how to decode Floats etc ? raw binary ptr ?
  def self.convert_c2rb(formal, val)
    formal = formal.type if formal.kind_of? C::Variable
    val &= (1 << 8*cp.sizeof(formal))-1 if formal.integral?
    val = Expression.make_signed(val, 8*cp.sizeof(formal)) if formal.integral? and formal.signed?
    val = nil if formal.pointer? and val == 0
    val
  end

  # C raw ret -> ruby obj
  # can be overridden for system-specific calling convention (eg return 0/-1 => raise an error)
  def self.convert_ret_c2rb(fproto, ret)
    fproto = fproto.type if fproto.kind_of? C::Variable
    convert_c2rb(fproto.untypedef.type, ret)
  end

  def self.cp ; @cp ||= C::Parser.new(host_exe.new(host_cpu)) ; end
  def self.cp=(c); @cp = c ; end

  # allocate a callback for a given C prototype (string)
  # accepts full C functions (with body) (only 1 at a time) or toplevel 'asm' statement
  def self.callback_alloc_c(proto, &b)
    proto += ';'	# allow 'int foo()'
    parse_c(proto)
    v = cp.toplevel.symbol.values.find_all { |v_| v_.kind_of? C::Variable and v_.type.kind_of? C::Function }.first
    if (v and v.initializer) or cp.toplevel.statements.find { |st| st.kind_of? C::Asm }
      cp.toplevel.statements.delete_if { |st| st.kind_of? C::Asm }
      cp.toplevel.symbol.delete v.name if v
      sc = sc_map_resolve(compile_c(proto))
      sc.base_x
    elsif not v
      raise 'empty prototype'
    else
      cp.toplevel.symbol.delete v.name
      callback_alloc_cobj(v, b)
    end
  end

  # allocates a callback for a given C prototype (C variable, pointer to func accepted)
  def self.callback_alloc_cobj(proto, b)
    ori = proto
    proto = proto.type if proto and proto.kind_of? C::Variable
    proto = proto.pointed while proto and proto.pointer?
    id = callback_find_id
    cb = {}
    cb[:id] = id
    cb[:proc] = b
    cb[:proto] = proto
    cb[:proto_ori] = ori
    cb[:abi_stackfix] = proto.args.inject(0) { |s, a| s + [cp.sizeof(a), cp.typesize[:ptr]].max } if ori and ori.has_attribute('stdcall')
    cb[:abi_stackfix] = proto.args[2..-1].to_a.inject(0) { |s, a| s + [cp.sizeof(a), cp.typesize[:ptr]].max } if ori and ori.has_attribute('fastcall')	# supercedes stdcall
    @@callback_table[id] = cb
    id
  end

  # releases a callback id, so that it may be reused by a later callback_alloc
  def self.callback_free(id)
    @@callback_table.delete id
  end

  # finds a free callback id, allocates a new page if needed
  def self.callback_find_id
    if not id = @@callback_addrs.find { |a| not @@callback_table[a] }
      page_size = 4096
      cb_page = memory_alloc(page_size)
      sc = Shellcode.new(host_cpu, cb_page)
      case sc.cpu.shortname
      when 'ia32'
        asm = "call #{CALLBACK_TARGET}"
      when 'x64'
        if (cb_page - CALLBACK_TARGET).abs >= 0x7fff_f000
          # cannot directly 'jmp CB_T'
          asm = "1: mov rax, #{CALLBACK_TARGET}  push rax  lea rax, [rip-$_+1b]  ret"
        else
          asm = "1: lea rax, [rip-$_+1b]  jmp #{CALLBACK_TARGET}"
        end
      else
        raise 'Who are you?'
      end

      # fill the page with valid callbacks
      loop do
        off = sc.encoded.length
        sc.assemble asm
        break if sc.encoded.length > page_size
        @@callback_addrs << (cb_page + off)
      end

      memory_write cb_page, sc.encode_string[0, page_size]
      memory_perm cb_page, page_size, 'rx'

      raise 'callback_alloc bouh' if not id = @@callback_addrs.find { |a| not @@callback_table[a] }
    end
    id
  end

  # compile a bunch of C functions, defines methods in this module to call them
  # returns the raw pointer to the code page
  # if given a block, run the block and then undefine all the C functions & free memory
  def self.new_func_c(src)
    sc = sc_map_resolve(compile_c(src))

    parse_c(src)	# XXX the Shellcode parser may have defined stuff / interpreted C another way...
    defs = []
    cp.toplevel.symbol.dup.each_value { |v|
      next if not v.kind_of? C::Variable
      cp.toplevel.symbol.delete v.name
      next if not v.type.kind_of? C::Function or not v.initializer
      next if not off = sc.encoded_x.export[v.name]
      rbname = c_func_name_to_rb(v.name)
      new_caller_for(v, rbname, sc.base_x+off)
      defs << rbname
    }
    if block_given?
      begin
        yield
      ensure
        defs.each { |d| class << self ; self ; end.send(:remove_method, d) }
        memory_free sc.base_r if sc.base_r
        memory_free sc.base_w if sc.base_w
        memory_free sc.base_x if sc.base_x
      end
    else
      sc.base_x
    end
  end

  # compile an asm sequence, callable with the ABI of the C prototype given
  # function name comes from the prototype
  # the shellcode is mapped in read-only memory unless selfmodifyingcode is true
  # note that you can use a .data section for simple writable non-executable memory
  def self.new_func_asm(proto, asm, selfmodifyingcode=false)
    proto += "\n;"
    old = cp.toplevel.symbol.keys
    parse_c(proto)
    news = cp.toplevel.symbol.keys - old
    raise "invalid proto #{proto}" if news.length != 1
    f = cp.toplevel.symbol[news.first]
    raise "invalid func proto #{proto}" if not f.name or not f.type.kind_of? C::Function or f.initializer
    cp.toplevel.symbol.delete f.name

    sc = Shellcode_RWX.assemble(host_cpu, asm)
    sc = sc_map_resolve(sc)
    if selfmodifyingcode
      memory_perm sc.base_x, sc.encoded_x.length, 'rwx'
    end
    rbname = c_func_name_to_rb(f.name)
    new_caller_for(f, rbname, sc.base_x)
    if block_given?
      begin
        yield
      ensure
        class << self ; self ; end.send(:remove_method, rbname)
        memory_free sc.base_r if sc.base_r
        memory_free sc.base_w if sc.base_w
        memory_free sc.base_x
      end
    else
      sc.base_x
    end
  end

  # allocate a C::AllocCStruct to hold a specific struct defined in a previous new_api_c
  def self.alloc_c_struct(structname, values={})
    cp.alloc_c_struct(structname, values)
  end

  # return a C::AllocCStruct mapped over the string (with optionnal offset)
  # str may be an EncodedData
  def self.decode_c_struct(structname, str, off=0)
    str = str.data if str.kind_of? EncodedData
    cp.decode_c_struct(structname, str, off)
  end

  # allocate a C::AllocCStruct holding an Array of typename variables
  # if len is an int, it holds the ary length, or it can be an array of initialisers
  # eg alloc_c_ary("int", [4, 5, 28])
  def self.alloc_c_ary(typename, len)
    cp.alloc_c_ary(typename, len)
  end

  # return a C::AllocCStruct holding an array of type typename mapped over str
  def self.decode_c_ary(typename, len, str, off=0)
    cp.decode_c_ary(typename, len, str, off)
  end

  # return an AllocCStruct holding an array of 1 element of type typename
  # access its value with obj[0]
  # useful when you need a pointer to an int that will be filled by an API: use alloc_c_ptr('int')
  def self.alloc_c_ptr(typename, init=nil)
    cp.alloc_c_ary(typename, (init ? [init] : 1))
  end

  # return the binary version of a ruby value encoded as a C variable
  # only integral types handled for now
  def self.encode_c_value(var, val)
    cp.encode_c_value(var, val)
  end

  # decode a C variable
  # only integral types handled for now
  def self.decode_c_value(str, var, off=0)
    cp.decode_c_value(str, var, off)
  end

  # read a 0-terminated string from memory
  def self.memory_read_strz(ptr, szmax=4096)
    # read up to the end of the ptr memory page
    pglim = (ptr + 0x1000) & ~0xfff
    sz = [pglim-ptr, szmax].min
    data = memory_read(ptr, sz)
    return data[0, data.index(?\0)] if data.index(?\0)
    if sz < szmax
      data = memory_read(ptr, szmax)
      data = data[0, data.index(?\0)] if data.index(?\0)
    end
    data
  end

  # read a 0-terminated wide string from memory
  def self.memory_read_wstrz(ptr, szmax=4096)
    # read up to the end of the ptr memory page
    pglim = (ptr + 0x1000) & ~0xfff
    sz = [pglim-ptr, szmax].min
    data = memory_read(ptr, sz)
    if i = data.unpack('v*').index(0)
      return data[0, 2*i]
    end
    if sz < szmax
      data = memory_read(ptr, szmax)
      data = data[0, 2*i] if i = data.unpack('v*').index(0)
    end
    data
  end

  # automatically build/load the bin module
  start

  case host_arch
  when :windows

    new_api_c <<EOS, 'kernel32'
#define PAGE_NOACCESS          0x01
#define PAGE_READONLY          0x02
#define PAGE_READWRITE         0x04
#define PAGE_WRITECOPY         0x08
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80
#define PAGE_GUARD            0x100
#define PAGE_NOCACHE          0x200
#define PAGE_WRITECOMBINE     0x400

#define MEM_COMMIT           0x1000
#define MEM_RESERVE          0x2000
#define MEM_DECOMMIT         0x4000
#define MEM_RELEASE          0x8000
#define MEM_FREE            0x10000
#define MEM_PRIVATE         0x20000
#define MEM_MAPPED          0x40000
#define MEM_RESET           0x80000
#define MEM_TOP_DOWN       0x100000
#define MEM_WRITE_WATCH    0x200000
#define MEM_PHYSICAL       0x400000
#define MEM_LARGE_PAGES  0x20000000
#define MEM_4MB_PAGES    0x80000000

__stdcall uintptr_t VirtualAlloc(uintptr_t addr, uintptr_t size, int type, int prot);
__stdcall uintptr_t VirtualFree(uintptr_t addr, uintptr_t size, int freetype);
__stdcall uintptr_t VirtualProtect(uintptr_t addr, uintptr_t size, int prot, int *oldprot);
EOS

    # allocate some memory suitable for code allocation (ie VirtualAlloc)
    def self.memory_alloc(sz)
      virtualalloc(nil, sz, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE)
    end

    # free memory allocated through memory_alloc
    def self.memory_free(addr)
      virtualfree(addr, 0, MEM_RELEASE)
    end

    # change memory permissions - perm in [r rw rx rwx]
    def self.memory_perm(addr, len, perm)
      perm = { 'r' => PAGE_READONLY, 'rw' => PAGE_READWRITE, 'rx' => PAGE_EXECUTE_READ,
        'rwx' => PAGE_EXECUTE_READWRITE }[perm.to_s.downcase]
      virtualprotect(addr, len, perm, str_ptr([0].pack('C')*8))
    end

  when :linux

    new_api_c <<EOS
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

#define MAP_PRIVATE   0x2
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20

uintptr_t mmap(uintptr_t addr, uintptr_t length, int prot, int flags, uintptr_t fd, uintptr_t offset);
uintptr_t munmap(uintptr_t addr, uintptr_t length);
uintptr_t mprotect(uintptr_t addr, uintptr_t len, int prot);
EOS

    # allocate some memory suitable for code allocation (ie mmap)
    def self.memory_alloc(sz)
      @mmaps ||= {}	# save size for mem_free
      a = mmap(nil, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
      @mmaps[a] = sz
      a
    end

    # free memory allocated through memory_alloc
    def self.memory_free(addr)
      munmap(addr, @mmaps[addr])
    end

    # change memory permissions - perm 'rwx'
    # on PaX-enabled systems, this may need a non-mprotect-restricted ruby interpreter
    # if a mapping 'rx' is denied, will try to create a file and mmap() it rx in place
    def self.memory_perm(addr, len, perm)
      perm = perm.to_s.downcase
      len += (addr & 0xfff) + 0xfff
      len &= ~0xfff
      addr &= ~0xfff

      p = 0
      p |= PROT_READ  if perm.include?('r')
      p |= PROT_WRITE if perm.include?('w')
      p |= PROT_EXEC  if perm.include?('x')

      ret = mprotect(addr, len, p)

      if ret != 0 and perm.include?('x') and not perm.include?('w') and len > 0 and @memory_perm_wd ||= find_write_dir
        # We are on a PaX-mprotected system. Try to use a file mapping to work aroud.
        Dir.chdir(@memory_perm_wd) {
          fname = 'tmp_mprot_%d_%x' % [Process.pid, addr]
          data = memory_read(addr, len)
          begin
            File.open(fname, 'w') { |fd| fd.write data }
            # reopen to ensure filesystem flush
            rret = File.open(fname, 'r') { |fd| mmap(addr, len, p, MAP_FIXED|MAP_PRIVATE, fd.fileno, 0) }
            raise 'hax' if data != memory_read(addr, len)
            ret = 0 if rret == addr
          ensure
            File.unlink(fname) rescue nil
          end
        }
      end

      ret
    end

  end
end
end
