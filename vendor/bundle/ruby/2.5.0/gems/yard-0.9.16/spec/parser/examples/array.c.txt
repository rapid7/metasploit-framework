/**********************************************************************

  array.c -

  $Author$
  created at: Fri Aug  6 09:46:12 JST 1993

  Copyright (C) 1993-2007 Yukihiro Matsumoto
  Copyright (C) 2000  Network Applied Communication Laboratory, Inc.
  Copyright (C) 2000  Information-technology Promotion Agency, Japan

**********************************************************************/

#include "internal.h"
#include "ruby/util.h"
#include "ruby/st.h"
#include "probes.h"
#include "id.h"
#include "debug_counter.h"

#ifndef ARRAY_DEBUG
# define NDEBUG
#endif
#include "ruby_assert.h"

VALUE rb_cArray;

static ID id_div;

/* for OPTIMIZED_CMP: */
#define id_cmp idCmp

#define ARY_DEFAULT_SIZE 16
#define ARY_MAX_SIZE (LONG_MAX / (int)sizeof(VALUE))

# define ARY_SHARED_P(ary) \
    (assert(!FL_TEST((ary), ELTS_SHARED) || !FL_TEST((ary), RARRAY_EMBED_FLAG)), \
     FL_TEST((ary),ELTS_SHARED)!=0)
# define ARY_EMBED_P(ary) \
    (assert(!FL_TEST((ary), ELTS_SHARED) || !FL_TEST((ary), RARRAY_EMBED_FLAG)), \
     FL_TEST((ary), RARRAY_EMBED_FLAG)!=0)

#define ARY_HEAP_PTR(a) (assert(!ARY_EMBED_P(a)), RARRAY(a)->as.heap.ptr)
#define ARY_HEAP_LEN(a) (assert(!ARY_EMBED_P(a)), RARRAY(a)->as.heap.len)
#define ARY_EMBED_PTR(a) (assert(ARY_EMBED_P(a)), RARRAY(a)->as.ary)
#define ARY_EMBED_LEN(a) \
    (assert(ARY_EMBED_P(a)), \
     (long)((RBASIC(a)->flags >> RARRAY_EMBED_LEN_SHIFT) & \
	 (RARRAY_EMBED_LEN_MASK >> RARRAY_EMBED_LEN_SHIFT)))
#define ARY_HEAP_SIZE(a) (assert(!ARY_EMBED_P(a)), assert(ARY_OWNS_HEAP_P(a)), RARRAY(a)->as.heap.aux.capa * sizeof(VALUE))

#define ARY_OWNS_HEAP_P(a) (!FL_TEST((a), ELTS_SHARED|RARRAY_EMBED_FLAG))
#define FL_SET_EMBED(a) do { \
    assert(!ARY_SHARED_P(a)); \
    FL_SET((a), RARRAY_EMBED_FLAG); \
} while (0)
#define FL_UNSET_EMBED(ary) FL_UNSET((ary), RARRAY_EMBED_FLAG|RARRAY_EMBED_LEN_MASK)
#define FL_SET_SHARED(ary) do { \
    assert(!ARY_EMBED_P(ary)); \
    FL_SET((ary), ELTS_SHARED); \
} while (0)
#define FL_UNSET_SHARED(ary) FL_UNSET((ary), ELTS_SHARED)

#define ARY_SET_PTR(ary, p) do { \
    assert(!ARY_EMBED_P(ary)); \
    assert(!OBJ_FROZEN(ary)); \
    RARRAY(ary)->as.heap.ptr = (p); \
} while (0)
#define ARY_SET_EMBED_LEN(ary, n) do { \
    long tmp_n = (n); \
    assert(ARY_EMBED_P(ary)); \
    assert(!OBJ_FROZEN(ary)); \
    RBASIC(ary)->flags &= ~RARRAY_EMBED_LEN_MASK; \
    RBASIC(ary)->flags |= (tmp_n) << RARRAY_EMBED_LEN_SHIFT; \
} while (0)
#define ARY_SET_HEAP_LEN(ary, n) do { \
    assert(!ARY_EMBED_P(ary)); \
    RARRAY(ary)->as.heap.len = (n); \
} while (0)
#define ARY_SET_LEN(ary, n) do { \
    if (ARY_EMBED_P(ary)) { \
        ARY_SET_EMBED_LEN((ary), (n)); \
    } \
    else { \
        ARY_SET_HEAP_LEN((ary), (n)); \
    } \
    assert(RARRAY_LEN(ary) == (n)); \
} while (0)
#define ARY_INCREASE_PTR(ary, n) do  { \
    assert(!ARY_EMBED_P(ary)); \
    assert(!OBJ_FROZEN(ary)); \
    RARRAY(ary)->as.heap.ptr += (n); \
} while (0)
#define ARY_INCREASE_LEN(ary, n) do  { \
    assert(!OBJ_FROZEN(ary)); \
    if (ARY_EMBED_P(ary)) { \
        ARY_SET_EMBED_LEN((ary), RARRAY_LEN(ary)+(n)); \
    } \
    else { \
        RARRAY(ary)->as.heap.len += (n); \
    } \
} while (0)

#define ARY_CAPA(ary) (ARY_EMBED_P(ary) ? RARRAY_EMBED_LEN_MAX : \
		       ARY_SHARED_ROOT_P(ary) ? RARRAY_LEN(ary) : RARRAY(ary)->as.heap.aux.capa)
#define ARY_SET_CAPA(ary, n) do { \
    assert(!ARY_EMBED_P(ary)); \
    assert(!ARY_SHARED_P(ary)); \
    assert(!OBJ_FROZEN(ary)); \
    RARRAY(ary)->as.heap.aux.capa = (n); \
} while (0)

#define ARY_SHARED(ary) (assert(ARY_SHARED_P(ary)), RARRAY(ary)->as.heap.aux.shared)
#define ARY_SET_SHARED(ary, value) do { \
    const VALUE _ary_ = (ary); \
    const VALUE _value_ = (value); \
    assert(!ARY_EMBED_P(_ary_)); \
    assert(ARY_SHARED_P(_ary_)); \
    assert(ARY_SHARED_ROOT_P(_value_)); \
    RB_OBJ_WRITE(_ary_, &RARRAY(_ary_)->as.heap.aux.shared, _value_); \
} while (0)
#define RARRAY_SHARED_ROOT_FLAG FL_USER5
#define ARY_SHARED_ROOT_P(ary) (FL_TEST((ary), RARRAY_SHARED_ROOT_FLAG))
#define ARY_SHARED_NUM(ary) \
    (assert(ARY_SHARED_ROOT_P(ary)), RARRAY(ary)->as.heap.aux.capa)
#define ARY_SHARED_OCCUPIED(ary) (ARY_SHARED_NUM(ary) == 1)
#define ARY_SET_SHARED_NUM(ary, value) do { \
    assert(ARY_SHARED_ROOT_P(ary)); \
    RARRAY(ary)->as.heap.aux.capa = (value); \
} while (0)
#define FL_SET_SHARED_ROOT(ary) do { \
    assert(!ARY_EMBED_P(ary)); \
    FL_SET((ary), RARRAY_SHARED_ROOT_FLAG); \
} while (0)

#define ARY_SET(a, i, v) RARRAY_ASET((assert(!ARY_SHARED_P(a)), (a)), (i), (v))

void
rb_mem_clear(register VALUE *mem, register long size)
{
    while (size--) {
	*mem++ = Qnil;
    }
}

static void
ary_mem_clear(VALUE ary, long beg, long size)
{
    RARRAY_PTR_USE(ary, ptr, {
	rb_mem_clear(ptr + beg, size);
    });
}

static inline void
memfill(register VALUE *mem, register long size, register VALUE val)
{
    while (size--) {
	*mem++ = val;
    }
}

static void
ary_memfill(VALUE ary, long beg, long size, VALUE val)
{
    RARRAY_PTR_USE(ary, ptr, {
	memfill(ptr + beg, size, val);
	RB_OBJ_WRITTEN(ary, Qundef, val);
    });
}

static void
ary_memcpy0(VALUE ary, long beg, long argc, const VALUE *argv, VALUE buff_owner_ary)
{
#if 1
    assert(!ARY_SHARED_P(buff_owner_ary));

    if (argc > (int)(128/sizeof(VALUE)) /* is magic number (cache line size) */) {
	rb_gc_writebarrier_remember(buff_owner_ary);
	RARRAY_PTR_USE(ary, ptr, {
	    MEMCPY(ptr+beg, argv, VALUE, argc);
	});
    }
    else {
	int i;
	RARRAY_PTR_USE(ary, ptr, {
	    for (i=0; i<argc; i++) {
		RB_OBJ_WRITE(buff_owner_ary, &ptr[i+beg], argv[i]);
	    }
	});
    }
#else
    /* giveup write barrier (traditional way) */
    RARRAY_PTR(buff_owner_ary);
    MEMCPY(RARRAY_PTR(ary)+beg, argv, VALUE, argc);
#endif
}

static void
ary_memcpy(VALUE ary, long beg, long argc, const VALUE *argv)
{
    ary_memcpy0(ary, beg, argc, argv, ary);
}

static void
ary_resize_capa(VALUE ary, long capacity)
{
    assert(RARRAY_LEN(ary) <= capacity);
    assert(!OBJ_FROZEN(ary));
    assert(!ARY_SHARED_P(ary));
    if (capacity > RARRAY_EMBED_LEN_MAX) {
        if (ARY_EMBED_P(ary)) {
            long len = ARY_EMBED_LEN(ary);
            VALUE *ptr = ALLOC_N(VALUE, (capacity));
            MEMCPY(ptr, ARY_EMBED_PTR(ary), VALUE, len);
            FL_UNSET_EMBED(ary);
            ARY_SET_PTR(ary, ptr);
            ARY_SET_HEAP_LEN(ary, len);
        }
        else {
	    SIZED_REALLOC_N(RARRAY(ary)->as.heap.ptr, VALUE, capacity, RARRAY(ary)->as.heap.aux.capa);
        }
        ARY_SET_CAPA(ary, (capacity));
    }
    else {
        if (!ARY_EMBED_P(ary)) {
            long len = RARRAY_LEN(ary);
	    const VALUE *ptr = RARRAY_CONST_PTR(ary);

	    if (len > capacity) len = capacity;
            MEMCPY((VALUE *)RARRAY(ary)->as.ary, ptr, VALUE, len);
            FL_SET_EMBED(ary);
            ARY_SET_LEN(ary, len);
	    ruby_xfree((VALUE *)ptr);
        }
    }
}

static inline void
ary_shrink_capa(VALUE ary)
{
    long capacity = ARY_HEAP_LEN(ary);
    long old_capa = RARRAY(ary)->as.heap.aux.capa;
    assert(!ARY_SHARED_P(ary));
    assert(old_capa >= capacity);
    if (old_capa > capacity)
	REALLOC_N(RARRAY(ary)->as.heap.ptr, VALUE, capacity);
}

static void
ary_double_capa(VALUE ary, long min)
{
    long new_capa = ARY_CAPA(ary) / 2;

    if (new_capa < ARY_DEFAULT_SIZE) {
	new_capa = ARY_DEFAULT_SIZE;
    }
    if (new_capa >= ARY_MAX_SIZE - min) {
	new_capa = (ARY_MAX_SIZE - min) / 2;
    }
    new_capa += min;
    ary_resize_capa(ary, new_capa);
}

static void
rb_ary_decrement_share(VALUE shared)
{
    if (shared) {
	long num = ARY_SHARED_NUM(shared) - 1;
	if (num == 0) {
	    rb_ary_free(shared);
	    rb_gc_force_recycle(shared);
	}
	else if (num > 0) {
	    ARY_SET_SHARED_NUM(shared, num);
	}
    }
}

static void
rb_ary_unshare(VALUE ary)
{
    VALUE shared = RARRAY(ary)->as.heap.aux.shared;
    rb_ary_decrement_share(shared);
    FL_UNSET_SHARED(ary);
}

static inline void
rb_ary_unshare_safe(VALUE ary)
{
    if (ARY_SHARED_P(ary) && !ARY_EMBED_P(ary)) {
	rb_ary_unshare(ary);
    }
}

static VALUE
rb_ary_increment_share(VALUE shared)
{
    long num = ARY_SHARED_NUM(shared);
    if (num >= 0) {
	ARY_SET_SHARED_NUM(shared, num + 1);
    }
    return shared;
}

static void
rb_ary_set_shared(VALUE ary, VALUE shared)
{
    rb_ary_increment_share(shared);
    FL_SET_SHARED(ary);
    ARY_SET_SHARED(ary, shared);
}

static inline void
rb_ary_modify_check(VALUE ary)
{
    rb_check_frozen(ary);
}

void
rb_ary_modify(VALUE ary)
{
    rb_ary_modify_check(ary);
    if (ARY_SHARED_P(ary)) {
	long shared_len, len = RARRAY_LEN(ary);
	VALUE shared = ARY_SHARED(ary);
        if (len <= RARRAY_EMBED_LEN_MAX) {
	    const VALUE *ptr = ARY_HEAP_PTR(ary);
            FL_UNSET_SHARED(ary);
            FL_SET_EMBED(ary);
	    MEMCPY((VALUE *)ARY_EMBED_PTR(ary), ptr, VALUE, len);
            rb_ary_decrement_share(shared);
            ARY_SET_EMBED_LEN(ary, len);
        }
	else if (ARY_SHARED_OCCUPIED(shared) && len > ((shared_len = RARRAY_LEN(shared))>>1)) {
	    long shift = RARRAY_CONST_PTR(ary) - RARRAY_CONST_PTR(shared);
	    FL_UNSET_SHARED(ary);
	    ARY_SET_PTR(ary, RARRAY_CONST_PTR(shared));
	    ARY_SET_CAPA(ary, shared_len);
	    RARRAY_PTR_USE(ary, ptr, {
		MEMMOVE(ptr, ptr+shift, VALUE, len);
	    });
	    FL_SET_EMBED(shared);
	    rb_ary_decrement_share(shared);
	}
        else {
            VALUE *ptr = ALLOC_N(VALUE, len);
            MEMCPY(ptr, RARRAY_CONST_PTR(ary), VALUE, len);
            rb_ary_unshare(ary);
            ARY_SET_CAPA(ary, len);
            ARY_SET_PTR(ary, ptr);
        }

	rb_gc_writebarrier_remember(ary);
    }
}

static VALUE
ary_ensure_room_for_push(VALUE ary, long add_len)
{
    long old_len = RARRAY_LEN(ary);
    long new_len = old_len + add_len;
    long capa;

    if (old_len > ARY_MAX_SIZE - add_len) {
	rb_raise(rb_eIndexError, "index %ld too big", new_len);
    }
    if (ARY_SHARED_P(ary)) {
	if (new_len > RARRAY_EMBED_LEN_MAX) {
	    VALUE shared = ARY_SHARED(ary);
	    if (ARY_SHARED_OCCUPIED(shared)) {
		if (RARRAY_CONST_PTR(ary) - RARRAY_CONST_PTR(shared) + new_len <= RARRAY_LEN(shared)) {
		    rb_ary_modify_check(ary);
		    return shared;
		}
		else {
		    /* if array is shared, then it is likely it participate in push/shift pattern */
		    rb_ary_modify(ary);
		    capa = ARY_CAPA(ary);
		    if (new_len > capa - (capa >> 6)) {
			ary_double_capa(ary, new_len);
		    }
		    return ary;
		}
	    }
	}
	rb_ary_modify(ary);
    }
    else {
	rb_ary_modify_check(ary);
    }
    capa = ARY_CAPA(ary);
    if (new_len > capa) {
	ary_double_capa(ary, new_len);
    }

    return ary;
}

/*
 *  call-seq:
 *      ary.freeze -> ary
 *
 *  Calls Object#freeze on +ary+ to prevent any further
 *  modification. A RuntimeError will be raised if a modification
 *  attempt is made.
 *
 */

VALUE
rb_ary_freeze(VALUE ary)
{
    return rb_obj_freeze(ary);
}

/*
 *  call-seq:
 *     ary.frozen?  -> true or false
 *
 *  Return +true+ if this array is frozen (or temporarily frozen
 *  while being sorted). See also Object#frozen?
 */

static VALUE
rb_ary_frozen_p(VALUE ary)
{
    if (OBJ_FROZEN(ary)) return Qtrue;
    return Qfalse;
}

/* This can be used to take a snapshot of an array (with
   e.g. rb_ary_replace) and check later whether the array has been
   modified from the snapshot.  The snapshot is cheap, though if
   something does modify the array it will pay the cost of copying
   it.  If Array#pop or Array#shift has been called, the array will
   be still shared with the snapshot, but the array length will
   differ. */
VALUE
rb_ary_shared_with_p(VALUE ary1, VALUE ary2)
{
    if (!ARY_EMBED_P(ary1) && ARY_SHARED_P(ary1) &&
	!ARY_EMBED_P(ary2) && ARY_SHARED_P(ary2) &&
	RARRAY(ary1)->as.heap.aux.shared == RARRAY(ary2)->as.heap.aux.shared &&
	RARRAY(ary1)->as.heap.len == RARRAY(ary2)->as.heap.len) {
	return Qtrue;
    }
    return Qfalse;
}

static VALUE
ary_alloc(VALUE klass)
{
    NEWOBJ_OF(ary, struct RArray, klass, T_ARRAY | RARRAY_EMBED_FLAG | (RGENGC_WB_PROTECTED_ARRAY ? FL_WB_PROTECTED : 0));
    /* Created array is:
     *   FL_SET_EMBED((VALUE)ary);
     *   ARY_SET_EMBED_LEN((VALUE)ary, 0);
     */
    return (VALUE)ary;
}

static VALUE
empty_ary_alloc(VALUE klass)
{
    RUBY_DTRACE_CREATE_HOOK(ARRAY, 0);
    return ary_alloc(klass);
}

static VALUE
ary_new(VALUE klass, long capa)
{
    VALUE ary,*ptr;

    if (capa < 0) {
	rb_raise(rb_eArgError, "negative array size (or size too big)");
    }
    if (capa > ARY_MAX_SIZE) {
	rb_raise(rb_eArgError, "array size too big");
    }

    RUBY_DTRACE_CREATE_HOOK(ARRAY, capa);

    ary = ary_alloc(klass);
    if (capa > RARRAY_EMBED_LEN_MAX) {
	ptr = ALLOC_N(VALUE, capa);
        FL_UNSET_EMBED(ary);
        ARY_SET_PTR(ary, ptr);
        ARY_SET_CAPA(ary, capa);
        ARY_SET_HEAP_LEN(ary, 0);
    }

    return ary;
}

VALUE
rb_ary_new_capa(long capa)
{
    return ary_new(rb_cArray, capa);
}

VALUE
rb_ary_new(void)
{
    return rb_ary_new2(RARRAY_EMBED_LEN_MAX);
}

VALUE
(rb_ary_new_from_args)(long n, ...)
{
    va_list ar;
    VALUE ary;
    long i;

    ary = rb_ary_new2(n);

    va_start(ar, n);
    for (i=0; i<n; i++) {
	ARY_SET(ary, i, va_arg(ar, VALUE));
    }
    va_end(ar);

    ARY_SET_LEN(ary, n);
    return ary;
}

VALUE
rb_ary_tmp_new_from_values(VALUE klass, long n, const VALUE *elts)
{
    VALUE ary;

    ary = ary_new(klass, n);
    if (n > 0 && elts) {
	ary_memcpy(ary, 0, n, elts);
	ARY_SET_LEN(ary, n);
    }

    return ary;
}

VALUE
rb_ary_new_from_values(long n, const VALUE *elts)
{
    return rb_ary_tmp_new_from_values(rb_cArray, n, elts);
}

VALUE
rb_ary_tmp_new(long capa)
{
    return ary_new(0, capa);
}

VALUE
rb_ary_tmp_new_fill(long capa)
{
    VALUE ary = ary_new(0, capa);
    ary_memfill(ary, 0, capa, Qnil);
    ARY_SET_LEN(ary, capa);
    return ary;
}

void
rb_ary_free(VALUE ary)
{
    if (ARY_OWNS_HEAP_P(ary)) {
	RB_DEBUG_COUNTER_INC(obj_ary_ptr);
	ruby_sized_xfree((void *)ARY_HEAP_PTR(ary), ARY_HEAP_SIZE(ary));
    }
    else {
	RB_DEBUG_COUNTER_INC(obj_ary_embed);
    }
}

RUBY_FUNC_EXPORTED size_t
rb_ary_memsize(VALUE ary)
{
    if (ARY_OWNS_HEAP_P(ary)) {
	return ARY_CAPA(ary) * sizeof(VALUE);
    }
    else {
	return 0;
    }
}

static inline void
ary_discard(VALUE ary)
{
    rb_ary_free(ary);
    RBASIC(ary)->flags |= RARRAY_EMBED_FLAG;
    RBASIC(ary)->flags &= ~RARRAY_EMBED_LEN_MASK;
}

static VALUE
ary_make_shared(VALUE ary)
{
    assert(!ARY_EMBED_P(ary));
    if (ARY_SHARED_P(ary)) {
	return ARY_SHARED(ary);
    }
    else if (ARY_SHARED_ROOT_P(ary)) {
	return ary;
    }
    else if (OBJ_FROZEN(ary)) {
	ary_shrink_capa(ary);
	FL_SET_SHARED_ROOT(ary);
	ARY_SET_SHARED_NUM(ary, 1);
	return ary;
    }
    else {
	long capa = ARY_CAPA(ary), len = RARRAY_LEN(ary);
	NEWOBJ_OF(shared, struct RArray, 0, T_ARRAY | (RGENGC_WB_PROTECTED_ARRAY ? FL_WB_PROTECTED : 0));
        FL_UNSET_EMBED(shared);

	ARY_SET_LEN((VALUE)shared, capa);
	ARY_SET_PTR((VALUE)shared, RARRAY_CONST_PTR(ary));
	ary_mem_clear((VALUE)shared, len, capa - len);
	FL_SET_SHARED_ROOT(shared);
	ARY_SET_SHARED_NUM((VALUE)shared, 1);
	FL_SET_SHARED(ary);
	ARY_SET_SHARED(ary, (VALUE)shared);
	OBJ_FREEZE(shared);
	return (VALUE)shared;
    }
}

static VALUE
ary_make_substitution(VALUE ary)
{
    long len = RARRAY_LEN(ary);

    if (len <= RARRAY_EMBED_LEN_MAX) {
	VALUE subst = rb_ary_new2(len);
	ary_memcpy(subst, 0, len, RARRAY_CONST_PTR(ary));
        ARY_SET_EMBED_LEN(subst, len);
        return subst;
    }
    else {
        return rb_ary_increment_share(ary_make_shared(ary));
    }
}

VALUE
rb_assoc_new(VALUE car, VALUE cdr)
{
    return rb_ary_new3(2, car, cdr);
}

static VALUE
to_ary(VALUE ary)
{
    return rb_convert_type_with_id(ary, T_ARRAY, "Array", idTo_ary);
}

VALUE
rb_check_array_type(VALUE ary)
{
    return rb_check_convert_type_with_id(ary, T_ARRAY, "Array", idTo_ary);
}

/*
 *  call-seq:
 *     Array.try_convert(obj) -> array or nil
 *
 *  Tries to convert +obj+ into an array, using +to_ary+ method.  Returns the
 *  converted array or +nil+ if +obj+ cannot be converted for any reason.
 *  This method can be used to check if an argument is an array.
 *
 *     Array.try_convert([1])   #=> [1]
 *     Array.try_convert("1")   #=> nil
 *
 *     if tmp = Array.try_convert(arg)
 *       # the argument is an array
 *     elsif tmp = String.try_convert(arg)
 *       # the argument is a string
 *     end
 *
 */

static VALUE
rb_ary_s_try_convert(VALUE dummy, VALUE ary)
{
    return rb_check_array_type(ary);
}

/*
 *  call-seq:
 *     Array.new(size=0, default=nil)
 *     Array.new(array)
 *     Array.new(size) {|index| block }
 *
 *  Returns a new array.
 *
 *  In the first form, if no arguments are sent, the new array will be empty.
 *  When a +size+ and an optional +default+ are sent, an array is created with
 *  +size+ copies of +default+.  Take notice that all elements will reference the
 *  same object +default+.
 *
 *  The second form creates a copy of the array passed as a parameter (the
 *  array is generated by calling to_ary on the parameter).
 *
 *    first_array = ["Matz", "Guido"]
 *
 *    second_array = Array.new(first_array) #=> ["Matz", "Guido"]
 *
 *    first_array.equal? second_array       #=> false
 *
 *  In the last form, an array of the given size is created.  Each element in
 *  this array is created by passing the element's index to the given block
 *  and storing the return value.
 *
 *    Array.new(3){ |index| index ** 2 }
 *    # => [0, 1, 4]
 *
 *  == Common gotchas
 *
 *  When sending the second parameter, the same object will be used as the
 *  value for all the array elements:
 *
 *     a = Array.new(2, Hash.new)
 *     # => [{}, {}]
 *
 *     a[0]['cat'] = 'feline'
 *     a # => [{"cat"=>"feline"}, {"cat"=>"feline"}]
 *
 *     a[1]['cat'] = 'Felix'
 *     a # => [{"cat"=>"Felix"}, {"cat"=>"Felix"}]
 *
 *  Since all the Array elements store the same hash, changes to one of them
 *  will affect them all.
 *
 *  If multiple copies are what you want, you should use the block
 *  version which uses the result of that block each time an element
 *  of the array needs to be initialized:
 *
 *     a = Array.new(2) { Hash.new }
 *     a[0]['cat'] = 'feline'
 *     a # => [{"cat"=>"feline"}, {}]
 *
 */

static VALUE
rb_ary_initialize(int argc, VALUE *argv, VALUE ary)
{
    long len;
    VALUE size, val;

    rb_ary_modify(ary);
    if (argc == 0) {
	if (ARY_OWNS_HEAP_P(ary) && RARRAY_CONST_PTR(ary) != 0) {
	    ruby_sized_xfree((void *)RARRAY_CONST_PTR(ary), ARY_HEAP_SIZE(ary));
	}
        rb_ary_unshare_safe(ary);
        FL_SET_EMBED(ary);
	ARY_SET_EMBED_LEN(ary, 0);
	if (rb_block_given_p()) {
	    rb_warning("given block not used");
	}
	return ary;
    }
    rb_scan_args(argc, argv, "02", &size, &val);
    if (argc == 1 && !FIXNUM_P(size)) {
	val = rb_check_array_type(size);
	if (!NIL_P(val)) {
	    rb_ary_replace(ary, val);
	    return ary;
	}
    }

    len = NUM2LONG(size);
    /* NUM2LONG() may call size.to_int, ary can be frozen, modified, etc */
    if (len < 0) {
	rb_raise(rb_eArgError, "negative array size");
    }
    if (len > ARY_MAX_SIZE) {
	rb_raise(rb_eArgError, "array size too big");
    }
    /* recheck after argument conversion */
    rb_ary_modify(ary);
    ary_resize_capa(ary, len);
    if (rb_block_given_p()) {
	long i;

	if (argc == 2) {
	    rb_warn("block supersedes default value argument");
	}
	for (i=0; i<len; i++) {
	    rb_ary_store(ary, i, rb_yield(LONG2NUM(i)));
	    ARY_SET_LEN(ary, i + 1);
	}
    }
    else {
	ary_memfill(ary, 0, len, val);
	ARY_SET_LEN(ary, len);
    }
    return ary;
}

/*
 * Returns a new array populated with the given objects.
 *
 *   Array.[]( 1, 'a', /^A/ ) # => [1, "a", /^A/]
 *   Array[ 1, 'a', /^A/ ]    # => [1, "a", /^A/]
 *   [ 1, 'a', /^A/ ]         # => [1, "a", /^A/]
 */

static VALUE
rb_ary_s_create(int argc, VALUE *argv, VALUE klass)
{
    VALUE ary = ary_new(klass, argc);
    if (argc > 0 && argv) {
        ary_memcpy(ary, 0, argc, argv);
        ARY_SET_LEN(ary, argc);
    }

    return ary;
}

void
rb_ary_store(VALUE ary, long idx, VALUE val)
{
    long len = RARRAY_LEN(ary);

    if (idx < 0) {
	idx += len;
	if (idx < 0) {
	    rb_raise(rb_eIndexError, "index %ld too small for array; minimum: %ld",
		     idx - len, -len);
	}
    }
    else if (idx >= ARY_MAX_SIZE) {
	rb_raise(rb_eIndexError, "index %ld too big", idx);
    }

    rb_ary_modify(ary);
    if (idx >= ARY_CAPA(ary)) {
	ary_double_capa(ary, idx);
    }
    if (idx > len) {
	ary_mem_clear(ary, len, idx - len + 1);
    }

    if (idx >= len) {
	ARY_SET_LEN(ary, idx + 1);
    }
    ARY_SET(ary, idx, val);
}

static VALUE
ary_make_partial(VALUE ary, VALUE klass, long offset, long len)
{
    assert(offset >= 0);
    assert(len >= 0);
    assert(offset+len <= RARRAY_LEN(ary));

    if (len <= RARRAY_EMBED_LEN_MAX) {
        VALUE result = ary_alloc(klass);
	ary_memcpy(result, 0, len, RARRAY_CONST_PTR(ary) + offset);
        ARY_SET_EMBED_LEN(result, len);
        return result;
    }
    else {
        VALUE shared, result = ary_alloc(klass);
        FL_UNSET_EMBED(result);

        shared = ary_make_shared(ary);
        ARY_SET_PTR(result, RARRAY_CONST_PTR(ary));
        ARY_SET_LEN(result, RARRAY_LEN(ary));
        rb_ary_set_shared(result, shared);

        ARY_INCREASE_PTR(result, offset);
        ARY_SET_LEN(result, len);
        return result;
    }
}

static VALUE
ary_make_shared_copy(VALUE ary)
{
    return ary_make_partial(ary, rb_obj_class(ary), 0, RARRAY_LEN(ary));
}

enum ary_take_pos_flags
{
    ARY_TAKE_FIRST = 0,
    ARY_TAKE_LAST = 1
};

static VALUE
ary_take_first_or_last(int argc, const VALUE *argv, VALUE ary, enum ary_take_pos_flags last)
{
    VALUE nv;
    long n;
    long len;
    long offset = 0;

    rb_scan_args(argc, argv, "1", &nv);
    n = NUM2LONG(nv);
    len = RARRAY_LEN(ary);
    if (n > len) {
	n = len;
    }
    else if (n < 0) {
	rb_raise(rb_eArgError, "negative array size");
    }
    if (last) {
	offset = len - n;
    }
    return ary_make_partial(ary, rb_cArray, offset, n);
}

/*
 *  call-seq:
 *     ary << obj            -> ary
 *
 *  Append---Pushes the given object on to the end of this array. This
 *  expression returns the array itself, so several appends
 *  may be chained together.
 *
 *     a = [ 1, 2 ]
 *     a << "c" << "d" << [ 3, 4 ]
 *             #=>  [ 1, 2, "c", "d", [ 3, 4 ] ]
 *     a
 *             #=>  [ 1, 2, "c", "d", [ 3, 4 ] ]
 *
 */

VALUE
rb_ary_push(VALUE ary, VALUE item)
{
    long idx = RARRAY_LEN(ary);
    VALUE target_ary = ary_ensure_room_for_push(ary, 1);
    RARRAY_PTR_USE(ary, ptr, {
	RB_OBJ_WRITE(target_ary, &ptr[idx], item);
    });
    ARY_SET_LEN(ary, idx + 1);
    return ary;
}

VALUE
rb_ary_cat(VALUE ary, const VALUE *argv, long len)
{
    long oldlen = RARRAY_LEN(ary);
    VALUE target_ary = ary_ensure_room_for_push(ary, len);
    ary_memcpy0(ary, oldlen, len, argv, target_ary);
    ARY_SET_LEN(ary, oldlen + len);
    return ary;
}

/*
 *  call-seq:
 *     ary.push(obj, ... )   -> ary
 *
 *  Append --- Pushes the given object(s) on to the end of this array. This
 *  expression returns the array itself, so several appends
 *  may be chained together. See also Array#pop for the opposite
 *  effect.
 *
 *     a = [ "a", "b", "c" ]
 *     a.push("d", "e", "f")
 *             #=> ["a", "b", "c", "d", "e", "f"]
 *     [1, 2, 3].push(4).push(5)
 *             #=> [1, 2, 3, 4, 5]
 */

static VALUE
rb_ary_push_m(int argc, VALUE *argv, VALUE ary)
{
    return rb_ary_cat(ary, argv, argc);
}

VALUE
rb_ary_pop(VALUE ary)
{
    long n;
    rb_ary_modify_check(ary);
    n = RARRAY_LEN(ary);
    if (n == 0) return Qnil;
    if (ARY_OWNS_HEAP_P(ary) &&
	n * 3 < ARY_CAPA(ary) &&
	ARY_CAPA(ary) > ARY_DEFAULT_SIZE)
    {
	ary_resize_capa(ary, n * 2);
    }
    --n;
    ARY_SET_LEN(ary, n);
    return RARRAY_AREF(ary, n);
}

/*
 *  call-seq:
 *     ary.pop    -> obj or nil
 *     ary.pop(n) -> new_ary
 *
 *  Removes the last element from +self+ and returns it, or
 *  +nil+ if the array is empty.
 *
 *  If a number +n+ is given, returns an array of the last +n+ elements
 *  (or less) just like <code>array.slice!(-n, n)</code> does. See also
 *  Array#push for the opposite effect.
 *
 *     a = [ "a", "b", "c", "d" ]
 *     a.pop     #=> "d"
 *     a.pop(2)  #=> ["b", "c"]
 *     a         #=> ["a"]
 */

static VALUE
rb_ary_pop_m(int argc, VALUE *argv, VALUE ary)
{
    VALUE result;

    if (argc == 0) {
	return rb_ary_pop(ary);
    }

    rb_ary_modify_check(ary);
    result = ary_take_first_or_last(argc, argv, ary, ARY_TAKE_LAST);
    ARY_INCREASE_LEN(ary, -RARRAY_LEN(result));
    return result;
}

VALUE
rb_ary_shift(VALUE ary)
{
    VALUE top;
    long len = RARRAY_LEN(ary);

    rb_ary_modify_check(ary);
    if (len == 0) return Qnil;
    top = RARRAY_AREF(ary, 0);
    if (!ARY_SHARED_P(ary)) {
	if (len < ARY_DEFAULT_SIZE) {
	    RARRAY_PTR_USE(ary, ptr, {
		MEMMOVE(ptr, ptr+1, VALUE, len-1);
	    }); /* WB: no new reference */
            ARY_INCREASE_LEN(ary, -1);
	    return top;
	}
        assert(!ARY_EMBED_P(ary)); /* ARY_EMBED_LEN_MAX < ARY_DEFAULT_SIZE */

	ARY_SET(ary, 0, Qnil);
	ary_make_shared(ary);
    }
    else if (ARY_SHARED_OCCUPIED(ARY_SHARED(ary))) {
	RARRAY_PTR_USE(ary, ptr, ptr[0] = Qnil);
    }
    ARY_INCREASE_PTR(ary, 1);		/* shift ptr */
    ARY_INCREASE_LEN(ary, -1);

    return top;
}

/*
 *  call-seq:
 *     ary.shift    -> obj or nil
 *     ary.shift(n) -> new_ary
 *
 *  Removes the first element of +self+ and returns it (shifting all
 *  other elements down by one). Returns +nil+ if the array
 *  is empty.
 *
 *  If a number +n+ is given, returns an array of the first +n+ elements
 *  (or less) just like <code>array.slice!(0, n)</code> does. With +ary+
 *  containing only the remainder elements, not including what was shifted to
 *  +new_ary+. See also Array#unshift for the opposite effect.
 *
 *     args = [ "-m", "-q", "filename" ]
 *     args.shift     #=> "-m"
 *     args           #=> ["-q", "filename"]
 *
 *     args = [ "-m", "-q", "filename" ]
 *     args.shift(2)  #=> ["-m", "-q"]
 *     args           #=> ["filename"]
 */

static VALUE
rb_ary_shift_m(int argc, VALUE *argv, VALUE ary)
{
    VALUE result;
    long n;

    if (argc == 0) {
	return rb_ary_shift(ary);
    }

    rb_ary_modify_check(ary);
    result = ary_take_first_or_last(argc, argv, ary, ARY_TAKE_FIRST);
    n = RARRAY_LEN(result);
    if (ARY_SHARED_P(ary)) {
	if (ARY_SHARED_OCCUPIED(ARY_SHARED(ary))) {
	  setup_occupied_shared:
	    ary_mem_clear(ary, 0, n);
	}
        ARY_INCREASE_PTR(ary, n);
    }
    else {
	if (RARRAY_LEN(ary) < ARY_DEFAULT_SIZE) {
	    RARRAY_PTR_USE(ary, ptr, {
		MEMMOVE(ptr, ptr+n, VALUE, RARRAY_LEN(ary)-n);
	    }); /* WB: no new reference */
	}
	else {
	    ary_make_shared(ary);
	    goto setup_occupied_shared;
	}
    }
    ARY_INCREASE_LEN(ary, -n);

    return result;
}

static VALUE
ary_ensure_room_for_unshift(VALUE ary, int argc)
{
    long len = RARRAY_LEN(ary);
    long new_len = len + argc;
    long capa;
    const VALUE *head, *sharedp;

    if (len > ARY_MAX_SIZE - argc) {
	rb_raise(rb_eIndexError, "index %ld too big", new_len);
    }

    if (ARY_SHARED_P(ary)) {
	VALUE shared = ARY_SHARED(ary);
	capa = RARRAY_LEN(shared);
	if (ARY_SHARED_OCCUPIED(shared) && capa > new_len) {
	    head = RARRAY_CONST_PTR(ary);
	    sharedp = RARRAY_CONST_PTR(shared);
	    goto makeroom_if_need;
	}
    }

    rb_ary_modify(ary);
    capa = ARY_CAPA(ary);
    if (capa - (capa >> 6) <= new_len) {
	ary_double_capa(ary, new_len);
    }

    /* use shared array for big "queues" */
    if (new_len > ARY_DEFAULT_SIZE * 4) {
	/* make a room for unshifted items */
	capa = ARY_CAPA(ary);
	ary_make_shared(ary);

	head = sharedp = RARRAY_CONST_PTR(ary);
	goto makeroom;
      makeroom_if_need:
	if (head - sharedp < argc) {
	    long room;
	  makeroom:
	    room = capa - new_len;
	    room -= room >> 4;
	    MEMMOVE((VALUE *)sharedp + argc + room, head, VALUE, len);
	    head = sharedp + argc + room;
	}
	ARY_SET_PTR(ary, head - argc);
	assert(ARY_SHARED_OCCUPIED(ARY_SHARED(ary)));
	return ARY_SHARED(ary);
    }
    else {
	/* sliding items */
	RARRAY_PTR_USE(ary, ptr, {
	    MEMMOVE(ptr + argc, ptr, VALUE, len);
	});

	return ary;
    }
}

/*
 *  call-seq:
 *     ary.unshift(obj, ...)  -> ary
 *
 *  Prepends objects to the front of +self+, moving other elements upwards.
 *  See also Array#shift for the opposite effect.
 *
 *     a = [ "b", "c", "d" ]
 *     a.unshift("a")   #=> ["a", "b", "c", "d"]
 *     a.unshift(1, 2)  #=> [ 1, 2, "a", "b", "c", "d"]
 */

static VALUE
rb_ary_unshift_m(int argc, VALUE *argv, VALUE ary)
{
    long len = RARRAY_LEN(ary);
    VALUE target_ary;

    if (argc == 0) {
	rb_ary_modify_check(ary);
	return ary;
    }

    target_ary = ary_ensure_room_for_unshift(ary, argc);
    ary_memcpy0(ary, 0, argc, argv, target_ary);
    ARY_SET_LEN(ary, len + argc);
    return ary;
}

VALUE
rb_ary_unshift(VALUE ary, VALUE item)
{
    return rb_ary_unshift_m(1,&item,ary);
}

/* faster version - use this if you don't need to treat negative offset */
static inline VALUE
rb_ary_elt(VALUE ary, long offset)
{
    long len = RARRAY_LEN(ary);
    if (len == 0) return Qnil;
    if (offset < 0 || len <= offset) {
	return Qnil;
    }
    return RARRAY_AREF(ary, offset);
}

VALUE
rb_ary_entry(VALUE ary, long offset)
{
    long len = RARRAY_LEN(ary);
    const VALUE *ptr = RARRAY_CONST_PTR(ary);
    if (len == 0) return Qnil;
    if (offset < 0) {
        offset += len;
        if (offset < 0) return Qnil;
    }
    else if (len <= offset) {
        return Qnil;
    }
    return ptr[offset];
}

VALUE
rb_ary_subseq(VALUE ary, long beg, long len)
{
    VALUE klass;
    long alen = RARRAY_LEN(ary);

    if (beg > alen) return Qnil;
    if (beg < 0 || len < 0) return Qnil;

    if (alen < len || alen < beg + len) {
	len = alen - beg;
    }
    klass = rb_obj_class(ary);
    if (len == 0) return ary_new(klass, 0);

    return ary_make_partial(ary, klass, beg, len);
}

/*
 *  call-seq:
 *     ary[index]                -> obj     or nil
 *     ary[start, length]        -> new_ary or nil
 *     ary[range]                -> new_ary or nil
 *     ary.slice(index)          -> obj     or nil
 *     ary.slice(start, length)  -> new_ary or nil
 *     ary.slice(range)          -> new_ary or nil
 *
 *  Element Reference --- Returns the element at +index+, or returns a
 *  subarray starting at the +start+ index and continuing for +length+
 *  elements, or returns a subarray specified by +range+ of indices.
 *
 *  Negative indices count backward from the end of the array (-1 is the last
 *  element).  For +start+ and +range+ cases the starting index is just before
 *  an element.  Additionally, an empty array is returned when the starting
 *  index for an element range is at the end of the array.
 *
 *  Returns +nil+ if the index (or starting index) are out of range.
 *
 *     a = [ "a", "b", "c", "d", "e" ]
 *     a[2] +  a[0] + a[1]    #=> "cab"
 *     a[6]                   #=> nil
 *     a[1, 2]                #=> [ "b", "c" ]
 *     a[1..3]                #=> [ "b", "c", "d" ]
 *     a[4..7]                #=> [ "e" ]
 *     a[6..10]               #=> nil
 *     a[-3, 3]               #=> [ "c", "d", "e" ]
 *     # special cases
 *     a[5]                   #=> nil
 *     a[6, 1]                #=> nil
 *     a[5, 1]                #=> []
 *     a[5..10]               #=> []
 *
 */

VALUE
rb_ary_aref(int argc, const VALUE *argv, VALUE ary)
{
    VALUE arg;
    long beg, len;

    if (argc == 2) {
	beg = NUM2LONG(argv[0]);
	len = NUM2LONG(argv[1]);
	if (beg < 0) {
	    beg += RARRAY_LEN(ary);
	}
	return rb_ary_subseq(ary, beg, len);
    }
    if (argc != 1) {
	rb_scan_args(argc, argv, "11", NULL, NULL);
    }
    arg = argv[0];
    /* special case - speeding up */
    if (FIXNUM_P(arg)) {
	return rb_ary_entry(ary, FIX2LONG(arg));
    }
    /* check if idx is Range */
    switch (rb_range_beg_len(arg, &beg, &len, RARRAY_LEN(ary), 0)) {
      case Qfalse:
	break;
      case Qnil:
	return Qnil;
      default:
	return rb_ary_subseq(ary, beg, len);
    }
    return rb_ary_entry(ary, NUM2LONG(arg));
}

/*
 *  call-seq:
 *     ary.at(index)   ->   obj  or nil
 *
 *  Returns the element at +index+. A negative index counts from the end of
 *  +self+. Returns +nil+ if the index is out of range. See also
 *  Array#[].
 *
 *     a = [ "a", "b", "c", "d", "e" ]
 *     a.at(0)     #=> "a"
 *     a.at(-1)    #=> "e"
 */

VALUE
rb_ary_at(VALUE ary, VALUE pos)
{
    return rb_ary_entry(ary, NUM2LONG(pos));
}

/*
 *  call-seq:
 *     ary.first     ->   obj or nil
 *     ary.first(n)  ->   new_ary
 *
 *  Returns the first element, or the first +n+ elements, of the array.
 *  If the array is empty, the first form returns +nil+, and the
 *  second form returns an empty array. See also Array#last for
 *  the opposite effect.
 *
 *     a = [ "q", "r", "s", "t" ]
 *     a.first     #=> "q"
 *     a.first(2)  #=> ["q", "r"]
 */

static VALUE
rb_ary_first(int argc, VALUE *argv, VALUE ary)
{
    if (argc == 0) {
	if (RARRAY_LEN(ary) == 0) return Qnil;
	return RARRAY_AREF(ary, 0);
    }
    else {
	return ary_take_first_or_last(argc, argv, ary, ARY_TAKE_FIRST);
    }
}

/*
 *  call-seq:
 *     ary.last     ->  obj or nil
 *     ary.last(n)  ->  new_ary
 *
 *  Returns the last element(s) of +self+. If the array is empty,
 *  the first form returns +nil+.
 *
 *  See also Array#first for the opposite effect.
 *
 *     a = [ "w", "x", "y", "z" ]
 *     a.last     #=> "z"
 *     a.last(2)  #=> ["y", "z"]
 */

VALUE
rb_ary_last(int argc, const VALUE *argv, VALUE ary)
{
    if (argc == 0) {
	long len = RARRAY_LEN(ary);
	if (len == 0) return Qnil;
	return RARRAY_AREF(ary, len-1);
    }
    else {
	return ary_take_first_or_last(argc, argv, ary, ARY_TAKE_LAST);
    }
}

/*
 *  call-seq:
 *     ary.fetch(index)                    -> obj
 *     ary.fetch(index, default)           -> obj
 *     ary.fetch(index) { |index| block }  -> obj
 *
 *  Tries to return the element at position +index+, but throws an IndexError
 *  exception if the referenced +index+ lies outside of the array bounds.  This
 *  error can be prevented by supplying a second argument, which will act as a
 *  +default+ value.
 *
 *  Alternatively, if a block is given it will only be executed when an
 *  invalid +index+ is referenced.
 *
 *  Negative values of +index+ count from the end of the array.
 *
 *     a = [ 11, 22, 33, 44 ]
 *     a.fetch(1)               #=> 22
 *     a.fetch(-1)              #=> 44
 *     a.fetch(4, 'cat')        #=> "cat"
 *     a.fetch(100) { |i| puts "#{i} is out of bounds" }
 *                              #=> "100 is out of bounds"
 */

static VALUE
rb_ary_fetch(int argc, VALUE *argv, VALUE ary)
{
    VALUE pos, ifnone;
    long block_given;
    long idx;

    rb_scan_args(argc, argv, "11", &pos, &ifnone);
    block_given = rb_block_given_p();
    if (block_given && argc == 2) {
	rb_warn("block supersedes default value argument");
    }
    idx = NUM2LONG(pos);

    if (idx < 0) {
	idx +=  RARRAY_LEN(ary);
    }
    if (idx < 0 || RARRAY_LEN(ary) <= idx) {
	if (block_given) return rb_yield(pos);
	if (argc == 1) {
	    rb_raise(rb_eIndexError, "index %ld outside of array bounds: %ld...%ld",
			idx - (idx < 0 ? RARRAY_LEN(ary) : 0), -RARRAY_LEN(ary), RARRAY_LEN(ary));
	}
	return ifnone;
    }
    return RARRAY_AREF(ary, idx);
}

/*
 *  call-seq:
 *     ary.find_index(obj)             ->  int or nil
 *     ary.find_index { |item| block } ->  int or nil
 *     ary.find_index                  ->  Enumerator
 *     ary.index(obj)             ->  int or nil
 *     ary.index { |item| block } ->  int or nil
 *     ary.index                  ->  Enumerator
 *
 *  Returns the _index_ of the first object in +ary+ such that the object is
 *  <code>==</code> to +obj+.
 *
 *  If a block is given instead of an argument, returns the _index_ of the
 *  first object for which the block returns +true+.  Returns +nil+ if no
 *  match is found.
 *
 *  See also Array#rindex.
 *
 *  An Enumerator is returned if neither a block nor argument is given.
 *
 *     a = [ "a", "b", "c" ]
 *     a.index("b")              #=> 1
 *     a.index("z")              #=> nil
 *     a.index { |x| x == "b" }  #=> 1
 */

static VALUE
rb_ary_index(int argc, VALUE *argv, VALUE ary)
{
    VALUE val;
    long i;

    if (argc == 0) {
	RETURN_ENUMERATOR(ary, 0, 0);
	for (i=0; i<RARRAY_LEN(ary); i++) {
	    if (RTEST(rb_yield(RARRAY_AREF(ary, i)))) {
		return LONG2NUM(i);
	    }
	}
	return Qnil;
    }
    rb_check_arity(argc, 0, 1);
    val = argv[0];
    if (rb_block_given_p())
	rb_warn("given block not used");
    for (i=0; i<RARRAY_LEN(ary); i++) {
	VALUE e = RARRAY_AREF(ary, i);
	if (rb_equal(e, val)) {
	    return LONG2NUM(i);
	}
    }
    return Qnil;
}

/*
 *  call-seq:
 *     ary.rindex(obj)             ->  int or nil
 *     ary.rindex { |item| block } ->  int or nil
 *     ary.rindex                  ->  Enumerator
 *
 *  Returns the _index_ of the last object in +self+ <code>==</code> to +obj+.
 *
 *  If a block is given instead of an argument, returns the _index_ of the
 *  first object for which the block returns +true+, starting from the last
 *  object.
 *
 *  Returns +nil+ if no match is found.
 *
 *  See also Array#index.
 *
 *  If neither block nor argument is given, an Enumerator is returned instead.
 *
 *     a = [ "a", "b", "b", "b", "c" ]
 *     a.rindex("b")             #=> 3
 *     a.rindex("z")             #=> nil
 *     a.rindex { |x| x == "b" } #=> 3
 */

static VALUE
rb_ary_rindex(int argc, VALUE *argv, VALUE ary)
{
    VALUE val;
    long i = RARRAY_LEN(ary), len;

    if (argc == 0) {
	RETURN_ENUMERATOR(ary, 0, 0);
	while (i--) {
	    if (RTEST(rb_yield(RARRAY_AREF(ary, i))))
		return LONG2NUM(i);
	    if (i > (len = RARRAY_LEN(ary))) {
		i = len;
	    }
	}
	return Qnil;
    }
    rb_check_arity(argc, 0, 1);
    val = argv[0];
    if (rb_block_given_p())
	rb_warn("given block not used");
    while (i--) {
	VALUE e = RARRAY_AREF(ary, i);
	if (rb_equal(e, val)) {
	    return LONG2NUM(i);
	}
    }
    return Qnil;
}

VALUE
rb_ary_to_ary(VALUE obj)
{
    VALUE tmp = rb_check_array_type(obj);

    if (!NIL_P(tmp)) return tmp;
    return rb_ary_new3(1, obj);
}

static void
rb_ary_splice(VALUE ary, long beg, long len, const VALUE *rptr, long rlen)
{
    long olen;
    long rofs;

    if (len < 0) rb_raise(rb_eIndexError, "negative length (%ld)", len);
    olen = RARRAY_LEN(ary);
    if (beg < 0) {
	beg += olen;
	if (beg < 0) {
	    rb_raise(rb_eIndexError, "index %ld too small for array; minimum: %ld",
		     beg - olen, -olen);
	}
    }
    if (olen < len || olen < beg + len) {
	len = olen - beg;
    }

    {
	const VALUE *optr = RARRAY_CONST_PTR(ary);
	rofs = (rptr >= optr && rptr < optr + olen) ? rptr - optr : -1;
    }

    if (beg >= olen) {
	VALUE target_ary;
	if (beg > ARY_MAX_SIZE - rlen) {
	    rb_raise(rb_eIndexError, "index %ld too big", beg);
	}
	target_ary = ary_ensure_room_for_push(ary, rlen-len); /* len is 0 or negative */
	len = beg + rlen;
	ary_mem_clear(ary, olen, beg - olen);
	if (rlen > 0) {
	    if (rofs != -1) rptr = RARRAY_CONST_PTR(ary) + rofs;
	    ary_memcpy0(ary, beg, rlen, rptr, target_ary);
	}
	ARY_SET_LEN(ary, len);
    }
    else {
	long alen;

	if (olen - len > ARY_MAX_SIZE - rlen) {
	    rb_raise(rb_eIndexError, "index %ld too big", olen + rlen - len);
	}
	rb_ary_modify(ary);
	alen = olen + rlen - len;
	if (alen >= ARY_CAPA(ary)) {
	    ary_double_capa(ary, alen);
	}

	if (len != rlen) {
	    RARRAY_PTR_USE(ary, ptr,
			   MEMMOVE(ptr + beg + rlen, ptr + beg + len,
				   VALUE, olen - (beg + len)));
	    ARY_SET_LEN(ary, alen);
	}
	if (rlen > 0) {
	    if (rofs != -1) rptr = RARRAY_CONST_PTR(ary) + rofs;
	    MEMMOVE(RARRAY_PTR(ary) + beg, rptr, VALUE, rlen);
	}
    }
}

void
rb_ary_set_len(VALUE ary, long len)
{
    long capa;

    rb_ary_modify_check(ary);
    if (ARY_SHARED_P(ary)) {
	rb_raise(rb_eRuntimeError, "can't set length of shared ");
    }
    if (len > (capa = (long)ARY_CAPA(ary))) {
	rb_bug("probable buffer overflow: %ld for %ld", len, capa);
    }
    ARY_SET_LEN(ary, len);
}

/*!
 * expands or shrinks \a ary to \a len elements.
 * expanded region will be filled with Qnil.
 * \param ary  an array
 * \param len  new size
 * \return     \a ary
 * \post       the size of \a ary is \a len.
 */
VALUE
rb_ary_resize(VALUE ary, long len)
{
    long olen;

    rb_ary_modify(ary);
    olen = RARRAY_LEN(ary);
    if (len == olen) return ary;
    if (len > ARY_MAX_SIZE) {
	rb_raise(rb_eIndexError, "index %ld too big", len);
    }
    if (len > olen) {
	if (len >= ARY_CAPA(ary)) {
	    ary_double_capa(ary, len);
	}
	ary_mem_clear(ary, olen, len - olen);
	ARY_SET_LEN(ary, len);
    }
    else if (ARY_EMBED_P(ary)) {
        ARY_SET_EMBED_LEN(ary, len);
    }
    else if (len <= RARRAY_EMBED_LEN_MAX) {
	VALUE tmp[RARRAY_EMBED_LEN_MAX];
	MEMCPY(tmp, ARY_HEAP_PTR(ary), VALUE, len);
	ary_discard(ary);
	MEMCPY((VALUE *)ARY_EMBED_PTR(ary), tmp, VALUE, len); /* WB: no new reference */
        ARY_SET_EMBED_LEN(ary, len);
    }
    else {
	if (olen > len + ARY_DEFAULT_SIZE) {
	    SIZED_REALLOC_N(RARRAY(ary)->as.heap.ptr, VALUE, len, RARRAY(ary)->as.heap.aux.capa);
	    ARY_SET_CAPA(ary, len);
	}
	ARY_SET_HEAP_LEN(ary, len);
    }
    return ary;
}

/*
 *  call-seq:
 *     ary[index]         = obj                      ->  obj
 *     ary[start, length] = obj or other_ary or nil  ->  obj or other_ary or nil
 *     ary[range]         = obj or other_ary or nil  ->  obj or other_ary or nil
 *
 *  Element Assignment --- Sets the element at +index+, or replaces a subarray
 *  from the +start+ index for +length+ elements, or replaces a subarray
 *  specified by the +range+ of indices.
 *
 *  If indices are greater than the current capacity of the array, the array
 *  grows automatically.  Elements are inserted into the array at +start+ if
 *  +length+ is zero.
 *
 *  Negative indices will count backward from the end of the array.  For
 *  +start+ and +range+ cases the starting index is just before an element.
 *
 *  An IndexError is raised if a negative index points past the beginning of
 *  the array.
 *
 *  See also Array#push, and Array#unshift.
 *
 *     a = Array.new
 *     a[4] = "4";                 #=> [nil, nil, nil, nil, "4"]
 *     a[0, 3] = [ 'a', 'b', 'c' ] #=> ["a", "b", "c", nil, "4"]
 *     a[1..2] = [ 1, 2 ]          #=> ["a", 1, 2, nil, "4"]
 *     a[0, 2] = "?"               #=> ["?", 2, nil, "4"]
 *     a[0..2] = "A"               #=> ["A", "4"]
 *     a[-1]   = "Z"               #=> ["A", "Z"]
 *     a[1..-1] = nil              #=> ["A", nil]
 *     a[1..-1] = []               #=> ["A"]
 *     a[0, 0] = [ 1, 2 ]          #=> [1, 2, "A"]
 *     a[3, 0] = "B"               #=> [1, 2, "A", "B"]
 */

static VALUE
rb_ary_aset(int argc, VALUE *argv, VALUE ary)
{
    long offset, beg, len;
    VALUE rpl;

    if (argc == 3) {
	rb_ary_modify_check(ary);
	beg = NUM2LONG(argv[0]);
	len = NUM2LONG(argv[1]);
	goto range;
    }
    rb_check_arity(argc, 2, 2);
    rb_ary_modify_check(ary);
    if (FIXNUM_P(argv[0])) {
	offset = FIX2LONG(argv[0]);
	goto fixnum;
    }
    if (rb_range_beg_len(argv[0], &beg, &len, RARRAY_LEN(ary), 1)) {
	/* check if idx is Range */
      range:
	rpl = rb_ary_to_ary(argv[argc-1]);
	rb_ary_splice(ary, beg, len, RARRAY_CONST_PTR(rpl), RARRAY_LEN(rpl));
	RB_GC_GUARD(rpl);
	return argv[argc-1];
    }

    offset = NUM2LONG(argv[0]);
fixnum:
    rb_ary_store(ary, offset, argv[1]);
    return argv[1];
}

/*
 *  call-seq:
 *     ary.insert(index, obj...)  -> ary
 *
 *  Inserts the given values before the element with the given +index+.
 *
 *  Negative indices count backwards from the end of the array, where +-1+ is
 *  the last element. If a negative index is used, the given values will be
 *  inserted after that element, so using an index of +-1+ will insert the
 *  values at the end of the array.
 *
 *     a = %w{ a b c d }
 *     a.insert(2, 99)         #=> ["a", "b", 99, "c", "d"]
 *     a.insert(-2, 1, 2, 3)   #=> ["a", "b", 99, "c", 1, 2, 3, "d"]
 */

static VALUE
rb_ary_insert(int argc, VALUE *argv, VALUE ary)
{
    long pos;

    rb_check_arity(argc, 1, UNLIMITED_ARGUMENTS);
    rb_ary_modify_check(ary);
    pos = NUM2LONG(argv[0]);
    if (argc == 1) return ary;
    if (pos == -1) {
	pos = RARRAY_LEN(ary);
    }
    else if (pos < 0) {
	long minpos = -RARRAY_LEN(ary) - 1;
	if (pos < minpos) {
	    rb_raise(rb_eIndexError, "index %ld too small for array; minimum: %ld",
		     pos, minpos);
	}
	pos++;
    }
    rb_ary_splice(ary, pos, 0, argv + 1, argc - 1);
    return ary;
}

static VALUE
rb_ary_length(VALUE ary);

static VALUE
ary_enum_length(VALUE ary, VALUE args, VALUE eobj)
{
    return rb_ary_length(ary);
}

/*
 *  call-seq:
 *     ary.each { |item| block }  -> ary
 *     ary.each                   -> Enumerator
 *
 *  Calls the given block once for each element in +self+, passing that element
 *  as a parameter.  Returns the array itself.
 *
 *  If no block is given, an Enumerator is returned.
 *
 *     a = [ "a", "b", "c" ]
 *     a.each {|x| print x, " -- " }
 *
 *  produces:
 *
 *     a -- b -- c --
 */

VALUE
rb_ary_each(VALUE ary)
{
    long i;

    RETURN_SIZED_ENUMERATOR(ary, 0, 0, ary_enum_length);
    for (i=0; i<RARRAY_LEN(ary); i++) {
	rb_yield(RARRAY_AREF(ary, i));
    }
    return ary;
}

/*
 *  call-seq:
 *     ary.each_index { |index| block }  -> ary
 *     ary.each_index                    -> Enumerator
 *
 *  Same as Array#each, but passes the +index+ of the element instead of the
 *  element itself.
 *
 *  An Enumerator is returned if no block is given.
 *
 *     a = [ "a", "b", "c" ]
 *     a.each_index {|x| print x, " -- " }
 *
 *  produces:
 *
 *     0 -- 1 -- 2 --
 */

static VALUE
rb_ary_each_index(VALUE ary)
{
    long i;
    RETURN_SIZED_ENUMERATOR(ary, 0, 0, ary_enum_length);

    for (i=0; i<RARRAY_LEN(ary); i++) {
	rb_yield(LONG2NUM(i));
    }
    return ary;
}

/*
 *  call-seq:
 *     ary.reverse_each { |item| block }  -> ary
 *     ary.reverse_each                   -> Enumerator
 *
 *  Same as Array#each, but traverses +self+ in reverse order.
 *
 *     a = [ "a", "b", "c" ]
 *     a.reverse_each {|x| print x, " " }
 *
 *  produces:
 *
 *     c b a
 */

static VALUE
rb_ary_reverse_each(VALUE ary)
{
    long len;

    RETURN_SIZED_ENUMERATOR(ary, 0, 0, ary_enum_length);
    len = RARRAY_LEN(ary);
    while (len--) {
	long nlen;
	rb_yield(RARRAY_AREF(ary, len));
	nlen = RARRAY_LEN(ary);
	if (nlen < len) {
	    len = nlen;
	}
    }
    return ary;
}

/*
 *  call-seq:
 *     ary.length -> int
 *
 *  Returns the number of elements in +self+. May be zero.
 *
 *     [ 1, 2, 3, 4, 5 ].length   #=> 5
 *     [].length                  #=> 0
 */

static VALUE
rb_ary_length(VALUE ary)
{
    long len = RARRAY_LEN(ary);
    return LONG2NUM(len);
}

/*
 *  call-seq:
 *     ary.empty?   -> true or false
 *
 *  Returns +true+ if +self+ contains no elements.
 *
 *     [].empty?   #=> true
 */

static VALUE
rb_ary_empty_p(VALUE ary)
{
    if (RARRAY_LEN(ary) == 0)
	return Qtrue;
    return Qfalse;
}

VALUE
rb_ary_dup(VALUE ary)
{
    long len = RARRAY_LEN(ary);
    VALUE dup = rb_ary_new2(len);
    ary_memcpy(dup, 0, len, RARRAY_CONST_PTR(ary));
    ARY_SET_LEN(dup, len);
    return dup;
}

VALUE
rb_ary_resurrect(VALUE ary)
{
    return rb_ary_new4(RARRAY_LEN(ary), RARRAY_CONST_PTR(ary));
}

extern VALUE rb_output_fs;

static void ary_join_1(VALUE obj, VALUE ary, VALUE sep, long i, VALUE result, int *first);

static VALUE
recursive_join(VALUE obj, VALUE argp, int recur)
{
    VALUE *arg = (VALUE *)argp;
    VALUE ary = arg[0];
    VALUE sep = arg[1];
    VALUE result = arg[2];
    int *first = (int *)arg[3];

    if (recur) {
	rb_raise(rb_eArgError, "recursive array join");
    }
    else {
	ary_join_1(obj, ary, sep, 0, result, first);
    }
    return Qnil;
}

static void
ary_join_0(VALUE ary, VALUE sep, long max, VALUE result)
{
    long i;
    VALUE val;

    if (max > 0) rb_enc_copy(result, RARRAY_AREF(ary, 0));
    for (i=0; i<max; i++) {
	val = RARRAY_AREF(ary, i);
	if (i > 0 && !NIL_P(sep))
	    rb_str_buf_append(result, sep);
	rb_str_buf_append(result, val);
	if (OBJ_TAINTED(val)) OBJ_TAINT(result);
    }
}

static void
ary_join_1(VALUE obj, VALUE ary, VALUE sep, long i, VALUE result, int *first)
{
    VALUE val, tmp;

    for (; i<RARRAY_LEN(ary); i++) {
	if (i > 0 && !NIL_P(sep))
	    rb_str_buf_append(result, sep);

	val = RARRAY_AREF(ary, i);
	if (RB_TYPE_P(val, T_STRING)) {
	  str_join:
	    rb_str_buf_append(result, val);
	    *first = FALSE;
	}
	else if (RB_TYPE_P(val, T_ARRAY)) {
	    obj = val;
	  ary_join:
	    if (val == ary) {
		rb_raise(rb_eArgError, "recursive array join");
	    }
	    else {
		VALUE args[4];

		args[0] = val;
		args[1] = sep;
		args[2] = result;
		args[3] = (VALUE)first;
		rb_exec_recursive(recursive_join, obj, (VALUE)args);
	    }
	}
	else {
	    tmp = rb_check_string_type(val);
	    if (!NIL_P(tmp)) {
		val = tmp;
		goto str_join;
	    }
	    tmp = rb_check_convert_type_with_id(val, T_ARRAY, "Array", idTo_ary);
	    if (!NIL_P(tmp)) {
		obj = val;
		val = tmp;
		goto ary_join;
	    }
	    val = rb_obj_as_string(val);
	    if (*first) {
		rb_enc_copy(result, val);
		*first = FALSE;
	    }
	    goto str_join;
	}
    }
}

VALUE
rb_ary_join(VALUE ary, VALUE sep)
{
    long len = 1, i;
    int taint = FALSE;
    VALUE val, tmp, result;

    if (RARRAY_LEN(ary) == 0) return rb_usascii_str_new(0, 0);
    if (OBJ_TAINTED(ary)) taint = TRUE;

    if (!NIL_P(sep)) {
	StringValue(sep);
	len += RSTRING_LEN(sep) * (RARRAY_LEN(ary) - 1);
    }
    for (i=0; i<RARRAY_LEN(ary); i++) {
	val = RARRAY_AREF(ary, i);
	tmp = rb_check_string_type(val);

	if (NIL_P(tmp) || tmp != val) {
	    int first;
	    result = rb_str_buf_new(len + (RARRAY_LEN(ary)-i)*10);
	    rb_enc_associate(result, rb_usascii_encoding());
	    if (taint) OBJ_TAINT(result);
	    ary_join_0(ary, sep, i, result);
	    first = i == 0;
	    ary_join_1(ary, ary, sep, i, result, &first);
	    return result;
	}

	len += RSTRING_LEN(tmp);
    }

    result = rb_str_buf_new(len);
    if (taint) OBJ_TAINT(result);
    ary_join_0(ary, sep, RARRAY_LEN(ary), result);

    return result;
}

/*
 *  call-seq:
 *     ary.join(separator=$,)    -> str
 *
 *  Returns a string created by converting each element of the array to
 *  a string, separated by the given +separator+.
 *  If the +separator+ is +nil+, it uses current <code>$,</code>.
 *  If both the +separator+ and <code>$,</code> are +nil+,
 *  it uses an empty string.
 *
 *     [ "a", "b", "c" ].join        #=> "abc"
 *     [ "a", "b", "c" ].join("-")   #=> "a-b-c"
 *
 *  For nested arrays, join is applied recursively:
 *
 *     [ "a", [1, 2, [:x, :y]], "b" ].join("-")   #=> "a-1-2-x-y-b"
 */

static VALUE
rb_ary_join_m(int argc, VALUE *argv, VALUE ary)
{
    VALUE sep;

    rb_scan_args(argc, argv, "01", &sep);
    if (NIL_P(sep)) sep = rb_output_fs;

    return rb_ary_join(ary, sep);
}

static VALUE
inspect_ary(VALUE ary, VALUE dummy, int recur)
{
    int tainted = OBJ_TAINTED(ary);
    long i;
    VALUE s, str;

    if (recur) return rb_usascii_str_new_cstr("[...]");
    str = rb_str_buf_new2("[");
    for (i=0; i<RARRAY_LEN(ary); i++) {
	s = rb_inspect(RARRAY_AREF(ary, i));
	if (OBJ_TAINTED(s)) tainted = TRUE;
	if (i > 0) rb_str_buf_cat2(str, ", ");
	else rb_enc_copy(str, s);
	rb_str_buf_append(str, s);
    }
    rb_str_buf_cat2(str, "]");
    if (tainted) OBJ_TAINT(str);
    return str;
}

/*
 *  call-seq:
 *     ary.inspect  -> string
 *     ary.to_s     -> string
 *
 *  Creates a string representation of +self+.
 *
 *     [ "a", "b", "c" ].to_s     #=> "[\"a\", \"b\", \"c\"]"
 */

static VALUE
rb_ary_inspect(VALUE ary)
{
    if (RARRAY_LEN(ary) == 0) return rb_usascii_str_new2("[]");
    return rb_exec_recursive(inspect_ary, ary, 0);
}

VALUE
rb_ary_to_s(VALUE ary)
{
    return rb_ary_inspect(ary);
}

/*
 *  call-seq:
 *     ary.to_a     -> ary
 *
 *  Returns +self+.
 *
 *  If called on a subclass of Array, converts the receiver to an Array object.
 */

static VALUE
rb_ary_to_a(VALUE ary)
{
    if (rb_obj_class(ary) != rb_cArray) {
	VALUE dup = rb_ary_new2(RARRAY_LEN(ary));
	rb_ary_replace(dup, ary);
	return dup;
    }
    return ary;
}

/*
 *  call-seq:
 *     ary.to_h     -> hash
 *
 *  Returns the result of interpreting <i>ary</i> as an array of
 *  <tt>[key, value]</tt> pairs.
 *
 *     [[:foo, :bar], [1, 2]].to_h
 *       # => {:foo => :bar, 1 => 2}
 */

static VALUE
rb_ary_to_h(VALUE ary)
{
    long i;
    VALUE hash = rb_hash_new();
    for (i=0; i<RARRAY_LEN(ary); i++) {
	const VALUE elt = rb_ary_elt(ary, i);
	const VALUE key_value_pair = rb_check_array_type(elt);
	if (NIL_P(key_value_pair)) {
	    rb_raise(rb_eTypeError, "wrong element type %"PRIsVALUE" at %ld (expected array)",
		     rb_obj_class(elt), i);
	}
	if (RARRAY_LEN(key_value_pair) != 2) {
	    rb_raise(rb_eArgError, "wrong array length at %ld (expected 2, was %ld)",
		i, RARRAY_LEN(key_value_pair));
	}
	rb_hash_aset(hash, RARRAY_AREF(key_value_pair, 0), RARRAY_AREF(key_value_pair, 1));
    }
    return hash;
}

/*
 *  call-seq:
 *     ary.to_ary -> ary
 *
 *  Returns +self+.
 */

static VALUE
rb_ary_to_ary_m(VALUE ary)
{
    return ary;
}

static void
ary_reverse(VALUE *p1, VALUE *p2)
{
    while (p1 < p2) {
	VALUE tmp = *p1;
	*p1++ = *p2;
	*p2-- = tmp;
    }
}

VALUE
rb_ary_reverse(VALUE ary)
{
    VALUE *p2;
    long len = RARRAY_LEN(ary);

    rb_ary_modify(ary);
    if (len > 1) {
	RARRAY_PTR_USE(ary, p1, {
	    p2 = p1 + len - 1;	/* points last item */
	    ary_reverse(p1, p2);
	}); /* WB: no new reference */
    }
    return ary;
}

/*
 *  call-seq:
 *     ary.reverse!   -> ary
 *
 *  Reverses +self+ in place.
 *
 *     a = [ "a", "b", "c" ]
 *     a.reverse!       #=> ["c", "b", "a"]
 *     a                #=> ["c", "b", "a"]
 */

static VALUE
rb_ary_reverse_bang(VALUE ary)
{
    return rb_ary_reverse(ary);
}

/*
 *  call-seq:
 *     ary.reverse    -> new_ary
 *
 *  Returns a new array containing +self+'s elements in reverse order.
 *
 *     [ "a", "b", "c" ].reverse   #=> ["c", "b", "a"]
 *     [ 1 ].reverse               #=> [1]
 */

static VALUE
rb_ary_reverse_m(VALUE ary)
{
    long len = RARRAY_LEN(ary);
    VALUE dup = rb_ary_new2(len);

    if (len > 0) {
	const VALUE *p1 = RARRAY_CONST_PTR(ary);
	VALUE *p2 = (VALUE *)RARRAY_CONST_PTR(dup) + len - 1;
	do *p2-- = *p1++; while (--len > 0);
    }
    ARY_SET_LEN(dup, RARRAY_LEN(ary));
    return dup;
}

static inline long
rotate_count(long cnt, long len)
{
    return (cnt < 0) ? (len - (~cnt % len) - 1) : (cnt % len);
}

VALUE
rb_ary_rotate(VALUE ary, long cnt)
{
    rb_ary_modify(ary);

    if (cnt != 0) {
	VALUE *ptr = RARRAY_PTR(ary);
	long len = RARRAY_LEN(ary);

	if (len > 0 && (cnt = rotate_count(cnt, len)) > 0) {
	    --len;
	    if (cnt < len) ary_reverse(ptr + cnt, ptr + len);
	    if (--cnt > 0) ary_reverse(ptr, ptr + cnt);
	    if (len > 0) ary_reverse(ptr, ptr + len);
	    return ary;
	}
    }

    return Qnil;
}

/*
 *  call-seq:
 *     ary.rotate!(count=1)   -> ary
 *
 *  Rotates +self+ in place so that the element at +count+ comes first, and
 *  returns +self+.
 *
 *  If +count+ is negative then it rotates in the opposite direction, starting
 *  from the end of the array where +-1+ is the last element.
 *
 *     a = [ "a", "b", "c", "d" ]
 *     a.rotate!        #=> ["b", "c", "d", "a"]
 *     a                #=> ["b", "c", "d", "a"]
 *     a.rotate!(2)     #=> ["d", "a", "b", "c"]
 *     a.rotate!(-3)    #=> ["a", "b", "c", "d"]
 */

static VALUE
rb_ary_rotate_bang(int argc, VALUE *argv, VALUE ary)
{
    long n = 1;

    switch (argc) {
      case 1: n = NUM2LONG(argv[0]);
      case 0: break;
      default: rb_scan_args(argc, argv, "01", NULL);
    }
    rb_ary_rotate(ary, n);
    return ary;
}

/*
 *  call-seq:
 *     ary.rotate(count=1)    -> new_ary
 *
 *  Returns a new array by rotating +self+ so that the element at +count+ is
 *  the first element of the new array.
 *
 *  If +count+ is negative then it rotates in the opposite direction, starting
 *  from the end of +self+ where +-1+ is the last element.
 *
 *     a = [ "a", "b", "c", "d" ]
 *     a.rotate         #=> ["b", "c", "d", "a"]
 *     a                #=> ["a", "b", "c", "d"]
 *     a.rotate(2)      #=> ["c", "d", "a", "b"]
 *     a.rotate(-3)     #=> ["b", "c", "d", "a"]
 */

static VALUE
rb_ary_rotate_m(int argc, VALUE *argv, VALUE ary)
{
    VALUE rotated;
    const VALUE *ptr;
    long len, cnt = 1;

    switch (argc) {
      case 1: cnt = NUM2LONG(argv[0]);
      case 0: break;
      default: rb_scan_args(argc, argv, "01", NULL);
    }

    len = RARRAY_LEN(ary);
    rotated = rb_ary_new2(len);
    if (len > 0) {
	cnt = rotate_count(cnt, len);
	ptr = RARRAY_CONST_PTR(ary);
	len -= cnt;
	ary_memcpy(rotated, 0, len, ptr + cnt);
	ary_memcpy(rotated, len, cnt, ptr);
    }
    ARY_SET_LEN(rotated, RARRAY_LEN(ary));
    return rotated;
}

struct ary_sort_data {
    VALUE ary;
    struct cmp_opt_data cmp_opt;
};

static VALUE
sort_reentered(VALUE ary)
{
    if (RBASIC(ary)->klass) {
	rb_raise(rb_eRuntimeError, "sort reentered");
    }
    return Qnil;
}

static int
sort_1(const void *ap, const void *bp, void *dummy)
{
    struct ary_sort_data *data = dummy;
    VALUE retval = sort_reentered(data->ary);
    VALUE a = *(const VALUE *)ap, b = *(const VALUE *)bp;
    VALUE args[2];
    int n;

    args[0] = a;
    args[1] = b;
    retval = rb_yield_values2(2, args);
    n = rb_cmpint(retval, a, b);
    sort_reentered(data->ary);
    return n;
}

static int
sort_2(const void *ap, const void *bp, void *dummy)
{
    struct ary_sort_data *data = dummy;
    VALUE retval = sort_reentered(data->ary);
    VALUE a = *(const VALUE *)ap, b = *(const VALUE *)bp;
    int n;

    if (FIXNUM_P(a) && FIXNUM_P(b) && CMP_OPTIMIZABLE(data->cmp_opt, Fixnum)) {
	if ((long)a > (long)b) return 1;
	if ((long)a < (long)b) return -1;
	return 0;
    }
    if (STRING_P(a) && STRING_P(b) && CMP_OPTIMIZABLE(data->cmp_opt, String)) {
	return rb_str_cmp(a, b);
    }
    if (RB_FLOAT_TYPE_P(a) && CMP_OPTIMIZABLE(data->cmp_opt, Float)) {
	return rb_float_cmp(a, b);
    }

    retval = rb_funcallv(a, id_cmp, 1, &b);
    n = rb_cmpint(retval, a, b);
    sort_reentered(data->ary);

    return n;
}

/*
 *  call-seq:
 *     ary.sort!                   -> ary
 *     ary.sort! { |a, b| block }  -> ary
 *
 *  Sorts +self+ in place.
 *
 *  Comparisons for the sort will be done using the <code><=></code> operator
 *  or using an optional code block.
 *
 *  The block must implement a comparison between +a+ and +b+ and return
 *  an integer less than 0 when +b+ follows +a+, +0+ when +a+ and +b+
 *  are equivalent, or an integer greater than 0 when +a+ follows +b+.
 *
 *  The result is not guaranteed to be stable.  When the comparison of two
 *  elements returns +0+, the order of the elements is unpredictable.
 *
 *     ary = [ "d", "a", "e", "c", "b" ]
 *     ary.sort!                     #=> ["a", "b", "c", "d", "e"]
 *     ary.sort! { |a, b| b <=> a }  #=> ["e", "d", "c", "b", "a"]
 *
 *  See also Enumerable#sort_by.
 */

VALUE
rb_ary_sort_bang(VALUE ary)
{
    rb_ary_modify(ary);
    assert(!ARY_SHARED_P(ary));
    if (RARRAY_LEN(ary) > 1) {
	VALUE tmp = ary_make_substitution(ary); /* only ary refers tmp */
	struct ary_sort_data data;
	long len = RARRAY_LEN(ary);

	RBASIC_CLEAR_CLASS(tmp);
	data.ary = tmp;
	data.cmp_opt.opt_methods = 0;
	data.cmp_opt.opt_inited = 0;
	RARRAY_PTR_USE(tmp, ptr, {
	    ruby_qsort(ptr, len, sizeof(VALUE),
		       rb_block_given_p()?sort_1:sort_2, &data);
	}); /* WB: no new reference */
	rb_ary_modify(ary);
        if (ARY_EMBED_P(tmp)) {
            if (ARY_SHARED_P(ary)) { /* ary might be destructively operated in the given block */
                rb_ary_unshare(ary);
		FL_SET_EMBED(ary);
            }
	    ary_memcpy(ary, 0, ARY_EMBED_LEN(tmp), ARY_EMBED_PTR(tmp));
            ARY_SET_LEN(ary, ARY_EMBED_LEN(tmp));
        }
        else {
            if (!ARY_EMBED_P(ary) && ARY_HEAP_PTR(ary) == ARY_HEAP_PTR(tmp)) {
                FL_UNSET_SHARED(ary);
                ARY_SET_CAPA(ary, RARRAY_LEN(tmp));
            }
            else {
                assert(!ARY_SHARED_P(tmp));
                if (ARY_EMBED_P(ary)) {
                    FL_UNSET_EMBED(ary);
                }
                else if (ARY_SHARED_P(ary)) {
                    /* ary might be destructively operated in the given block */
                    rb_ary_unshare(ary);
                }
                else {
		    ruby_sized_xfree((void *)ARY_HEAP_PTR(ary), ARY_HEAP_SIZE(ary));
                }
                ARY_SET_PTR(ary, RARRAY_CONST_PTR(tmp));
                ARY_SET_HEAP_LEN(ary, len);
                ARY_SET_CAPA(ary, RARRAY_LEN(tmp));
            }
            /* tmp was lost ownership for the ptr */
            FL_UNSET(tmp, FL_FREEZE);
            FL_SET_EMBED(tmp);
            ARY_SET_EMBED_LEN(tmp, 0);
            FL_SET(tmp, FL_FREEZE);
	}
        /* tmp will be GC'ed. */
        RBASIC_SET_CLASS_RAW(tmp, rb_cArray); /* rb_cArray must be marked */
    }
    return ary;
}

/*
 *  call-seq:
 *     ary.sort                   -> new_ary
 *     ary.sort { |a, b| block }  -> new_ary
 *
 *  Returns a new array created by sorting +self+.
 *
 *  Comparisons for the sort will be done using the <code><=></code> operator
 *  or using an optional code block.
 *
 *  The block must implement a comparison between +a+ and +b+ and return
 *  an integer less than 0 when +b+ follows +a+, +0+ when +a+ and +b+
 *  are equivalent, or an integer greater than 0 when +a+ follows +b+.
 *
 *  The result is not guaranteed to be stable.  When the comparison of two
 *  elements returns +0+, the order of the elements is unpredictable.
 *
 *     ary = [ "d", "a", "e", "c", "b" ]
 *     ary.sort                     #=> ["a", "b", "c", "d", "e"]
 *     ary.sort { |a, b| b <=> a }  #=> ["e", "d", "c", "b", "a"]
 *
 *  See also Enumerable#sort_by.
 */

VALUE
rb_ary_sort(VALUE ary)
{
    ary = rb_ary_dup(ary);
    rb_ary_sort_bang(ary);
    return ary;
}

static VALUE rb_ary_bsearch_index(VALUE ary);

/*
 *  call-seq:
 *     ary.bsearch {|x| block }  -> elem
 *
 *  By using binary search, finds a value from this array which meets
 *  the given condition in O(log n) where n is the size of the array.
 *
 *  You can use this method in two use cases: a find-minimum mode and
 *  a find-any mode.  In either case, the elements of the array must be
 *  monotone (or sorted) with respect to the block.
 *
 *  In find-minimum mode (this is a good choice for typical use case),
 *  the block must return true or false, and there must be an index i
 *  (0 <= i <= ary.size) so that:
 *
 *  - the block returns false for any element whose index is less than
 *    i, and
 *  - the block returns true for any element whose index is greater
 *    than or equal to i.
 *
 *  This method returns the i-th element.  If i is equal to ary.size,
 *  it returns nil.
 *
 *     ary = [0, 4, 7, 10, 12]
 *     ary.bsearch {|x| x >=   4 } #=> 4
 *     ary.bsearch {|x| x >=   6 } #=> 7
 *     ary.bsearch {|x| x >=  -1 } #=> 0
 *     ary.bsearch {|x| x >= 100 } #=> nil
 *
 *  In find-any mode (this behaves like libc's bsearch(3)), the block
 *  must return a number, and there must be two indices i and j
 *  (0 <= i <= j <= ary.size) so that:
 *
 *  - the block returns a positive number for ary[k] if 0 <= k < i,
 *  - the block returns zero for ary[k] if i <= k < j, and
 *  - the block returns a negative number for ary[k] if
 *    j <= k < ary.size.
 *
 *  Under this condition, this method returns any element whose index
 *  is within i...j.  If i is equal to j (i.e., there is no element
 *  that satisfies the block), this method returns nil.
 *
 *     ary = [0, 4, 7, 10, 12]
 *     # try to find v such that 4 <= v < 8
 *     ary.bsearch {|x| 1 - x / 4 } #=> 4 or 7
 *     # try to find v such that 8 <= v < 10
 *     ary.bsearch {|x| 4 - x / 2 } #=> nil
 *
 *  You must not mix the two modes at a time; the block must always
 *  return either true/false, or always return a number.  It is
 *  undefined which value is actually picked up at each iteration.
 */

static VALUE
rb_ary_bsearch(VALUE ary)
{
    VALUE index_result = rb_ary_bsearch_index(ary);

    if (FIXNUM_P(index_result)) {
	return rb_ary_entry(ary, FIX2LONG(index_result));
    }
    return index_result;
}

/*
 *  call-seq:
 *     ary.bsearch_index {|x| block }  -> int or nil
 *
 *  By using binary search, finds an index of a value from this array which
 *  meets the given condition in O(log n) where n is the size of the array.
 *
 *  It supports two modes, depending on the nature of the block and they are
 *  exactly the same as in the case of #bsearch method with the only difference
 *  being that this method returns the index of the element instead of the
 *  element itself. For more details consult the documentation for #bsearch.
 */

static VALUE
rb_ary_bsearch_index(VALUE ary)
{
    long low = 0, high = RARRAY_LEN(ary), mid;
    int smaller = 0, satisfied = 0;
    VALUE v, val;

    RETURN_ENUMERATOR(ary, 0, 0);
    while (low < high) {
	mid = low + ((high - low) / 2);
	val = rb_ary_entry(ary, mid);
	v = rb_yield(val);
	if (FIXNUM_P(v)) {
	    if (v == INT2FIX(0)) return INT2FIX(mid);
	    smaller = (SIGNED_VALUE)v < 0; /* Fixnum preserves its sign-bit */
	}
	else if (v == Qtrue) {
	    satisfied = 1;
	    smaller = 1;
	}
	else if (v == Qfalse || v == Qnil) {
	    smaller = 0;
	}
	else if (rb_obj_is_kind_of(v, rb_cNumeric)) {
	    const VALUE zero = INT2FIX(0);
	    switch (rb_cmpint(rb_funcallv(v, id_cmp, 1, &zero), v, zero)) {
	      case 0: return INT2FIX(mid);
	      case 1: smaller = 1; break;
	      case -1: smaller = 0;
	    }
	}
	else {
	    rb_raise(rb_eTypeError, "wrong argument type %"PRIsVALUE
		     " (must be numeric, true, false or nil)",
		     rb_obj_class(v));
	}
	if (smaller) {
	    high = mid;
	}
	else {
	    low = mid + 1;
	}
    }
    if (!satisfied) return Qnil;
    return INT2FIX(low);
}


static VALUE
sort_by_i(RB_BLOCK_CALL_FUNC_ARGLIST(i, dummy))
{
    return rb_yield(i);
}

/*
 *  call-seq:
 *     ary.sort_by! { |obj| block }    -> ary
 *     ary.sort_by!                    -> Enumerator
 *
 *  Sorts +self+ in place using a set of keys generated by mapping the
 *  values in +self+ through the given block.
 *
 *  The result is not guaranteed to be stable.  When two keys are equal,
 *  the order of the corresponding elements is unpredictable.
 *
 *  If no block is given, an Enumerator is returned instead.
 *
 *  See also Enumerable#sort_by.
 */

static VALUE
rb_ary_sort_by_bang(VALUE ary)
{
    VALUE sorted;

    RETURN_SIZED_ENUMERATOR(ary, 0, 0, ary_enum_length);
    rb_ary_modify(ary);
    sorted = rb_block_call(ary, rb_intern("sort_by"), 0, 0, sort_by_i, 0);
    rb_ary_replace(ary, sorted);
    return ary;
}


/*
 *  call-seq:
 *     ary.collect { |item| block }  -> new_ary
 *     ary.map     { |item| block }  -> new_ary
 *     ary.collect                   -> Enumerator
 *     ary.map                       -> Enumerator
 *
 *  Invokes the given block once for each element of +self+.
 *
 *  Creates a new array containing the values returned by the block.
 *
 *  See also Enumerable#collect.
 *
 *  If no block is given, an Enumerator is returned instead.
 *
 *     a = [ "a", "b", "c", "d" ]
 *     a.collect { |x| x + "!" }         #=> ["a!", "b!", "c!", "d!"]
 *     a.map.with_index { |x, i| x * i } #=> ["", "b", "cc", "ddd"]
 *     a                                 #=> ["a", "b", "c", "d"]
 */

static VALUE
rb_ary_collect(VALUE ary)
{
    long i;
    VALUE collect;

    RETURN_SIZED_ENUMERATOR(ary, 0, 0, ary_enum_length);
    collect = rb_ary_new2(RARRAY_LEN(ary));
    for (i = 0; i < RARRAY_LEN(ary); i++) {
	rb_ary_push(collect, rb_yield(RARRAY_AREF(ary, i)));
    }
    return collect;
}


/*
 *  call-seq:
 *     ary.collect! {|item| block }   -> ary
 *     ary.map!     {|item| block }   -> ary
 *     ary.collect!                   -> Enumerator
 *     ary.map!                       -> Enumerator
 *
 *  Invokes the given block once for each element of +self+, replacing the
 *  element with the value returned by the block.
 *
 *  See also Enumerable#collect.
 *
 *  If no block is given, an Enumerator is returned instead.
 *
 *     a = [ "a", "b", "c", "d" ]
 *     a.map! {|x| x + "!" }
 *     a #=>  [ "a!", "b!", "c!", "d!" ]
 *     a.collect!.with_index {|x, i| x[0...i] }
 *     a #=>  ["", "b", "c!", "d!"]
 */

static VALUE
rb_ary_collect_bang(VALUE ary)
{
    long i;

    RETURN_SIZED_ENUMERATOR(ary, 0, 0, ary_enum_length);
    rb_ary_modify(ary);
    for (i = 0; i < RARRAY_LEN(ary); i++) {
	rb_ary_store(ary, i, rb_yield(RARRAY_AREF(ary, i)));
    }
    return ary;
}

VALUE
rb_get_values_at(VALUE obj, long olen, int argc, const VALUE *argv, VALUE (*func) (VALUE, long))
{
    VALUE result = rb_ary_new2(argc);
    long beg, len, i, j;

    for (i=0; i<argc; i++) {
	if (FIXNUM_P(argv[i])) {
	    rb_ary_push(result, (*func)(obj, FIX2LONG(argv[i])));
	    continue;
	}
	/* check if idx is Range */
	if (rb_range_beg_len(argv[i], &beg, &len, olen, 1)) {
	    long end = olen < beg+len ? olen : beg+len;
	    for (j = beg; j < end; j++) {
		rb_ary_push(result, (*func)(obj, j));
	    }
	    if (beg + len > j)
		rb_ary_resize(result, RARRAY_LEN(result) + (beg + len) - j);
	    continue;
	}
	rb_ary_push(result, (*func)(obj, NUM2LONG(argv[i])));
    }
    return result;
}

/*
 *  call-seq:
 *     ary.values_at(selector, ...)  -> new_ary
 *
 *  Returns an array containing the elements in +self+ corresponding to the
 *  given +selector+(s).
 *
 *  The selectors may be either integer indices or ranges.
 *
 *  See also Array#select.
 *
 *     a = %w{ a b c d e f }
 *     a.values_at(1, 3, 5)          # => ["b", "d", "f"]
 *     a.values_at(1, 3, 5, 7)       # => ["b", "d", "f", nil]
 *     a.values_at(-1, -2, -2, -7)   # => ["f", "e", "e", nil]
 *     a.values_at(4..6, 3...6)      # => ["e", "f", nil, "d", "e", "f"]
 */

static VALUE
rb_ary_values_at(int argc, VALUE *argv, VALUE ary)
{
    return rb_get_values_at(ary, RARRAY_LEN(ary), argc, argv, rb_ary_entry);
}


/*
 *  call-seq:
 *     ary.select { |item| block } -> new_ary
 *     ary.select                  -> Enumerator
 *
 *  Returns a new array containing all elements of +ary+
 *  for which the given +block+ returns a true value.
 *
 *  If no block is given, an Enumerator is returned instead.
 *
 *     [1,2,3,4,5].select { |num|  num.even?  }   #=> [2, 4]
 *
 *     a = %w{ a b c d e f }
 *     a.select { |v| v =~ /[aeiou]/ }  #=> ["a", "e"]
 *
 *  See also Enumerable#select.
 */

static VALUE
rb_ary_select(VALUE ary)
{
    VALUE result;
    long i;

    RETURN_SIZED_ENUMERATOR(ary, 0, 0, ary_enum_length);
    result = rb_ary_new2(RARRAY_LEN(ary));
    for (i = 0; i < RARRAY_LEN(ary); i++) {
	if (RTEST(rb_yield(RARRAY_AREF(ary, i)))) {
	    rb_ary_push(result, rb_ary_elt(ary, i));
	}
    }
    return result;
}

struct select_bang_arg {
    VALUE ary;
    long len[2];
};

static VALUE
select_bang_i(VALUE a)
{
    volatile struct select_bang_arg *arg = (void *)a;
    VALUE ary = arg->ary;
    long i1, i2;

    for (i1 = i2 = 0; i1 < RARRAY_LEN(ary); arg->len[0] = ++i1) {
	VALUE v = RARRAY_AREF(ary, i1);
	if (!RTEST(rb_yield(v))) continue;
	if (i1 != i2) {
	    rb_ary_store(ary, i2, v);
	}
	arg->len[1] = ++i2;
    }
    return (i1 == i2) ? Qnil : ary;
}

static VALUE
select_bang_ensure(VALUE a)
{
    volatile struct select_bang_arg *arg = (void *)a;
    VALUE ary = arg->ary;
    long len = RARRAY_LEN(ary);
    long i1 = arg->len[0], i2 = arg->len[1];

    if (i2 < len && i2 < i1) {
	long tail = 0;
	if (i1 < len) {
	    tail = len - i1;
	    RARRAY_PTR_USE(ary, ptr, {
		    MEMMOVE(ptr + i2, ptr + i1, VALUE, tail);
		});
	}
	ARY_SET_LEN(ary, i2 + tail);
    }
    return ary;
}

/*
 *  call-seq:
 *     ary.select!  {|item| block } -> ary or nil
 *     ary.select!                  -> Enumerator
 *
 *  Invokes the given block passing in successive elements from +self+,
 *  deleting elements for which the block returns a +false+ value.
 *
 *  The array may not be changed instantly every time the block is called.
 *
 *  If changes were made, it will return +self+, otherwise it returns +nil+.
 *
 *  See also Array#keep_if
 *
 *  If no block is given, an Enumerator is returned instead.
 *
 */

static VALUE
rb_ary_select_bang(VALUE ary)
{
    struct select_bang_arg args;

    RETURN_SIZED_ENUMERATOR(ary, 0, 0, ary_enum_length);
    rb_ary_modify(ary);

    args.ary = ary;
    args.len[0] = args.len[1] = 0;
    return rb_ensure(select_bang_i, (VALUE)&args, select_bang_ensure, (VALUE)&args);
}

/*
 *  call-seq:
 *     ary.keep_if { |item| block } -> ary
 *     ary.keep_if                  -> Enumerator
 *
 *  Deletes every element of +self+ for which the given block evaluates to
 *  +false+.
 *
 *  See also Array#select!
 *
 *  If no block is given, an Enumerator is returned instead.
 *
 *     a = %w{ a b c d e f }
 *     a.keep_if { |v| v =~ /[aeiou]/ }  #=> ["a", "e"]
 */

static VALUE
rb_ary_keep_if(VALUE ary)
{
    RETURN_SIZED_ENUMERATOR(ary, 0, 0, ary_enum_length);
    rb_ary_select_bang(ary);
    return ary;
}

static void
ary_resize_smaller(VALUE ary, long len)
{
    rb_ary_modify(ary);
    if (RARRAY_LEN(ary) > len) {
	ARY_SET_LEN(ary, len);
	if (len * 2 < ARY_CAPA(ary) &&
	    ARY_CAPA(ary) > ARY_DEFAULT_SIZE) {
	    ary_resize_capa(ary, len * 2);
	}
    }
}

/*
 *  call-seq:
 *     ary.delete(obj)            -> item or nil
 *     ary.delete(obj) { block }  -> item or result of block
 *
 *  Deletes all items from +self+ that are equal to +obj+.
 *
 *  Returns the last deleted item, or +nil+ if no matching item is found.
 *
 *  If the optional code block is given, the result of the block is returned if
 *  the item is not found.  (To remove +nil+ elements and get an informative
 *  return value, use Array#compact!)
 *
 *     a = [ "a", "b", "b", "b", "c" ]
 *     a.delete("b")                   #=> "b"
 *     a                               #=> ["a", "c"]
 *     a.delete("z")                   #=> nil
 *     a.delete("z") { "not found" }   #=> "not found"
 */

VALUE
rb_ary_delete(VALUE ary, VALUE item)
{
    VALUE v = item;
    long i1, i2;

    for (i1 = i2 = 0; i1 < RARRAY_LEN(ary); i1++) {
	VALUE e = RARRAY_AREF(ary, i1);

	if (rb_equal(e, item)) {
	    v = e;
	    continue;
	}
	if (i1 != i2) {
	    rb_ary_store(ary, i2, e);
	}
	i2++;
    }
    if (RARRAY_LEN(ary) == i2) {
	if (rb_block_given_p()) {
	    return rb_yield(item);
	}
	return Qnil;
    }

    ary_resize_smaller(ary, i2);

    return v;
}

void
rb_ary_delete_same(VALUE ary, VALUE item)
{
    long i1, i2;

    for (i1 = i2 = 0; i1 < RARRAY_LEN(ary); i1++) {
	VALUE e = RARRAY_AREF(ary, i1);

	if (e == item) {
	    continue;
	}
	if (i1 != i2) {
	    rb_ary_store(ary, i2, e);
	}
	i2++;
    }
    if (RARRAY_LEN(ary) == i2) {
	return;
    }

    ary_resize_smaller(ary, i2);
}

VALUE
rb_ary_delete_at(VALUE ary, long pos)
{
    long len = RARRAY_LEN(ary);
    VALUE del;

    if (pos >= len) return Qnil;
    if (pos < 0) {
	pos += len;
	if (pos < 0) return Qnil;
    }

    rb_ary_modify(ary);
    del = RARRAY_AREF(ary, pos);
    RARRAY_PTR_USE(ary, ptr, {
	MEMMOVE(ptr+pos, ptr+pos+1, VALUE, len-pos-1);
    });
    ARY_INCREASE_LEN(ary, -1);

    return del;
}

/*
 *  call-seq:
 *     ary.delete_at(index)  -> obj or nil
 *
 *  Deletes the element at the specified +index+, returning that element, or
 *  +nil+ if the +index+ is out of range.
 *
 *  See also Array#slice!
 *
 *     a = ["ant", "bat", "cat", "dog"]
 *     a.delete_at(2)    #=> "cat"
 *     a                 #=> ["ant", "bat", "dog"]
 *     a.delete_at(99)   #=> nil
 */

static VALUE
rb_ary_delete_at_m(VALUE ary, VALUE pos)
{
    return rb_ary_delete_at(ary, NUM2LONG(pos));
}

/*
 *  call-seq:
 *     ary.slice!(index)         -> obj or nil
 *     ary.slice!(start, length) -> new_ary or nil
 *     ary.slice!(range)         -> new_ary or nil
 *
 *  Deletes the element(s) given by an +index+ (optionally up to +length+
 *  elements) or by a +range+.
 *
 *  Returns the deleted object (or objects), or +nil+ if the +index+ is out of
 *  range.
 *
 *     a = [ "a", "b", "c" ]
 *     a.slice!(1)     #=> "b"
 *     a               #=> ["a", "c"]
 *     a.slice!(-1)    #=> "c"
 *     a               #=> ["a"]
 *     a.slice!(100)   #=> nil
 *     a               #=> ["a"]
 */

static VALUE
rb_ary_slice_bang(int argc, VALUE *argv, VALUE ary)
{
    VALUE arg1, arg2;
    long pos, len, orig_len;

    rb_ary_modify_check(ary);
    if (argc == 2) {
	pos = NUM2LONG(argv[0]);
	len = NUM2LONG(argv[1]);
      delete_pos_len:
	if (len < 0) return Qnil;
	orig_len = RARRAY_LEN(ary);
	if (pos < 0) {
	    pos += orig_len;
	    if (pos < 0) return Qnil;
	}
	else if (orig_len < pos) return Qnil;
	if (orig_len < pos + len) {
	    len = orig_len - pos;
	}
	if (len == 0) return rb_ary_new2(0);
	arg2 = rb_ary_new4(len, RARRAY_CONST_PTR(ary)+pos);
	RBASIC_SET_CLASS(arg2, rb_obj_class(ary));
	rb_ary_splice(ary, pos, len, 0, 0);
	return arg2;
    }

    if (argc != 1) {
	/* error report */
	rb_scan_args(argc, argv, "11", NULL, NULL);
    }
    arg1 = argv[0];

    if (!FIXNUM_P(arg1)) {
	switch (rb_range_beg_len(arg1, &pos, &len, RARRAY_LEN(ary), 0)) {
	  case Qtrue:
	    /* valid range */
	    goto delete_pos_len;
	  case Qnil:
	    /* invalid range */
	    return Qnil;
	  default:
	    /* not a range */
	    break;
	}
    }

    return rb_ary_delete_at(ary, NUM2LONG(arg1));
}

static VALUE
ary_reject(VALUE orig, VALUE result)
{
    long i;

    for (i = 0; i < RARRAY_LEN(orig); i++) {
	VALUE v = RARRAY_AREF(orig, i);
	if (!RTEST(rb_yield(v))) {
	    rb_ary_push(result, v);
	}
    }
    return result;
}

static VALUE
reject_bang_i(VALUE a)
{
    volatile struct select_bang_arg *arg = (void *)a;
    VALUE ary = arg->ary;
    long i1, i2;

    for (i1 = i2 = 0; i1 < RARRAY_LEN(ary); arg->len[0] = ++i1) {
	VALUE v = RARRAY_AREF(ary, i1);
	if (RTEST(rb_yield(v))) continue;
	if (i1 != i2) {
	    rb_ary_store(ary, i2, v);
	}
	arg->len[1] = ++i2;
    }
    return (i1 == i2) ? Qnil : ary;
}

static VALUE
ary_reject_bang(VALUE ary)
{
    struct select_bang_arg args;

    rb_ary_modify_check(ary);
    args.ary = ary;
    args.len[0] = args.len[1] = 0;
    return rb_ensure(reject_bang_i, (VALUE)&args, select_bang_ensure, (VALUE)&args);
}

/*
 *  call-seq:
 *     ary.reject! { |item| block }  -> ary or nil
 *     ary.reject!                   -> Enumerator
 *
 *  Deletes every element of +self+ for which the block evaluates to +true+,
 *  if no changes were made returns +nil+.
 *
 *  The array may not be changed instantly every time the block is called.
 *
 *  See also Enumerable#reject and Array#delete_if.
 *
 *  If no block is given, an Enumerator is returned instead.
 */

static VALUE
rb_ary_reject_bang(VALUE ary)
{
    RETURN_SIZED_ENUMERATOR(ary, 0, 0, ary_enum_length);
    return ary_reject_bang(ary);
}

/*
 *  call-seq:
 *     ary.reject  {|item| block }  -> new_ary
 *     ary.reject                   -> Enumerator
 *
 *  Returns a new array containing the items in +self+ for which the given
 *  block is not +true+. The ordering of non-rejected elements is maintained.
 *
 *  See also Array#delete_if
 *
 *  If no block is given, an Enumerator is returned instead.
 */

static VALUE
rb_ary_reject(VALUE ary)
{
    VALUE rejected_ary;

    RETURN_SIZED_ENUMERATOR(ary, 0, 0, ary_enum_length);
    rejected_ary = rb_ary_new();
    ary_reject(ary, rejected_ary);
    return rejected_ary;
}

/*
 *  call-seq:
 *     ary.delete_if { |item| block }  -> ary
 *     ary.delete_if                   -> Enumerator
 *
 *  Deletes every element of +self+ for which block evaluates to +true+.
 *
 *  The array is changed instantly every time the block is called, not after
 *  the iteration is over.
 *
 *  See also Array#reject!
 *
 *  If no block is given, an Enumerator is returned instead.
 *
 *     scores = [ 97, 42, 75 ]
 *     scores.delete_if {|score| score < 80 }   #=> [97]
 */

static VALUE
rb_ary_delete_if(VALUE ary)
{
    RETURN_SIZED_ENUMERATOR(ary, 0, 0, ary_enum_length);
    ary_reject_bang(ary);
    return ary;
}

static VALUE
take_i(RB_BLOCK_CALL_FUNC_ARGLIST(val, cbarg))
{
    VALUE *args = (VALUE *)cbarg;
    if (args[1]-- == 0) rb_iter_break();
    if (argc > 1) val = rb_ary_new4(argc, argv);
    rb_ary_push(args[0], val);
    return Qnil;
}

static VALUE
take_items(VALUE obj, long n)
{
    VALUE result = rb_check_array_type(obj);
    VALUE args[2];

    if (!NIL_P(result)) return rb_ary_subseq(result, 0, n);
    result = rb_ary_new2(n);
    args[0] = result; args[1] = (VALUE)n;
    if (rb_check_block_call(obj, idEach, 0, 0, take_i, (VALUE)args) == Qundef)
	rb_raise(rb_eTypeError, "wrong argument type %"PRIsVALUE" (must respond to :each)",
		 rb_obj_class(obj));
    return result;
}


/*
 *  call-seq:
 *     ary.zip(arg, ...)                  -> new_ary
 *     ary.zip(arg, ...) { |arr| block }  -> nil
 *
 *  Converts any arguments to arrays, then merges elements of +self+ with
 *  corresponding elements from each argument.
 *
 *  This generates a sequence of <code>ary.size</code> _n_-element arrays,
 *  where _n_ is one more than the count of arguments.
 *
 *  If the size of any argument is less than the size of the initial array,
 *  +nil+ values are supplied.
 *
 *  If a block is given, it is invoked for each output +array+, otherwise an
 *  array of arrays is returned.
 *
 *     a = [ 4, 5, 6 ]
 *     b = [ 7, 8, 9 ]
 *     [1, 2, 3].zip(a, b)   #=> [[1, 4, 7], [2, 5, 8], [3, 6, 9]]
 *     [1, 2].zip(a, b)      #=> [[1, 4, 7], [2, 5, 8]]
 *     a.zip([1, 2], [8])    #=> [[4, 1, 8], [5, 2, nil], [6, nil, nil]]
 */

static VALUE
rb_ary_zip(int argc, VALUE *argv, VALUE ary)
{
    int i, j;
    long len = RARRAY_LEN(ary);
    VALUE result = Qnil;

    for (i=0; i<argc; i++) {
	argv[i] = take_items(argv[i], len);
    }

    if (rb_block_given_p()) {
	int arity = rb_block_arity();

	if (arity > 1) {
	    VALUE work, *tmp;

	    tmp = ALLOCV_N(VALUE, work, argc+1);

	    for (i=0; i<RARRAY_LEN(ary); i++) {
		tmp[0] = RARRAY_AREF(ary, i);
		for (j=0; j<argc; j++) {
		    tmp[j+1] = rb_ary_elt(argv[j], i);
		}
		rb_yield_values2(argc+1, tmp);
	    }

	    if (work) ALLOCV_END(work);
	}
	else {
	    for (i=0; i<RARRAY_LEN(ary); i++) {
		VALUE tmp = rb_ary_new2(argc+1);

		rb_ary_push(tmp, RARRAY_AREF(ary, i));
		for (j=0; j<argc; j++) {
		    rb_ary_push(tmp, rb_ary_elt(argv[j], i));
		}
		rb_yield(tmp);
	    }
	}
    }
    else {
	result = rb_ary_new_capa(len);

	for (i=0; i<len; i++) {
	    VALUE tmp = rb_ary_new_capa(argc+1);

	    rb_ary_push(tmp, RARRAY_AREF(ary, i));
	    for (j=0; j<argc; j++) {
		rb_ary_push(tmp, rb_ary_elt(argv[j], i));
	    }
	    rb_ary_push(result, tmp);
	}
    }

    return result;
}

/*
 *  call-seq:
 *     ary.transpose -> new_ary
 *
 *  Assumes that +self+ is an array of arrays and transposes the rows and
 *  columns.
 *
 *     a = [[1,2], [3,4], [5,6]]
 *     a.transpose   #=> [[1, 3, 5], [2, 4, 6]]
 *
 *  If the length of the subarrays don't match, an IndexError is raised.
 */

static VALUE
rb_ary_transpose(VALUE ary)
{
    long elen = -1, alen, i, j;
    VALUE tmp, result = 0;

    alen = RARRAY_LEN(ary);
    if (alen == 0) return rb_ary_dup(ary);
    for (i=0; i<alen; i++) {
	tmp = to_ary(rb_ary_elt(ary, i));
	if (elen < 0) {		/* first element */
	    elen = RARRAY_LEN(tmp);
	    result = rb_ary_new2(elen);
	    for (j=0; j<elen; j++) {
		rb_ary_store(result, j, rb_ary_new2(alen));
	    }
	}
	else if (elen != RARRAY_LEN(tmp)) {
	    rb_raise(rb_eIndexError, "element size differs (%ld should be %ld)",
		     RARRAY_LEN(tmp), elen);
	}
	for (j=0; j<elen; j++) {
	    rb_ary_store(rb_ary_elt(result, j), i, rb_ary_elt(tmp, j));
	}
    }
    return result;
}

/*
 *  call-seq:
 *     ary.replace(other_ary)  -> ary
 *     ary.initialize_copy(other_ary)	-> ary
 *
 *  Replaces the contents of +self+ with the contents of +other_ary+,
 *  truncating or expanding if necessary.
 *
 *     a = [ "a", "b", "c", "d", "e" ]
 *     a.replace([ "x", "y", "z" ])   #=> ["x", "y", "z"]
 *     a                              #=> ["x", "y", "z"]
 */

VALUE
rb_ary_replace(VALUE copy, VALUE orig)
{
    rb_ary_modify_check(copy);
    orig = to_ary(orig);
    if (copy == orig) return copy;

    if (RARRAY_LEN(orig) <= RARRAY_EMBED_LEN_MAX) {
        VALUE shared = 0;

        if (ARY_OWNS_HEAP_P(copy)) {
	    RARRAY_PTR_USE(copy, ptr, ruby_sized_xfree(ptr, ARY_HEAP_SIZE(copy)));
	}
        else if (ARY_SHARED_P(copy)) {
            shared = ARY_SHARED(copy);
            FL_UNSET_SHARED(copy);
        }
        FL_SET_EMBED(copy);
	ary_memcpy(copy, 0, RARRAY_LEN(orig), RARRAY_CONST_PTR(orig));
        if (shared) {
            rb_ary_decrement_share(shared);
        }
        ARY_SET_LEN(copy, RARRAY_LEN(orig));
    }
    else {
        VALUE shared = ary_make_shared(orig);
        if (ARY_OWNS_HEAP_P(copy)) {
	    RARRAY_PTR_USE(copy, ptr, ruby_sized_xfree(ptr, ARY_HEAP_SIZE(copy)));
        }
        else {
            rb_ary_unshare_safe(copy);
        }
        FL_UNSET_EMBED(copy);
        ARY_SET_PTR(copy, RARRAY_CONST_PTR(orig));
        ARY_SET_LEN(copy, RARRAY_LEN(orig));
        rb_ary_set_shared(copy, shared);
    }
    return copy;
}

/*
 *  call-seq:
 *     ary.clear    -> ary
 *
 *  Removes all elements from +self+.
 *
 *     a = [ "a", "b", "c", "d", "e" ]
 *     a.clear    #=> [ ]
 */

VALUE
rb_ary_clear(VALUE ary)
{
    rb_ary_modify_check(ary);
    ARY_SET_LEN(ary, 0);
    if (ARY_SHARED_P(ary)) {
	if (!ARY_EMBED_P(ary)) {
	    rb_ary_unshare(ary);
	    FL_SET_EMBED(ary);
	}
    }
    else if (ARY_DEFAULT_SIZE * 2 < ARY_CAPA(ary)) {
	ary_resize_capa(ary, ARY_DEFAULT_SIZE * 2);
    }
    return ary;
}

/*
 *  call-seq:
 *     ary.fill(obj)                                 -> ary
 *     ary.fill(obj, start [, length])               -> ary
 *     ary.fill(obj, range )                         -> ary
 *     ary.fill { |index| block }                    -> ary
 *     ary.fill(start [, length] ) { |index| block } -> ary
 *     ary.fill(range) { |index| block }             -> ary
 *
 *  The first three forms set the selected elements of +self+ (which
 *  may be the entire array) to +obj+.
 *
 *  A +start+ of +nil+ is equivalent to zero.
 *
 *  A +length+ of +nil+ is equivalent to the length of the array.
 *
 *  The last three forms fill the array with the value of the given block,
 *  which is passed the absolute index of each element to be filled.
 *
 *  Negative values of +start+ count from the end of the array, where +-1+ is
 *  the last element.
 *
 *     a = [ "a", "b", "c", "d" ]
 *     a.fill("x")              #=> ["x", "x", "x", "x"]
 *     a.fill("z", 2, 2)        #=> ["x", "x", "z", "z"]
 *     a.fill("y", 0..1)        #=> ["y", "y", "z", "z"]
 *     a.fill { |i| i*i }       #=> [0, 1, 4, 9]
 *     a.fill(-2) { |i| i*i*i } #=> [0, 1, 8, 27]
 */

static VALUE
rb_ary_fill(int argc, VALUE *argv, VALUE ary)
{
    VALUE item = Qundef, arg1, arg2;
    long beg = 0, end = 0, len = 0;

    if (rb_block_given_p()) {
	rb_scan_args(argc, argv, "02", &arg1, &arg2);
	argc += 1;		/* hackish */
    }
    else {
	rb_scan_args(argc, argv, "12", &item, &arg1, &arg2);
    }
    switch (argc) {
      case 1:
	beg = 0;
	len = RARRAY_LEN(ary);
	break;
      case 2:
	if (rb_range_beg_len(arg1, &beg, &len, RARRAY_LEN(ary), 1)) {
	    break;
	}
	/* fall through */
      case 3:
	beg = NIL_P(arg1) ? 0 : NUM2LONG(arg1);
	if (beg < 0) {
	    beg = RARRAY_LEN(ary) + beg;
	    if (beg < 0) beg = 0;
	}
	len = NIL_P(arg2) ? RARRAY_LEN(ary) - beg : NUM2LONG(arg2);
	break;
    }
    rb_ary_modify(ary);
    if (len < 0) {
        return ary;
    }
    if (beg >= ARY_MAX_SIZE || len > ARY_MAX_SIZE - beg) {
	rb_raise(rb_eArgError, "argument too big");
    }
    end = beg + len;
    if (RARRAY_LEN(ary) < end) {
	if (end >= ARY_CAPA(ary)) {
	    ary_resize_capa(ary, end);
	}
	ary_mem_clear(ary, RARRAY_LEN(ary), end - RARRAY_LEN(ary));
	ARY_SET_LEN(ary, end);
    }

    if (item == Qundef) {
	VALUE v;
	long i;

	for (i=beg; i<end; i++) {
	    v = rb_yield(LONG2NUM(i));
	    if (i>=RARRAY_LEN(ary)) break;
	    ARY_SET(ary, i, v);
	}
    }
    else {
	ary_memfill(ary, beg, len, item);
    }
    return ary;
}

/*
 *  call-seq:
 *     ary + other_ary   -> new_ary
 *
 *  Concatenation --- Returns a new array built by concatenating the
 *  two arrays together to produce a third array.
 *
 *     [ 1, 2, 3 ] + [ 4, 5 ]    #=> [ 1, 2, 3, 4, 5 ]
 *     a = [ "a", "b", "c" ]
 *     c = a + [ "d", "e", "f" ]
 *     c                         #=> [ "a", "b", "c", "d", "e", "f" ]
 *     a                         #=> [ "a", "b", "c" ]
 *
 *  Note that
 *     x += y
 *  is the same as
 *     x = x + y
 *  This means that it produces a new array. As a consequence,
 *  repeated use of <code>+=</code> on arrays can be quite inefficient.
 *
 *  See also Array#concat.
 */

VALUE
rb_ary_plus(VALUE x, VALUE y)
{
    VALUE z;
    long len, xlen, ylen;

    y = to_ary(y);
    xlen = RARRAY_LEN(x);
    ylen = RARRAY_LEN(y);
    len = xlen + ylen;
    z = rb_ary_new2(len);

    ary_memcpy(z, 0, xlen, RARRAY_CONST_PTR(x));
    ary_memcpy(z, xlen, ylen, RARRAY_CONST_PTR(y));
    ARY_SET_LEN(z, len);
    return z;
}

static VALUE
ary_append(VALUE x, VALUE y)
{
    long n = RARRAY_LEN(y);
    if (n > 0) {
	rb_ary_splice(x, RARRAY_LEN(x), 0, RARRAY_CONST_PTR(y), n);
    }
    return x;
}

/*
 *  call-seq:
 *     ary.concat(other_ary1, other_ary2,...)   -> ary
 *
 *  Appends the elements of +other_ary+s to +self+.
 *
 *     [ "a", "b" ].concat( ["c", "d"] ) #=> [ "a", "b", "c", "d" ]
 *     [ "a" ].concat( ["b"], ["c", "d"] ) #=> [ "a", "b", "c", "d" ]
 *     [ "a" ].concat #=> [ "a" ]
 *
 *     a = [ 1, 2, 3 ]
 *     a.concat( [ 4, 5 ] )
 *     a                                 #=> [ 1, 2, 3, 4, 5 ]
 *
 *     a = [ 1, 2 ]
 *     a.concat(a, a)                    #=> [1, 2, 1, 2, 1, 2]
 *
 *  See also Array#+.
 */

static VALUE
rb_ary_concat_multi(int argc, VALUE *argv, VALUE ary)
{
    rb_ary_modify_check(ary);

    if (argc == 1) {
	rb_ary_concat(ary, argv[0]);
    }
    else if (argc > 1) {
	int i;
	VALUE args = rb_ary_tmp_new(argc);
	for (i = 0; i < argc; i++) {
	    rb_ary_concat(args, argv[i]);
	}
	ary_append(ary, args);
    }

    return ary;
}

VALUE
rb_ary_concat(VALUE x, VALUE y)
{
    return ary_append(x, to_ary(y));
}

/*
 *  call-seq:
 *     ary * int     -> new_ary
 *     ary * str     -> new_string
 *
 *  Repetition --- With a String argument, equivalent to
 *  <code>ary.join(str)</code>.
 *
 *  Otherwise, returns a new array built by concatenating the +int+ copies of
 *  +self+.
 *
 *
 *     [ 1, 2, 3 ] * 3    #=> [ 1, 2, 3, 1, 2, 3, 1, 2, 3 ]
 *     [ 1, 2, 3 ] * ","  #=> "1,2,3"
 *
 */

static VALUE
rb_ary_times(VALUE ary, VALUE times)
{
    VALUE ary2, tmp;
    const VALUE *ptr;
    long t, len;

    tmp = rb_check_string_type(times);
    if (!NIL_P(tmp)) {
	return rb_ary_join(ary, tmp);
    }

    len = NUM2LONG(times);
    if (len == 0) {
	ary2 = ary_new(rb_obj_class(ary), 0);
	goto out;
    }
    if (len < 0) {
	rb_raise(rb_eArgError, "negative argument");
    }
    if (ARY_MAX_SIZE/len < RARRAY_LEN(ary)) {
	rb_raise(rb_eArgError, "argument too big");
    }
    len *= RARRAY_LEN(ary);

    ary2 = ary_new(rb_obj_class(ary), len);
    ARY_SET_LEN(ary2, len);

    ptr = RARRAY_CONST_PTR(ary);
    t = RARRAY_LEN(ary);
    if (0 < t) {
	ary_memcpy(ary2, 0, t, ptr);
	while (t <= len/2) {
	    ary_memcpy(ary2, t, t, RARRAY_CONST_PTR(ary2));
            t *= 2;
        }
        if (t < len) {
	    ary_memcpy(ary2, t, len-t, RARRAY_CONST_PTR(ary2));
        }
    }
  out:
    OBJ_INFECT(ary2, ary);

    return ary2;
}

/*
 *  call-seq:
 *     ary.assoc(obj)   -> element_ary  or  nil
 *
 *  Searches through an array whose elements are also arrays comparing +obj+
 *  with the first element of each contained array using <code>obj.==</code>.
 *
 *  Returns the first contained array that matches (that is, the first
 *  associated array), or +nil+ if no match is found.
 *
 *  See also Array#rassoc
 *
 *     s1 = [ "colors", "red", "blue", "green" ]
 *     s2 = [ "letters", "a", "b", "c" ]
 *     s3 = "foo"
 *     a  = [ s1, s2, s3 ]
 *     a.assoc("letters")  #=> [ "letters", "a", "b", "c" ]
 *     a.assoc("foo")      #=> nil
 */

VALUE
rb_ary_assoc(VALUE ary, VALUE key)
{
    long i;
    VALUE v;

    for (i = 0; i < RARRAY_LEN(ary); ++i) {
	v = rb_check_array_type(RARRAY_AREF(ary, i));
	if (!NIL_P(v) && RARRAY_LEN(v) > 0 &&
	    rb_equal(RARRAY_AREF(v, 0), key))
	    return v;
    }
    return Qnil;
}

/*
 *  call-seq:
 *     ary.rassoc(obj) -> element_ary or nil
 *
 *  Searches through the array whose elements are also arrays.
 *
 *  Compares +obj+ with the second element of each contained array using
 *  <code>obj.==</code>.
 *
 *  Returns the first contained array that matches +obj+.
 *
 *  See also Array#assoc.
 *
 *     a = [ [ 1, "one"], [2, "two"], [3, "three"], ["ii", "two"] ]
 *     a.rassoc("two")    #=> [2, "two"]
 *     a.rassoc("four")   #=> nil
 */

VALUE
rb_ary_rassoc(VALUE ary, VALUE value)
{
    long i;
    VALUE v;

    for (i = 0; i < RARRAY_LEN(ary); ++i) {
	v = RARRAY_AREF(ary, i);
	if (RB_TYPE_P(v, T_ARRAY) &&
	    RARRAY_LEN(v) > 1 &&
	    rb_equal(RARRAY_AREF(v, 1), value))
	    return v;
    }
    return Qnil;
}

static VALUE
recursive_equal(VALUE ary1, VALUE ary2, int recur)
{
    long i, len1;
    const VALUE *p1, *p2;

    if (recur) return Qtrue; /* Subtle! */

    p1 = RARRAY_CONST_PTR(ary1);
    p2 = RARRAY_CONST_PTR(ary2);
    len1 = RARRAY_LEN(ary1);

    for (i = 0; i < len1; i++) {
	if (*p1 != *p2) {
	    if (rb_equal(*p1, *p2)) {
		len1 = RARRAY_LEN(ary1);
		if (len1 != RARRAY_LEN(ary2))
		    return Qfalse;
		if (len1 < i)
		    return Qtrue;
		p1 = RARRAY_CONST_PTR(ary1) + i;
		p2 = RARRAY_CONST_PTR(ary2) + i;
	    }
	    else {
		return Qfalse;
	    }
	}
	p1++;
	p2++;
    }
    return Qtrue;
}

/*
 *  call-seq:
 *     ary == other_ary   ->   bool
 *
 *  Equality --- Two arrays are equal if they contain the same number of
 *  elements and if each element is equal to (according to Object#==) the
 *  corresponding element in +other_ary+.
 *
 *     [ "a", "c" ]    == [ "a", "c", 7 ]     #=> false
 *     [ "a", "c", 7 ] == [ "a", "c", 7 ]     #=> true
 *     [ "a", "c", 7 ] == [ "a", "d", "f" ]   #=> false
 *
 */

static VALUE
rb_ary_equal(VALUE ary1, VALUE ary2)
{
    if (ary1 == ary2) return Qtrue;
    if (!RB_TYPE_P(ary2, T_ARRAY)) {
	if (!rb_respond_to(ary2, idTo_ary)) {
	    return Qfalse;
	}
	return rb_equal(ary2, ary1);
    }
    if (RARRAY_LEN(ary1) != RARRAY_LEN(ary2)) return Qfalse;
    if (RARRAY_CONST_PTR(ary1) == RARRAY_CONST_PTR(ary2)) return Qtrue;
    return rb_exec_recursive_paired(recursive_equal, ary1, ary2, ary2);
}

static VALUE
recursive_eql(VALUE ary1, VALUE ary2, int recur)
{
    long i;

    if (recur) return Qtrue; /* Subtle! */
    for (i=0; i<RARRAY_LEN(ary1); i++) {
	if (!rb_eql(rb_ary_elt(ary1, i), rb_ary_elt(ary2, i)))
	    return Qfalse;
    }
    return Qtrue;
}

/*
 *  call-seq:
 *     ary.eql?(other)  -> true or false
 *
 *  Returns +true+ if +self+ and +other+ are the same object,
 *  or are both arrays with the same content (according to Object#eql?).
 */

static VALUE
rb_ary_eql(VALUE ary1, VALUE ary2)
{
    if (ary1 == ary2) return Qtrue;
    if (!RB_TYPE_P(ary2, T_ARRAY)) return Qfalse;
    if (RARRAY_LEN(ary1) != RARRAY_LEN(ary2)) return Qfalse;
    if (RARRAY_CONST_PTR(ary1) == RARRAY_CONST_PTR(ary2)) return Qtrue;
    return rb_exec_recursive_paired(recursive_eql, ary1, ary2, ary2);
}

/*
 *  call-seq:
 *     ary.hash   -> integer
 *
 *  Compute a hash-code for this array.
 *
 *  Two arrays with the same content will have the same hash code (and will
 *  compare using #eql?).
 *
 *  See also Object#hash.
 */

static VALUE
rb_ary_hash(VALUE ary)
{
    long i;
    st_index_t h;
    VALUE n;

    h = rb_hash_start(RARRAY_LEN(ary));
    h = rb_hash_uint(h, (st_index_t)rb_ary_hash);
    for (i=0; i<RARRAY_LEN(ary); i++) {
	n = rb_hash(RARRAY_AREF(ary, i));
	h = rb_hash_uint(h, NUM2LONG(n));
    }
    h = rb_hash_end(h);
    return ST2FIX(h);
}

/*
 *  call-seq:
 *     ary.include?(object)   -> true or false
 *
 *  Returns +true+ if the given +object+ is present in +self+ (that is, if any
 *  element <code>==</code> +object+), otherwise returns +false+.
 *
 *     a = [ "a", "b", "c" ]
 *     a.include?("b")   #=> true
 *     a.include?("z")   #=> false
 */

VALUE
rb_ary_includes(VALUE ary, VALUE item)
{
    long i;
    VALUE e;

    for (i=0; i<RARRAY_LEN(ary); i++) {
	e = RARRAY_AREF(ary, i);
	if (rb_equal(e, item)) {
	    return Qtrue;
	}
    }
    return Qfalse;
}


static VALUE
recursive_cmp(VALUE ary1, VALUE ary2, int recur)
{
    long i, len;

    if (recur) return Qundef;	/* Subtle! */
    len = RARRAY_LEN(ary1);
    if (len > RARRAY_LEN(ary2)) {
	len = RARRAY_LEN(ary2);
    }
    for (i=0; i<len; i++) {
	VALUE e1 = rb_ary_elt(ary1, i), e2 = rb_ary_elt(ary2, i);
	VALUE v = rb_funcallv(e1, id_cmp, 1, &e2);
	if (v != INT2FIX(0)) {
	    return v;
	}
    }
    return Qundef;
}

/*
 *  call-seq:
 *     ary <=> other_ary   ->  -1, 0, +1 or nil
 *
 *  Comparison --- Returns an integer (+-1+, +0+, or <code>+1</code>) if this
 *  array is less than, equal to, or greater than +other_ary+.
 *
 *  Each object in each array is compared (using the <=> operator).
 *
 *  Arrays are compared in an "element-wise" manner; the first element of +ary+
 *  is compared with the first one of +other_ary+ using the <=> operator, then
 *  each of the second elements, etc...
 *  As soon as the result of any such comparison is non zero (i.e. the two
 *  corresponding elements are not equal), that result is returned for the
 *  whole array comparison.
 *
 *  If all the elements are equal, then the result is based on a comparison of
 *  the array lengths. Thus, two arrays are "equal" according to Array#<=> if,
 *  and only if, they have the same length and the value of each element is
 *  equal to the value of the corresponding element in the other array.
 *
 *  +nil+ is returned if the +other_ary+ is not an array or if the comparison
 *  of two elements returned +nil+.
 *
 *     [ "a", "a", "c" ]    <=> [ "a", "b", "c" ]   #=> -1
 *     [ 1, 2, 3, 4, 5, 6 ] <=> [ 1, 2 ]            #=> +1
 *     [ 1, 2 ]             <=> [ 1, :two ]         #=> nil
 *
 */

VALUE
rb_ary_cmp(VALUE ary1, VALUE ary2)
{
    long len;
    VALUE v;

    ary2 = rb_check_array_type(ary2);
    if (NIL_P(ary2)) return Qnil;
    if (ary1 == ary2) return INT2FIX(0);
    v = rb_exec_recursive_paired(recursive_cmp, ary1, ary2, ary2);
    if (v != Qundef) return v;
    len = RARRAY_LEN(ary1) - RARRAY_LEN(ary2);
    if (len == 0) return INT2FIX(0);
    if (len > 0) return INT2FIX(1);
    return INT2FIX(-1);
}

static VALUE
ary_add_hash(VALUE hash, VALUE ary)
{
    long i;

    for (i=0; i<RARRAY_LEN(ary); i++) {
	VALUE elt = RARRAY_AREF(ary, i);
	rb_hash_add_new_element(hash, elt, elt);
    }
    return hash;
}

static inline VALUE
ary_tmp_hash_new(void)
{
    VALUE hash = rb_hash_new();

    RBASIC_CLEAR_CLASS(hash);
    return hash;
}

static VALUE
ary_make_hash(VALUE ary)
{
    VALUE hash = ary_tmp_hash_new();
    return ary_add_hash(hash, ary);
}

static VALUE
ary_add_hash_by(VALUE hash, VALUE ary)
{
    long i;

    for (i = 0; i < RARRAY_LEN(ary); ++i) {
	VALUE v = rb_ary_elt(ary, i), k = rb_yield(v);
	rb_hash_add_new_element(hash, k, v);
    }
    return hash;
}

static VALUE
ary_make_hash_by(VALUE ary)
{
    VALUE hash = ary_tmp_hash_new();
    return ary_add_hash_by(hash, ary);
}

static inline void
ary_recycle_hash(VALUE hash)
{
    assert(RBASIC_CLASS(hash) == 0);
    if (RHASH(hash)->ntbl) {
	st_table *tbl = RHASH(hash)->ntbl;
	st_free_table(tbl);
    }
    rb_gc_force_recycle(hash);
}

/*
 *  call-seq:
 *     ary - other_ary    -> new_ary
 *
 *  Array Difference
 *
 *  Returns a new array that is a copy of the original array, removing any
 *  items that also appear in +other_ary+. The order is preserved from the
 *  original array.
 *
 *  It compares elements using their #hash and #eql? methods for efficiency.
 *
 *     [ 1, 1, 2, 2, 3, 3, 4, 5 ] - [ 1, 2, 4 ]  #=>  [ 3, 3, 5 ]
 *
 *  If you need set-like behavior, see the library class Set.
 */

static VALUE
rb_ary_diff(VALUE ary1, VALUE ary2)
{
    VALUE ary3;
    VALUE hash;
    long i;

    hash = ary_make_hash(to_ary(ary2));
    ary3 = rb_ary_new();

    for (i=0; i<RARRAY_LEN(ary1); i++) {
	if (st_lookup(rb_hash_tbl_raw(hash), RARRAY_AREF(ary1, i), 0)) continue;
	rb_ary_push(ary3, rb_ary_elt(ary1, i));
    }
    ary_recycle_hash(hash);
    return ary3;
}

/*
 *  call-seq:
 *     ary & other_ary      -> new_ary
 *
 *  Set Intersection --- Returns a new array containing unique elements common to the
 *  two arrays. The order is preserved from the original array.
 *
 *  It compares elements using their #hash and #eql? methods for efficiency.
 *
 *     [ 1, 1, 3, 5 ] & [ 3, 2, 1 ]                 #=> [ 1, 3 ]
 *     [ 'a', 'b', 'b', 'z' ] & [ 'a', 'b', 'c' ]   #=> [ 'a', 'b' ]
 *
 *  See also Array#uniq.
 */


static VALUE
rb_ary_and(VALUE ary1, VALUE ary2)
{
    VALUE hash, ary3, v;
    st_table *table;
    st_data_t vv;
    long i;

    ary2 = to_ary(ary2);
    ary3 = rb_ary_new();
    if (RARRAY_LEN(ary2) == 0) return ary3;
    hash = ary_make_hash(ary2);
    table = rb_hash_tbl_raw(hash);

    for (i=0; i<RARRAY_LEN(ary1); i++) {
	v = RARRAY_AREF(ary1, i);
	vv = (st_data_t)v;
	if (st_delete(table, &vv, 0)) {
	    rb_ary_push(ary3, v);
	}
    }
    ary_recycle_hash(hash);

    return ary3;
}

static int
ary_hash_orset(st_data_t *key, st_data_t *value, st_data_t arg, int existing)
{
    if (existing) return ST_STOP;
    *key = *value = (VALUE)arg;
    return ST_CONTINUE;
}

/*
 *  call-seq:
 *     ary | other_ary     -> new_ary
 *
 *  Set Union --- Returns a new array by joining +ary+ with +other_ary+,
 *  excluding any duplicates and preserving the order from the given arrays.
 *
 *  It compares elements using their #hash and #eql? methods for efficiency.
 *
 *     [ "a", "b", "c" ] | [ "c", "d", "a" ]    #=> [ "a", "b", "c", "d" ]
 *     [ "c", "d", "a" ] | [ "a", "b", "c" ]    #=> [ "c", "d", "a", "b" ]
 *
 *  See also Array#uniq.
 */

static VALUE
rb_ary_or(VALUE ary1, VALUE ary2)
{
    VALUE hash, ary3;
    long i;

    ary2 = to_ary(ary2);
    hash = ary_make_hash(ary1);

    for (i=0; i<RARRAY_LEN(ary2); i++) {
	VALUE elt = RARRAY_AREF(ary2, i);
	if (!st_update(RHASH_TBL_RAW(hash), (st_data_t)elt, ary_hash_orset, (st_data_t)elt)) {
	    RB_OBJ_WRITTEN(hash, Qundef, elt);
	}
    }
    ary3 = rb_hash_values(hash);
    ary_recycle_hash(hash);
    return ary3;
}

/*
 *  call-seq:
 *     ary.max                     -> obj
 *     ary.max { |a, b| block }    -> obj
 *     ary.max(n)                  -> array
 *     ary.max(n) { |a, b| block } -> array
 *
 *  Returns the object in _ary_ with the maximum value. The
 *  first form assumes all objects implement <code>Comparable</code>;
 *  the second uses the block to return <em>a <=> b</em>.
 *
 *     a = %w(albatross dog horse)
 *     a.max                                   #=> "horse"
 *     a.max { |a, b| a.length <=> b.length }  #=> "albatross"
 *
 *  If the +n+ argument is given, maximum +n+ elements are returned
 *  as an array.
 *
 *     a = %w[albatross dog horse]
 *     a.max(2)                                  #=> ["horse", "dog"]
 *     a.max(2) {|a, b| a.length <=> b.length }  #=> ["albatross", "horse"]
 */
static VALUE
rb_ary_max(int argc, VALUE *argv, VALUE ary)
{
    struct cmp_opt_data cmp_opt = { 0, 0 };
    VALUE result = Qundef, v;
    VALUE num;
    long i;

    rb_scan_args(argc, argv, "01", &num);

    if (!NIL_P(num))
       return rb_nmin_run(ary, num, 0, 1, 1);

    if (rb_block_given_p()) {
	for (i = 0; i < RARRAY_LEN(ary); i++) {
	   v = RARRAY_AREF(ary, i);
	   if (result == Qundef || rb_cmpint(rb_yield_values(2, v, result), v, result) > 0) {
	       result = v;
	   }
	}
    }
    else {
	for (i = 0; i < RARRAY_LEN(ary); i++) {
	   v = RARRAY_AREF(ary, i);
	   if (result == Qundef || OPTIMIZED_CMP(v, result, cmp_opt) > 0) {
	       result = v;
	   }
	}
    }
    if (result == Qundef) return Qnil;
    return result;
}

/*
 *  call-seq:
 *     ary.min                     -> obj
 *     ary.min {| a,b | block }    -> obj
 *     ary.min(n)                  -> array
 *     ary.min(n) {| a,b | block } -> array
 *
 *  Returns the object in _ary_ with the minimum value. The
 *  first form assumes all objects implement <code>Comparable</code>;
 *  the second uses the block to return <em>a <=> b</em>.
 *
 *     a = %w(albatross dog horse)
 *     a.min                                   #=> "albatross"
 *     a.min { |a, b| a.length <=> b.length }  #=> "dog"
 *
 *  If the +n+ argument is given, minimum +n+ elements are returned
 *  as an array.
 *
 *     a = %w[albatross dog horse]
 *     a.min(2)                                  #=> ["albatross", "dog"]
 *     a.min(2) {|a, b| a.length <=> b.length }  #=> ["dog", "horse"]
 */
static VALUE
rb_ary_min(int argc, VALUE *argv, VALUE ary)
{
    struct cmp_opt_data cmp_opt = { 0, 0 };
    VALUE result = Qundef, v;
    VALUE num;
    long i;

    rb_scan_args(argc, argv, "01", &num);

    if (!NIL_P(num))
       return rb_nmin_run(ary, num, 0, 0, 1);

    if (rb_block_given_p()) {
	for (i = 0; i < RARRAY_LEN(ary); i++) {
	   v = RARRAY_AREF(ary, i);
	   if (result == Qundef || rb_cmpint(rb_yield_values(2, v, result), v, result) < 0) {
	       result = v;
	   }
	}
    }
    else {
	for (i = 0; i < RARRAY_LEN(ary); i++) {
	   v = RARRAY_AREF(ary, i);
	   if (result == Qundef || OPTIMIZED_CMP(v, result, cmp_opt) < 0) {
	       result = v;
	   }
	}
    }
    if (result == Qundef) return Qnil;
    return result;
}

static int
push_value(st_data_t key, st_data_t val, st_data_t ary)
{
    rb_ary_push((VALUE)ary, (VALUE)val);
    return ST_CONTINUE;
}

/*
 *  call-seq:
 *     ary.uniq!                -> ary or nil
 *     ary.uniq! { |item| ... } -> ary or nil
 *
 *  Removes duplicate elements from +self+.
 *
 *  If a block is given, it will use the return value of the block for
 *  comparison.
 *
 *  It compares values using their #hash and #eql? methods for efficiency.
 *
 *  +self+ is traversed in order, and the first occurrence is kept.
 *
 *  Returns +nil+ if no changes are made (that is, no duplicates are found).
 *
 *     a = [ "a", "a", "b", "b", "c" ]
 *     a.uniq!   # => ["a", "b", "c"]
 *
 *     b = [ "a", "b", "c" ]
 *     b.uniq!   # => nil
 *
 *     c = [["student","sam"], ["student","george"], ["teacher","matz"]]
 *     c.uniq! { |s| s.first } # => [["student", "sam"], ["teacher", "matz"]]
 *
 */

static VALUE
rb_ary_uniq_bang(VALUE ary)
{
    VALUE hash;
    long hash_size;

    rb_ary_modify_check(ary);
    if (RARRAY_LEN(ary) <= 1)
        return Qnil;
    if (rb_block_given_p())
	hash = ary_make_hash_by(ary);
    else
	hash = ary_make_hash(ary);

    hash_size = RHASH_SIZE(hash);
    if (RARRAY_LEN(ary) == hash_size) {
	return Qnil;
    }
    rb_ary_modify_check(ary);
    ARY_SET_LEN(ary, 0);
    if (ARY_SHARED_P(ary) && !ARY_EMBED_P(ary)) {
	rb_ary_unshare(ary);
	FL_SET_EMBED(ary);
    }
    ary_resize_capa(ary, hash_size);
    st_foreach(rb_hash_tbl_raw(hash), push_value, ary);
    ary_recycle_hash(hash);

    return ary;
}

/*
 *  call-seq:
 *     ary.uniq                -> new_ary
 *     ary.uniq { |item| ... } -> new_ary
 *
 *  Returns a new array by removing duplicate values in +self+.
 *
 *  If a block is given, it will use the return value of the block for comparison.
 *
 *  It compares values using their #hash and #eql? methods for efficiency.
 *
 *  +self+ is traversed in order, and the first occurrence is kept.
 *
 *     a = [ "a", "a", "b", "b", "c" ]
 *     a.uniq   # => ["a", "b", "c"]
 *
 *     b = [["student","sam"], ["student","george"], ["teacher","matz"]]
 *     b.uniq { |s| s.first } # => [["student", "sam"], ["teacher", "matz"]]
 *
 */

static VALUE
rb_ary_uniq(VALUE ary)
{
    VALUE hash, uniq;

    if (RARRAY_LEN(ary) <= 1)
        return rb_ary_dup(ary);
    if (rb_block_given_p()) {
	hash = ary_make_hash_by(ary);
	uniq = rb_hash_values(hash);
    }
    else {
	hash = ary_make_hash(ary);
	uniq = rb_hash_values(hash);
    }
    RBASIC_SET_CLASS(uniq, rb_obj_class(ary));
    ary_recycle_hash(hash);

    return uniq;
}

/*
 *  call-seq:
 *     ary.compact!    -> ary  or  nil
 *
 *  Removes +nil+ elements from the array.
 *
 *  Returns +nil+ if no changes were made, otherwise returns the array.
 *
 *     [ "a", nil, "b", nil, "c" ].compact! #=> [ "a", "b", "c" ]
 *     [ "a", "b", "c" ].compact!           #=> nil
 */

static VALUE
rb_ary_compact_bang(VALUE ary)
{
    VALUE *p, *t, *end;
    long n;

    rb_ary_modify(ary);
    p = t = (VALUE *)RARRAY_CONST_PTR(ary); /* WB: no new reference */
    end = p + RARRAY_LEN(ary);

    while (t < end) {
	if (NIL_P(*t)) t++;
	else *p++ = *t++;
    }
    n = p - RARRAY_CONST_PTR(ary);
    if (RARRAY_LEN(ary) == n) {
	return Qnil;
    }
    ary_resize_smaller(ary, n);

    return ary;
}

/*
 *  call-seq:
 *     ary.compact     -> new_ary
 *
 *  Returns a copy of +self+ with all +nil+ elements removed.
 *
 *     [ "a", nil, "b", nil, "c", nil ].compact
 *                       #=> [ "a", "b", "c" ]
 */

static VALUE
rb_ary_compact(VALUE ary)
{
    ary = rb_ary_dup(ary);
    rb_ary_compact_bang(ary);
    return ary;
}

/*
 *  call-seq:
 *     ary.count                   -> int
 *     ary.count(obj)              -> int
 *     ary.count { |item| block }  -> int
 *
 *  Returns the number of elements.
 *
 *  If an argument is given, counts the number of elements which equal +obj+
 *  using <code>==</code>.
 *
 *  If a block is given, counts the number of elements for which the block
 *  returns a true value.
 *
 *     ary = [1, 2, 4, 2]
 *     ary.count                  #=> 4
 *     ary.count(2)               #=> 2
 *     ary.count { |x| x%2 == 0 } #=> 3
 *
 */

static VALUE
rb_ary_count(int argc, VALUE *argv, VALUE ary)
{
    long i, n = 0;

    if (argc == 0) {
	VALUE v;

	if (!rb_block_given_p())
	    return LONG2NUM(RARRAY_LEN(ary));

	for (i = 0; i < RARRAY_LEN(ary); i++) {
	    v = RARRAY_AREF(ary, i);
	    if (RTEST(rb_yield(v))) n++;
	}
    }
    else {
	VALUE obj;

	rb_scan_args(argc, argv, "1", &obj);
	if (rb_block_given_p()) {
	    rb_warn("given block not used");
	}
	for (i = 0; i < RARRAY_LEN(ary); i++) {
	    if (rb_equal(RARRAY_AREF(ary, i), obj)) n++;
	}
    }

    return LONG2NUM(n);
}

static VALUE
flatten(VALUE ary, int level, int *modified)
{
    long i = 0;
    VALUE stack, result, tmp, elt;
    st_table *memo;
    st_data_t id;

    stack = ary_new(0, ARY_DEFAULT_SIZE);
    result = ary_new(0, RARRAY_LEN(ary));
    memo = st_init_numtable();
    st_insert(memo, (st_data_t)ary, (st_data_t)Qtrue);
    *modified = 0;

    while (1) {
	while (i < RARRAY_LEN(ary)) {
	    elt = RARRAY_AREF(ary, i++);
	    if (level >= 0 && RARRAY_LEN(stack) / 2 >= level) {
		rb_ary_push(result, elt);
		continue;
	    }
	    tmp = rb_check_array_type(elt);
	    if (RBASIC(result)->klass) {
		rb_raise(rb_eRuntimeError, "flatten reentered");
	    }
	    if (NIL_P(tmp)) {
		rb_ary_push(result, elt);
	    }
	    else {
		*modified = 1;
		id = (st_data_t)tmp;
		if (st_lookup(memo, id, 0)) {
		    st_free_table(memo);
		    rb_raise(rb_eArgError, "tried to flatten recursive array");
		}
		st_insert(memo, id, (st_data_t)Qtrue);
		rb_ary_push(stack, ary);
		rb_ary_push(stack, LONG2NUM(i));
		ary = tmp;
		i = 0;
	    }
	}
	if (RARRAY_LEN(stack) == 0) {
	    break;
	}
	id = (st_data_t)ary;
	st_delete(memo, &id, 0);
	tmp = rb_ary_pop(stack);
	i = NUM2LONG(tmp);
	ary = rb_ary_pop(stack);
    }

    st_free_table(memo);

    RBASIC_SET_CLASS(result, rb_obj_class(ary));
    return result;
}

/*
 *  call-seq:
 *     ary.flatten!        -> ary or nil
 *     ary.flatten!(level) -> ary or nil
 *
 *  Flattens +self+ in place.
 *
 *  Returns +nil+ if no modifications were made (i.e., the array contains no
 *  subarrays.)
 *
 *  The optional +level+ argument determines the level of recursion to flatten.
 *
 *     a = [ 1, 2, [3, [4, 5] ] ]
 *     a.flatten!   #=> [1, 2, 3, 4, 5]
 *     a.flatten!   #=> nil
 *     a            #=> [1, 2, 3, 4, 5]
 *     a = [ 1, 2, [3, [4, 5] ] ]
 *     a.flatten!(1) #=> [1, 2, 3, [4, 5]]
 */

static VALUE
rb_ary_flatten_bang(int argc, VALUE *argv, VALUE ary)
{
    int mod = 0, level = -1;
    VALUE result, lv;

    rb_scan_args(argc, argv, "01", &lv);
    rb_ary_modify_check(ary);
    if (!NIL_P(lv)) level = NUM2INT(lv);
    if (level == 0) return Qnil;

    result = flatten(ary, level, &mod);
    if (mod == 0) {
	ary_discard(result);
	return Qnil;
    }
    if (!(mod = ARY_EMBED_P(result))) rb_obj_freeze(result);
    rb_ary_replace(ary, result);
    if (mod) ARY_SET_EMBED_LEN(result, 0);

    return ary;
}

/*
 *  call-seq:
 *     ary.flatten -> new_ary
 *     ary.flatten(level) -> new_ary
 *
 *  Returns a new array that is a one-dimensional flattening of +self+
 *  (recursively).
 *
 *  That is, for every element that is an array, extract its elements into
 *  the new array.
 *
 *  The optional +level+ argument determines the level of recursion to
 *  flatten.
 *
 *     s = [ 1, 2, 3 ]           #=> [1, 2, 3]
 *     t = [ 4, 5, 6, [7, 8] ]   #=> [4, 5, 6, [7, 8]]
 *     a = [ s, t, 9, 10 ]       #=> [[1, 2, 3], [4, 5, 6, [7, 8]], 9, 10]
 *     a.flatten                 #=> [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
 *     a = [ 1, 2, [3, [4, 5] ] ]
 *     a.flatten(1)              #=> [1, 2, 3, [4, 5]]
 */

static VALUE
rb_ary_flatten(int argc, VALUE *argv, VALUE ary)
{
    int mod = 0, level = -1;
    VALUE result, lv;

    rb_scan_args(argc, argv, "01", &lv);
    if (!NIL_P(lv)) level = NUM2INT(lv);
    if (level == 0) return ary_make_shared_copy(ary);

    result = flatten(ary, level, &mod);
    OBJ_INFECT(result, ary);

    return result;
}

#define OPTHASH_GIVEN_P(opts) \
    (argc > 0 && !NIL_P((opts) = rb_check_hash_type(argv[argc-1])) && (--argc, 1))
static ID id_random;

#define RAND_UPTO(max) (long)rb_random_ulong_limited((randgen), (max)-1)

/*
 *  call-seq:
 *     ary.shuffle!              -> ary
 *     ary.shuffle!(random: rng) -> ary
 *
 *  Shuffles elements in +self+ in place.
 *
 *     a = [ 1, 2, 3 ]           #=> [1, 2, 3]
 *     a.shuffle!                #=> [2, 3, 1]
 *     a                         #=> [2, 3, 1]
 *
 *  The optional +rng+ argument will be used as the random number generator.
 *
 *     a.shuffle!(random: Random.new(1))  #=> [1, 3, 2]
 */

static VALUE
rb_ary_shuffle_bang(int argc, VALUE *argv, VALUE ary)
{
    VALUE opts, randgen = rb_cRandom;
    long i, len;

    if (OPTHASH_GIVEN_P(opts)) {
	VALUE rnd;
	ID keyword_ids[1];

	keyword_ids[0] = id_random;
	rb_get_kwargs(opts, keyword_ids, 0, 1, &rnd);
	if (rnd != Qundef) {
	    randgen = rnd;
	}
    }
    rb_check_arity(argc, 0, 0);
    rb_ary_modify(ary);
    i = len = RARRAY_LEN(ary);
    RARRAY_PTR_USE(ary, ptr, {
	while (i) {
	    long j = RAND_UPTO(i);
	    VALUE tmp;
	    if (len != RARRAY_LEN(ary) || ptr != RARRAY_CONST_PTR(ary)) {
		rb_raise(rb_eRuntimeError, "modified during shuffle");
	    }
	    tmp = ptr[--i];
	    ptr[i] = ptr[j];
	    ptr[j] = tmp;
	}
    }); /* WB: no new reference */
    return ary;
}


/*
 *  call-seq:
 *     ary.shuffle              -> new_ary
 *     ary.shuffle(random: rng) -> new_ary
 *
 *  Returns a new array with elements of +self+ shuffled.
 *
 *     a = [ 1, 2, 3 ]           #=> [1, 2, 3]
 *     a.shuffle                 #=> [2, 3, 1]
 *     a                         #=> [1, 2, 3]
 *
 *  The optional +rng+ argument will be used as the random number generator.
 *
 *     a.shuffle(random: Random.new(1))  #=> [1, 3, 2]
 */

static VALUE
rb_ary_shuffle(int argc, VALUE *argv, VALUE ary)
{
    ary = rb_ary_dup(ary);
    rb_ary_shuffle_bang(argc, argv, ary);
    return ary;
}


/*
 *  call-seq:
 *     ary.sample                  -> obj
 *     ary.sample(random: rng)     -> obj
 *     ary.sample(n)               -> new_ary
 *     ary.sample(n, random: rng)  -> new_ary
 *
 *  Choose a random element or +n+ random elements from the array.
 *
 *  The elements are chosen by using random and unique indices into the array
 *  in order to ensure that an element doesn't repeat itself unless the array
 *  already contained duplicate elements.
 *
 *  If the array is empty the first form returns +nil+ and the second form
 *  returns an empty array.
 *
 *  The optional +rng+ argument will be used as the random number generator.
 *
 *     a = [ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ]
 *     a.sample         #=> 7
 *     a.sample(4)      #=> [6, 4, 2, 5]
 */


static VALUE
rb_ary_sample(int argc, VALUE *argv, VALUE ary)
{
    VALUE nv, result;
    VALUE opts, randgen = rb_cRandom;
    long n, len, i, j, k, idx[10];
    long rnds[numberof(idx)];
    long memo_threshold;

    if (OPTHASH_GIVEN_P(opts)) {
	VALUE rnd;
	ID keyword_ids[1];

	keyword_ids[0] = id_random;
	rb_get_kwargs(opts, keyword_ids, 0, 1, &rnd);
	if (rnd != Qundef) {
	    randgen = rnd;
	}
    }
    len = RARRAY_LEN(ary);
    if (argc == 0) {
	if (len < 2)
	    i = 0;
	else
	    i = RAND_UPTO(len);

	return rb_ary_elt(ary, i);
    }
    rb_scan_args(argc, argv, "1", &nv);
    n = NUM2LONG(nv);
    if (n < 0) rb_raise(rb_eArgError, "negative sample number");
    if (n > len) n = len;
    if (n <= numberof(idx)) {
	for (i = 0; i < n; ++i) {
	    rnds[i] = RAND_UPTO(len - i);
	}
    }
    k = len;
    len = RARRAY_LEN(ary);
    if (len < k && n <= numberof(idx)) {
	for (i = 0; i < n; ++i) {
	    if (rnds[i] >= len) return rb_ary_new_capa(0);
	}
    }
    if (n > len) n = len;
    switch (n) {
      case 0:
	return rb_ary_new_capa(0);
      case 1:
	i = rnds[0];
	return rb_ary_new_from_values(1, &RARRAY_AREF(ary, i));
      case 2:
	i = rnds[0];
	j = rnds[1];
	if (j >= i) j++;
	return rb_ary_new_from_args(2, RARRAY_AREF(ary, i), RARRAY_AREF(ary, j));
      case 3:
	i = rnds[0];
	j = rnds[1];
	k = rnds[2];
	{
	    long l = j, g = i;
	    if (j >= i) l = i, g = ++j;
	    if (k >= l && (++k >= g)) ++k;
	}
	return rb_ary_new_from_args(3, RARRAY_AREF(ary, i), RARRAY_AREF(ary, j), RARRAY_AREF(ary, k));
    }
    memo_threshold =
	len < 2560 ? len / 128 :
	len < 5120 ? len / 64 :
	len < 10240 ? len / 32 :
	len / 16;
    if (n <= numberof(idx)) {
	long sorted[numberof(idx)];
	sorted[0] = idx[0] = rnds[0];
	for (i=1; i<n; i++) {
	    k = rnds[i];
	    for (j = 0; j < i; ++j) {
		if (k < sorted[j]) break;
		++k;
	    }
	    memmove(&sorted[j+1], &sorted[j], sizeof(sorted[0])*(i-j));
	    sorted[j] = idx[i] = k;
	}
	result = rb_ary_new_capa(n);
	RARRAY_PTR_USE(result, ptr_result, {
	    for (i=0; i<n; i++) {
		ptr_result[i] = RARRAY_AREF(ary, idx[i]);
	    }
	});
    }
    else if (n <= memo_threshold / 2) {
	long max_idx = 0;
#undef RUBY_UNTYPED_DATA_WARNING
#define RUBY_UNTYPED_DATA_WARNING 0
	VALUE vmemo = Data_Wrap_Struct(0, 0, 0, st_free_table);
	st_table *memo = st_init_numtable_with_size(n);
	DATA_PTR(vmemo) = memo;
	result = rb_ary_new_capa(n);
	RARRAY_PTR_USE(result, ptr_result, {
	    for (i=0; i<n; i++) {
		long r = RAND_UPTO(len-i) + i;
		ptr_result[i] = r;
		if (r > max_idx) max_idx = r;
	    }
	    len = RARRAY_LEN(ary);
	    if (len <= max_idx) n = 0;
	    else if (n > len) n = len;
	    RARRAY_PTR_USE(ary, ptr_ary, {
		for (i=0; i<n; i++) {
		    long j2 = j = ptr_result[i];
		    long i2 = i;
		    st_data_t value;
		    if (st_lookup(memo, (st_data_t)i, &value)) i2 = (long)value;
		    if (st_lookup(memo, (st_data_t)j, &value)) j2 = (long)value;
		    st_insert(memo, (st_data_t)j, (st_data_t)i2);
		    ptr_result[i] = ptr_ary[j2];
		}
	    });
	});
	DATA_PTR(vmemo) = 0;
	st_free_table(memo);
    }
    else {
	result = rb_ary_dup(ary);
	RBASIC_CLEAR_CLASS(result);
	RB_GC_GUARD(ary);
	RARRAY_PTR_USE(result, ptr_result, {
	    for (i=0; i<n; i++) {
		j = RAND_UPTO(len-i) + i;
		nv = ptr_result[j];
		ptr_result[j] = ptr_result[i];
		ptr_result[i] = nv;
	    }
	});
	RBASIC_SET_CLASS_RAW(result, rb_cArray);
    }
    ARY_SET_LEN(result, n);

    return result;
}

static VALUE
rb_ary_cycle_size(VALUE self, VALUE args, VALUE eobj)
{
    long mul;
    VALUE n = Qnil;
    if (args && (RARRAY_LEN(args) > 0)) {
	n = RARRAY_AREF(args, 0);
    }
    if (RARRAY_LEN(self) == 0) return INT2FIX(0);
    if (n == Qnil) return DBL2NUM(INFINITY);
    mul = NUM2LONG(n);
    if (mul <= 0) return INT2FIX(0);
    n = LONG2FIX(mul);
    return rb_funcallv(rb_ary_length(self), '*', 1, &n);
}

/*
 *  call-seq:
 *     ary.cycle(n=nil) { |obj| block }  -> nil
 *     ary.cycle(n=nil)                  -> Enumerator
 *
 *  Calls the given block for each element +n+ times or forever if +nil+ is
 *  given.
 *
 *  Does nothing if a non-positive number is given or the array is empty.
 *
 *  Returns +nil+ if the loop has finished without getting interrupted.
 *
 *  If no block is given, an Enumerator is returned instead.
 *
 *     a = ["a", "b", "c"]
 *     a.cycle { |x| puts x }     # print, a, b, c, a, b, c,.. forever.
 *     a.cycle(2) { |x| puts x }  # print, a, b, c, a, b, c.
 *
 */

static VALUE
rb_ary_cycle(int argc, VALUE *argv, VALUE ary)
{
    long n, i;
    VALUE nv = Qnil;

    rb_scan_args(argc, argv, "01", &nv);

    RETURN_SIZED_ENUMERATOR(ary, argc, argv, rb_ary_cycle_size);
    if (NIL_P(nv)) {
        n = -1;
    }
    else {
        n = NUM2LONG(nv);
        if (n <= 0) return Qnil;
    }

    while (RARRAY_LEN(ary) > 0 && (n < 0 || 0 < n--)) {
        for (i=0; i<RARRAY_LEN(ary); i++) {
            rb_yield(RARRAY_AREF(ary, i));
        }
    }
    return Qnil;
}

#define tmpbuf(n, size) rb_str_tmp_new((n)*(size))
#define tmpbuf_discard(s) (rb_str_resize((s), 0L), RBASIC_SET_CLASS_RAW(s, rb_cString))
#define tmpary(n) rb_ary_tmp_new(n)
#define tmpary_discard(a) (ary_discard(a), RBASIC_SET_CLASS_RAW(a, rb_cArray))

/*
 * Build a ruby array of the corresponding values and yield it to the
 * associated block.
 * Return the class of +values+ for reentry check.
 */
static int
yield_indexed_values(const VALUE values, const long r, const long *const p)
{
    const VALUE result = rb_ary_new2(r);
    VALUE *const result_array = RARRAY_PTR(result);
    const VALUE *const values_array = RARRAY_CONST_PTR(values);
    long i;

    for (i = 0; i < r; i++) result_array[i] = values_array[p[i]];
    ARY_SET_LEN(result, r);
    rb_yield(result);
    return !RBASIC(values)->klass;
}

/*
 * Compute permutations of +r+ elements of the set <code>[0..n-1]</code>.
 *
 * When we have a complete permutation of array indices, copy the values
 * at those indices into a new array and yield that array.
 *
 * n: the size of the set
 * r: the number of elements in each permutation
 * p: the array (of size r) that we're filling in
 * used: an array of booleans: whether a given index is already used
 * values: the Ruby array that holds the actual values to permute
 */
static void
permute0(const long n, const long r, long *const p, char *const used, const VALUE values)
{
    long i = 0, index = 0;

    for (;;) {
	const char *const unused = memchr(&used[i], 0, n-i);
	if (!unused) {
	    if (!index) break;
	    i = p[--index];                /* pop index */
	    used[i++] = 0;                 /* index unused */
	}
	else {
	    i = unused - used;
	    p[index] = i;
	    used[i] = 1;                   /* mark index used */
	    ++index;
	    if (index < r-1) {             /* if not done yet */
		p[index] = i = 0;
		continue;
	    }
	    for (i = 0; i < n; ++i) {
		if (used[i]) continue;
		p[index] = i;
		if (!yield_indexed_values(values, r, p)) {
		    rb_raise(rb_eRuntimeError, "permute reentered");
		}
	    }
	    i = p[--index];                /* pop index */
	    used[i] = 0;                   /* index unused */
	    p[index] = ++i;
	}
    }
}

/*
 * Returns the product of from, from-1, ..., from - how_many + 1.
 * http://en.wikipedia.org/wiki/Pochhammer_symbol
 */
static VALUE
descending_factorial(long from, long how_many)
{
    VALUE cnt = LONG2FIX(how_many >= 0);
    while (how_many-- > 0) {
	VALUE v = LONG2FIX(from--);
	cnt = rb_funcallv(cnt, '*', 1, &v);
    }
    return cnt;
}

static VALUE
binomial_coefficient(long comb, long size)
{
    VALUE r, v;
    if (comb > size-comb) {
	comb = size-comb;
    }
    if (comb < 0) {
	return LONG2FIX(0);
    }
    r = descending_factorial(size, comb);
    v = descending_factorial(comb, comb);
    return rb_funcallv(r, id_div, 1, &v);
}

static VALUE
rb_ary_permutation_size(VALUE ary, VALUE args, VALUE eobj)
{
    long n = RARRAY_LEN(ary);
    long k = (args && (RARRAY_LEN(args) > 0)) ? NUM2LONG(RARRAY_AREF(args, 0)) : n;

    return descending_factorial(n, k);
}

/*
 *  call-seq:
 *     ary.permutation { |p| block }          -> ary
 *     ary.permutation                        -> Enumerator
 *     ary.permutation(n) { |p| block }       -> ary
 *     ary.permutation(n)                     -> Enumerator
 *
 * When invoked with a block, yield all permutations of length +n+ of the
 * elements of the array, then return the array itself.
 *
 * If +n+ is not specified, yield all permutations of all elements.
 *
 * The implementation makes no guarantees about the order in which the
 * permutations are yielded.
 *
 * If no block is given, an Enumerator is returned instead.
 *
 * Examples:
 *
 *   a = [1, 2, 3]
 *   a.permutation.to_a    #=> [[1,2,3],[1,3,2],[2,1,3],[2,3,1],[3,1,2],[3,2,1]]
 *   a.permutation(1).to_a #=> [[1],[2],[3]]
 *   a.permutation(2).to_a #=> [[1,2],[1,3],[2,1],[2,3],[3,1],[3,2]]
 *   a.permutation(3).to_a #=> [[1,2,3],[1,3,2],[2,1,3],[2,3,1],[3,1,2],[3,2,1]]
 *   a.permutation(0).to_a #=> [[]] # one permutation of length 0
 *   a.permutation(4).to_a #=> []   # no permutations of length 4
 */

static VALUE
rb_ary_permutation(int argc, VALUE *argv, VALUE ary)
{
    VALUE num;
    long r, n, i;

    n = RARRAY_LEN(ary);                  /* Array length */
    RETURN_SIZED_ENUMERATOR(ary, argc, argv, rb_ary_permutation_size);   /* Return enumerator if no block */
    rb_scan_args(argc, argv, "01", &num);
    r = NIL_P(num) ? n : NUM2LONG(num);   /* Permutation size from argument */

    if (r < 0 || n < r) {
	/* no permutations: yield nothing */
    }
    else if (r == 0) { /* exactly one permutation: the zero-length array */
	rb_yield(rb_ary_new2(0));
    }
    else if (r == 1) { /* this is a special, easy case */
	for (i = 0; i < RARRAY_LEN(ary); i++) {
	    rb_yield(rb_ary_new3(1, RARRAY_AREF(ary, i)));
	}
    }
    else {             /* this is the general case */
	volatile VALUE t0;
	long *p = ALLOCV_N(long, t0, r+roomof(n, sizeof(long)));
	char *used = (char*)(p + r);
	VALUE ary0 = ary_make_shared_copy(ary); /* private defensive copy of ary */
	RBASIC_CLEAR_CLASS(ary0);

	MEMZERO(used, char, n); /* initialize array */

	permute0(n, r, p, used, ary0); /* compute and yield permutations */
	ALLOCV_END(t0);
	RBASIC_SET_CLASS_RAW(ary0, rb_cArray);
    }
    return ary;
}

static void
combinate0(const long len, const long n, long *const stack, const VALUE values)
{
    long lev = 0;

    MEMZERO(stack+1, long, n);
    stack[0] = -1;
    for (;;) {
	for (lev++; lev < n; lev++) {
	    stack[lev+1] = stack[lev]+1;
	}
	if (!yield_indexed_values(values, n, stack+1)) {
	    rb_raise(rb_eRuntimeError, "combination reentered");
	}
	do {
	    if (lev == 0) return;
	    stack[lev--]++;
	} while (stack[lev+1]+n == len+lev+1);
    }
}

static VALUE
rb_ary_combination_size(VALUE ary, VALUE args, VALUE eobj)
{
    long n = RARRAY_LEN(ary);
    long k = NUM2LONG(RARRAY_AREF(args, 0));

    return binomial_coefficient(k, n);
}

/*
 *  call-seq:
 *     ary.combination(n) { |c| block }    -> ary
 *     ary.combination(n)                  -> Enumerator
 *
 * When invoked with a block, yields all combinations of length +n+ of elements
 * from the array and then returns the array itself.
 *
 * The implementation makes no guarantees about the order in which the
 * combinations are yielded.
 *
 * If no block is given, an Enumerator is returned instead.
 *
 * Examples:
 *
 *     a = [1, 2, 3, 4]
 *     a.combination(1).to_a  #=> [[1],[2],[3],[4]]
 *     a.combination(2).to_a  #=> [[1,2],[1,3],[1,4],[2,3],[2,4],[3,4]]
 *     a.combination(3).to_a  #=> [[1,2,3],[1,2,4],[1,3,4],[2,3,4]]
 *     a.combination(4).to_a  #=> [[1,2,3,4]]
 *     a.combination(0).to_a  #=> [[]] # one combination of length 0
 *     a.combination(5).to_a  #=> []   # no combinations of length 5
 *
 */

static VALUE
rb_ary_combination(VALUE ary, VALUE num)
{
    long i, n, len;

    n = NUM2LONG(num);
    RETURN_SIZED_ENUMERATOR(ary, 1, &num, rb_ary_combination_size);
    len = RARRAY_LEN(ary);
    if (n < 0 || len < n) {
	/* yield nothing */
    }
    else if (n == 0) {
	rb_yield(rb_ary_new2(0));
    }
    else if (n == 1) {
	for (i = 0; i < RARRAY_LEN(ary); i++) {
	    rb_yield(rb_ary_new3(1, RARRAY_AREF(ary, i)));
	}
    }
    else {
	VALUE ary0 = ary_make_shared_copy(ary); /* private defensive copy of ary */
	volatile VALUE t0;
	long *stack = ALLOCV_N(long, t0, n+1);

	RBASIC_CLEAR_CLASS(ary0);
	combinate0(len, n, stack, ary0);
	ALLOCV_END(t0);
	RBASIC_SET_CLASS_RAW(ary0, rb_cArray);
    }
    return ary;
}

/*
 * Compute repeated permutations of +r+ elements of the set
 * <code>[0..n-1]</code>.
 *
 * When we have a complete repeated permutation of array indices, copy the
 * values at those indices into a new array and yield that array.
 *
 * n: the size of the set
 * r: the number of elements in each permutation
 * p: the array (of size r) that we're filling in
 * values: the Ruby array that holds the actual values to permute
 */
static void
rpermute0(const long n, const long r, long *const p, const VALUE values)
{
    long i = 0, index = 0;

    p[index] = i;
    for (;;) {
	if (++index < r-1) {
	    p[index] = i = 0;
	    continue;
	}
	for (i = 0; i < n; ++i) {
	    p[index] = i;
	    if (!yield_indexed_values(values, r, p)) {
		rb_raise(rb_eRuntimeError, "repeated permute reentered");
	    }
	}
	do {
	    if (index <= 0) return;
	} while ((i = ++p[--index]) >= n);
    }
}

static VALUE
rb_ary_repeated_permutation_size(VALUE ary, VALUE args, VALUE eobj)
{
    long n = RARRAY_LEN(ary);
    long k = NUM2LONG(RARRAY_AREF(args, 0));
    VALUE v;

    if (k < 0) {
	return LONG2FIX(0);
    }

    v = LONG2NUM(k);
    return rb_funcallv(LONG2NUM(n), idPow, 1, &v);
}

/*
 *  call-seq:
 *     ary.repeated_permutation(n) { |p| block } -> ary
 *     ary.repeated_permutation(n)               -> Enumerator
 *
 * When invoked with a block, yield all repeated permutations of length +n+ of
 * the elements of the array, then return the array itself.
 *
 * The implementation makes no guarantees about the order in which the repeated
 * permutations are yielded.
 *
 * If no block is given, an Enumerator is returned instead.
 *
 * Examples:
 *
 *     a = [1, 2]
 *     a.repeated_permutation(1).to_a  #=> [[1], [2]]
 *     a.repeated_permutation(2).to_a  #=> [[1,1],[1,2],[2,1],[2,2]]
 *     a.repeated_permutation(3).to_a  #=> [[1,1,1],[1,1,2],[1,2,1],[1,2,2],
 *                                     #    [2,1,1],[2,1,2],[2,2,1],[2,2,2]]
 *     a.repeated_permutation(0).to_a  #=> [[]] # one permutation of length 0
 */

static VALUE
rb_ary_repeated_permutation(VALUE ary, VALUE num)
{
    long r, n, i;

    n = RARRAY_LEN(ary);                  /* Array length */
    RETURN_SIZED_ENUMERATOR(ary, 1, &num, rb_ary_repeated_permutation_size);      /* Return Enumerator if no block */
    r = NUM2LONG(num);                    /* Permutation size from argument */

    if (r < 0) {
	/* no permutations: yield nothing */
    }
    else if (r == 0) { /* exactly one permutation: the zero-length array */
	rb_yield(rb_ary_new2(0));
    }
    else if (r == 1) { /* this is a special, easy case */
	for (i = 0; i < RARRAY_LEN(ary); i++) {
	    rb_yield(rb_ary_new3(1, RARRAY_AREF(ary, i)));
	}
    }
    else {             /* this is the general case */
	volatile VALUE t0;
	long *p = ALLOCV_N(long, t0, r);
	VALUE ary0 = ary_make_shared_copy(ary); /* private defensive copy of ary */
	RBASIC_CLEAR_CLASS(ary0);

	rpermute0(n, r, p, ary0); /* compute and yield repeated permutations */
	ALLOCV_END(t0);
	RBASIC_SET_CLASS_RAW(ary0, rb_cArray);
    }
    return ary;
}

static void
rcombinate0(const long n, const long r, long *const p, const long rest, const VALUE values)
{
    long i = 0, index = 0;

    p[index] = i;
    for (;;) {
	if (++index < r-1) {
	    p[index] = i;
	    continue;
	}
	for (; i < n; ++i) {
	    p[index] = i;
	    if (!yield_indexed_values(values, r, p)) {
		rb_raise(rb_eRuntimeError, "repeated combination reentered");
	    }
	}
	do {
	    if (index <= 0) return;
	} while ((i = ++p[--index]) >= n);
    }
}

static VALUE
rb_ary_repeated_combination_size(VALUE ary, VALUE args, VALUE eobj)
{
    long n = RARRAY_LEN(ary);
    long k = NUM2LONG(RARRAY_AREF(args, 0));
    if (k == 0) {
	return LONG2FIX(1);
    }
    return binomial_coefficient(k, n + k - 1);
}

/*
 *  call-seq:
 *     ary.repeated_combination(n) { |c| block } -> ary
 *     ary.repeated_combination(n)               -> Enumerator
 *
 * When invoked with a block, yields all repeated combinations of length +n+ of
 * elements from the array and then returns the array itself.
 *
 * The implementation makes no guarantees about the order in which the repeated
 * combinations are yielded.
 *
 * If no block is given, an Enumerator is returned instead.
 *
 * Examples:
 *
 *   a = [1, 2, 3]
 *   a.repeated_combination(1).to_a  #=> [[1], [2], [3]]
 *   a.repeated_combination(2).to_a  #=> [[1,1],[1,2],[1,3],[2,2],[2,3],[3,3]]
 *   a.repeated_combination(3).to_a  #=> [[1,1,1],[1,1,2],[1,1,3],[1,2,2],[1,2,3],
 *                                   #    [1,3,3],[2,2,2],[2,2,3],[2,3,3],[3,3,3]]
 *   a.repeated_combination(4).to_a  #=> [[1,1,1,1],[1,1,1,2],[1,1,1,3],[1,1,2,2],[1,1,2,3],
 *                                   #    [1,1,3,3],[1,2,2,2],[1,2,2,3],[1,2,3,3],[1,3,3,3],
 *                                   #    [2,2,2,2],[2,2,2,3],[2,2,3,3],[2,3,3,3],[3,3,3,3]]
 *   a.repeated_combination(0).to_a  #=> [[]] # one combination of length 0
 *
 */

static VALUE
rb_ary_repeated_combination(VALUE ary, VALUE num)
{
    long n, i, len;

    n = NUM2LONG(num);                 /* Combination size from argument */
    RETURN_SIZED_ENUMERATOR(ary, 1, &num, rb_ary_repeated_combination_size);   /* Return enumerator if no block */
    len = RARRAY_LEN(ary);
    if (n < 0) {
	/* yield nothing */
    }
    else if (n == 0) {
	rb_yield(rb_ary_new2(0));
    }
    else if (n == 1) {
	for (i = 0; i < RARRAY_LEN(ary); i++) {
	    rb_yield(rb_ary_new3(1, RARRAY_AREF(ary, i)));
	}
    }
    else if (len == 0) {
	/* yield nothing */
    }
    else {
	volatile VALUE t0;
	long *p = ALLOCV_N(long, t0, n);
	VALUE ary0 = ary_make_shared_copy(ary); /* private defensive copy of ary */
	RBASIC_CLEAR_CLASS(ary0);

	rcombinate0(len, n, p, n, ary0); /* compute and yield repeated combinations */
	ALLOCV_END(t0);
	RBASIC_SET_CLASS_RAW(ary0, rb_cArray);
    }
    return ary;
}

/*
 *  call-seq:
 *     ary.product(other_ary, ...)                -> new_ary
 *     ary.product(other_ary, ...) { |p| block }  -> ary
 *
 *  Returns an array of all combinations of elements from all arrays.
 *
 *  The length of the returned array is the product of the length of +self+ and
 *  the argument arrays.
 *
 *  If given a block, #product will yield all combinations and return +self+
 *  instead.
 *
 *     [1,2,3].product([4,5])     #=> [[1,4],[1,5],[2,4],[2,5],[3,4],[3,5]]
 *     [1,2].product([1,2])       #=> [[1,1],[1,2],[2,1],[2,2]]
 *     [1,2].product([3,4],[5,6]) #=> [[1,3,5],[1,3,6],[1,4,5],[1,4,6],
 *                                #     [2,3,5],[2,3,6],[2,4,5],[2,4,6]]
 *     [1,2].product()            #=> [[1],[2]]
 *     [1,2].product([])          #=> []
 */

static VALUE
rb_ary_product(int argc, VALUE *argv, VALUE ary)
{
    int n = argc+1;    /* How many arrays we're operating on */
    volatile VALUE t0 = tmpary(n);
    volatile VALUE t1 = tmpbuf(n, sizeof(int));
    VALUE *arrays = RARRAY_PTR(t0); /* The arrays we're computing the product of */
    int *counters = (int*)RSTRING_PTR(t1); /* The current position in each one */
    VALUE result = Qnil;      /* The array we'll be returning, when no block given */
    long i,j;
    long resultlen = 1;

    RBASIC_CLEAR_CLASS(t0);
    RBASIC_CLEAR_CLASS(t1);

    /* initialize the arrays of arrays */
    ARY_SET_LEN(t0, n);
    arrays[0] = ary;
    for (i = 1; i < n; i++) arrays[i] = Qnil;
    for (i = 1; i < n; i++) arrays[i] = to_ary(argv[i-1]);

    /* initialize the counters for the arrays */
    for (i = 0; i < n; i++) counters[i] = 0;

    /* Otherwise, allocate and fill in an array of results */
    if (rb_block_given_p()) {
	/* Make defensive copies of arrays; exit if any is empty */
	for (i = 0; i < n; i++) {
	    if (RARRAY_LEN(arrays[i]) == 0) goto done;
	    arrays[i] = ary_make_shared_copy(arrays[i]);
	}
    }
    else {
	/* Compute the length of the result array; return [] if any is empty */
	for (i = 0; i < n; i++) {
	    long k = RARRAY_LEN(arrays[i]);
	    if (k == 0) {
		result = rb_ary_new2(0);
		goto done;
	    }
            if (MUL_OVERFLOW_LONG_P(resultlen, k))
		rb_raise(rb_eRangeError, "too big to product");
	    resultlen *= k;
	}
	result = rb_ary_new2(resultlen);
    }
    for (;;) {
	int m;
	/* fill in one subarray */
	VALUE subarray = rb_ary_new2(n);
	for (j = 0; j < n; j++) {
	    rb_ary_push(subarray, rb_ary_entry(arrays[j], counters[j]));
	}

	/* put it on the result array */
	if (NIL_P(result)) {
	    FL_SET(t0, FL_USER5);
	    rb_yield(subarray);
	    if (! FL_TEST(t0, FL_USER5)) {
		rb_raise(rb_eRuntimeError, "product reentered");
	    }
	    else {
		FL_UNSET(t0, FL_USER5);
	    }
	}
	else {
	    rb_ary_push(result, subarray);
	}

	/*
	 * Increment the last counter.  If it overflows, reset to 0
	 * and increment the one before it.
	 */
	m = n-1;
	counters[m]++;
	while (counters[m] == RARRAY_LEN(arrays[m])) {
	    counters[m] = 0;
	    /* If the first counter overflows, we are done */
	    if (--m < 0) goto done;
	    counters[m]++;
	}
    }
done:
    tmpary_discard(t0);
    tmpbuf_discard(t1);

    return NIL_P(result) ? ary : result;
}

/*
 *  call-seq:
 *     ary.take(n)               -> new_ary
 *
 *  Returns first +n+ elements from the array.
 *
 *  If a negative number is given, raises an ArgumentError.
 *
 *  See also Array#drop
 *
 *     a = [1, 2, 3, 4, 5, 0]
 *     a.take(3)             #=> [1, 2, 3]
 *
 */

static VALUE
rb_ary_take(VALUE obj, VALUE n)
{
    long len = NUM2LONG(n);
    if (len < 0) {
	rb_raise(rb_eArgError, "attempt to take negative size");
    }
    return rb_ary_subseq(obj, 0, len);
}

/*
 *  call-seq:
 *     ary.take_while { |obj| block }  -> new_ary
 *     ary.take_while                  -> Enumerator
 *
 *  Passes elements to the block until the block returns +nil+ or +false+, then
 *  stops iterating and returns an array of all prior elements.
 *
 *  If no block is given, an Enumerator is returned instead.
 *
 *  See also Array#drop_while
 *
 *     a = [1, 2, 3, 4, 5, 0]
 *     a.take_while { |i| i < 3 }  #=> [1, 2]
 *
 */

static VALUE
rb_ary_take_while(VALUE ary)
{
    long i;

    RETURN_ENUMERATOR(ary, 0, 0);
    for (i = 0; i < RARRAY_LEN(ary); i++) {
	if (!RTEST(rb_yield(RARRAY_AREF(ary, i)))) break;
    }
    return rb_ary_take(ary, LONG2FIX(i));
}

/*
 *  call-seq:
 *     ary.drop(n)               -> new_ary
 *
 *  Drops first +n+ elements from +ary+ and returns the rest of the elements in
 *  an array.
 *
 *  If a negative number is given, raises an ArgumentError.
 *
 *  See also Array#take
 *
 *     a = [1, 2, 3, 4, 5, 0]
 *     a.drop(3)             #=> [4, 5, 0]
 *
 */

static VALUE
rb_ary_drop(VALUE ary, VALUE n)
{
    VALUE result;
    long pos = NUM2LONG(n);
    if (pos < 0) {
	rb_raise(rb_eArgError, "attempt to drop negative size");
    }

    result = rb_ary_subseq(ary, pos, RARRAY_LEN(ary));
    if (result == Qnil) result = rb_ary_new();
    return result;
}

/*
 *  call-seq:
 *     ary.drop_while { |obj| block }   -> new_ary
 *     ary.drop_while                  -> Enumerator
 *
 *  Drops elements up to, but not including, the first element for which the
 *  block returns +nil+ or +false+ and returns an array containing the
 *  remaining elements.
 *
 *  If no block is given, an Enumerator is returned instead.
 *
 *  See also Array#take_while
 *
 *     a = [1, 2, 3, 4, 5, 0]
 *     a.drop_while {|i| i < 3 }   #=> [3, 4, 5, 0]
 *
 */

static VALUE
rb_ary_drop_while(VALUE ary)
{
    long i;

    RETURN_ENUMERATOR(ary, 0, 0);
    for (i = 0; i < RARRAY_LEN(ary); i++) {
	if (!RTEST(rb_yield(RARRAY_AREF(ary, i)))) break;
    }
    return rb_ary_drop(ary, LONG2FIX(i));
}

/*
 *  call-seq:
 *     ary.any? [{ |obj| block }]   -> true or false
 *
 *  See also Enumerable#any?
 */

static VALUE
rb_ary_any_p(VALUE ary)
{
    long i, len = RARRAY_LEN(ary);
    const VALUE *ptr = RARRAY_CONST_PTR(ary);

    if (!len) return Qfalse;
    if (!rb_block_given_p()) {
	for (i = 0; i < len; ++i) if (RTEST(ptr[i])) return Qtrue;
    }
    else {
	for (i = 0; i < RARRAY_LEN(ary); ++i) {
	    if (RTEST(rb_yield(RARRAY_AREF(ary, i)))) return Qtrue;
	}
    }
    return Qfalse;
}

/*
 * call-seq:
 *   ary.dig(idx, ...)                 -> object
 *
 * Extracts the nested value specified by the sequence of <i>idx</i>
 * objects by calling +dig+ at each step, returning +nil+ if any
 * intermediate step is +nil+.
 *
 *   a = [[1, [2, 3]]]
 *
 *   a.dig(0, 1, 1)                    #=> 3
 *   a.dig(1, 2, 3)                    #=> nil
 *   a.dig(0, 0, 0)                    #=> TypeError: Integer does not have #dig method
 *   [42, {foo: :bar}].dig(1, :foo)    #=> :bar
 */

VALUE
rb_ary_dig(int argc, VALUE *argv, VALUE self)
{
    rb_check_arity(argc, 1, UNLIMITED_ARGUMENTS);
    self = rb_ary_at(self, *argv);
    if (!--argc) return self;
    ++argv;
    return rb_obj_dig(argc, argv, self, Qnil);
}

static inline VALUE
finish_exact_sum(long n, VALUE r, VALUE v, int z)
{
    if (n != 0)
        v = rb_fix_plus(LONG2FIX(n), v);
    if (r != Qundef) {
	/* r can be an Integer when mathn is loaded */
	if (FIXNUM_P(r))
	    v = rb_fix_plus(r, v);
	else if (RB_TYPE_P(r, T_BIGNUM))
	    v = rb_big_plus(r, v);
	else
	    v = rb_rational_plus(r, v);
    }
    else if (!n && z) {
        v = rb_fix_plus(LONG2FIX(0), v);
    }
    return v;
}

/*
 * call-seq:
 *   ary.sum(init=0)                    -> number
 *   ary.sum(init=0) {|e| expr }        -> number
 *
 * Returns the sum of elements.
 * For example, [e1, e2, e3].sum returns init + e1 + e2 + e3.
 *
 * If a block is given, the block is applied to each element
 * before addition.
 *
 * If <i>ary</i> is empty, it returns <i>init</i>.
 *
 *   [].sum                             #=> 0
 *   [].sum(0.0)                        #=> 0.0
 *   [1, 2, 3].sum                      #=> 6
 *   [3, 5.5].sum                       #=> 8.5
 *   [2.5, 3.0].sum(0.0) {|e| e * e }   #=> 15.25
 *   [Object.new].sum                   #=> TypeError
 *
 * The (arithmetic) mean value of an array can be obtained as follows.
 *
 *   mean = ary.sum(0.0) / ary.length
 *
 * This method can be used for non-numeric objects by
 * explicit <i>init</i> argument.
 *
 *   ["a", "b", "c"].sum("")            #=> "abc"
 *   [[1], [[2]], [3]].sum([])          #=> [1, [2], 3]
 *
 * However, Array#join and Array#flatten is faster than Array#sum for
 * array of strings and array of arrays.
 *
 *   ["a", "b", "c"].join               #=> "abc"
 *   [[1], [[2]], [3]].flatten(1)       #=> [1, [2], 3]
 *
 *
 * Array#sum method may not respect method redefinition of "+" methods
 * such as Integer#+.
 *
 */

static VALUE
rb_ary_sum(int argc, VALUE *argv, VALUE ary)
{
    VALUE e, v, r;
    long i, n;
    int block_given;

    if (rb_scan_args(argc, argv, "01", &v) == 0)
        v = LONG2FIX(0);

    block_given = rb_block_given_p();

    if (RARRAY_LEN(ary) == 0)
        return v;

    n = 0;
    r = Qundef;
    for (i = 0; i < RARRAY_LEN(ary); i++) {
        e = RARRAY_AREF(ary, i);
        if (block_given)
            e = rb_yield(e);
        if (FIXNUM_P(e)) {
            n += FIX2LONG(e); /* should not overflow long type */
            if (!FIXABLE(n)) {
                v = rb_big_plus(LONG2NUM(n), v);
                n = 0;
            }
        }
        else if (RB_TYPE_P(e, T_BIGNUM))
            v = rb_big_plus(e, v);
        else if (RB_TYPE_P(e, T_RATIONAL)) {
            if (r == Qundef)
                r = e;
            else
                r = rb_rational_plus(r, e);
        }
        else
            goto not_exact;
    }
    v = finish_exact_sum(n, r, v, argc!=0);
    return v;

  not_exact:
    v = finish_exact_sum(n, r, v, i!=0);

    if (RB_FLOAT_TYPE_P(e)) {
        /*
         * Kahan-Babuska balancing compensated summation algorithm
         * See http://link.springer.com/article/10.1007/s00607-005-0139-x
         */
        double f, c;

        f = NUM2DBL(v);
        c = 0.0;
        goto has_float_value;
        for (; i < RARRAY_LEN(ary); i++) {
            double x, t;
            e = RARRAY_AREF(ary, i);
            if (block_given)
                e = rb_yield(e);
            if (RB_FLOAT_TYPE_P(e))
              has_float_value:
                x = RFLOAT_VALUE(e);
            else if (FIXNUM_P(e))
                x = FIX2LONG(e);
            else if (RB_TYPE_P(e, T_BIGNUM))
                x = rb_big2dbl(e);
            else if (RB_TYPE_P(e, T_RATIONAL))
                x = rb_num2dbl(e);
            else
                goto not_float;

            t = f + x;
            if (fabs(f) >= fabs(x))
                c += ((f - t) + x);
            else
                c += ((x - t) + f);
            f = t;
        }
        f += c;
        return DBL2NUM(f);

      not_float:
        v = DBL2NUM(f);
    }

    goto has_some_value;
    for (; i < RARRAY_LEN(ary); i++) {
        e = RARRAY_AREF(ary, i);
        if (block_given)
            e = rb_yield(e);
      has_some_value:
        v = rb_funcall(v, idPLUS, 1, e);
    }
    return v;
}

/*
 *  Arrays are ordered, integer-indexed collections of any object.
 *
 *  Array indexing starts at 0, as in C or Java.  A negative index is assumed
 *  to be relative to the end of the array---that is, an index of -1 indicates
 *  the last element of the array, -2 is the next to last element in the
 *  array, and so on.
 *
 *  == Creating Arrays
 *
 *  A new array can be created by using the literal constructor
 *  <code>[]</code>.  Arrays can contain different types of objects.  For
 *  example, the array below contains an Integer, a String and a Float:
 *
 *     ary = [1, "two", 3.0] #=> [1, "two", 3.0]
 *
 *  An array can also be created by explicitly calling Array.new with zero, one
 *  (the initial size of the Array) or two arguments (the initial size and a
 *  default object).
 *
 *     ary = Array.new    #=> []
 *     Array.new(3)       #=> [nil, nil, nil]
 *     Array.new(3, true) #=> [true, true, true]
 *
 *  Note that the second argument populates the array with references to the
 *  same object.  Therefore, it is only recommended in cases when you need to
 *  instantiate arrays with natively immutable objects such as Symbols,
 *  numbers, true or false.
 *
 *  To create an array with separate objects a block can be passed instead.
 *  This method is safe to use with mutable objects such as hashes, strings or
 *  other arrays:
 *
 *     Array.new(4) { Hash.new }  #=> [{}, {}, {}, {}]
 *     Array.new(4) {|i| i.to_s } #=> ["0", "1", "2", "3"]
 *
 *  This is also a quick way to build up multi-dimensional arrays:
 *
 *     empty_table = Array.new(3) { Array.new(3) }
 *     #=> [[nil, nil, nil], [nil, nil, nil], [nil, nil, nil]]
 *
 *  An array can also be created by using the Array() method, provided by
 *  Kernel, which tries to call #to_ary, then #to_a on its argument.
 *
 *	Array({:a => "a", :b => "b"}) #=> [[:a, "a"], [:b, "b"]]
 *
 *  == Example Usage
 *
 *  In addition to the methods it mixes in through the Enumerable module, the
 *  Array class has proprietary methods for accessing, searching and otherwise
 *  manipulating arrays.
 *
 *  Some of the more common ones are illustrated below.
 *
 *  == Accessing Elements
 *
 *  Elements in an array can be retrieved using the Array#[] method.  It can
 *  take a single integer argument (a numeric index), a pair of arguments
 *  (start and length) or a range. Negative indices start counting from the end,
 *  with -1 being the last element.
 *
 *     arr = [1, 2, 3, 4, 5, 6]
 *     arr[2]    #=> 3
 *     arr[100]  #=> nil
 *     arr[-3]   #=> 4
 *     arr[2, 3] #=> [3, 4, 5]
 *     arr[1..4] #=> [2, 3, 4, 5]
 *     arr[1..-3] #=> [2, 3, 4]
 *
 *  Another way to access a particular array element is by using the #at method
 *
 *     arr.at(0) #=> 1
 *
 *  The #slice method works in an identical manner to Array#[].
 *
 *  To raise an error for indices outside of the array bounds or else to
 *  provide a default value when that happens, you can use #fetch.
 *
 *     arr = ['a', 'b', 'c', 'd', 'e', 'f']
 *     arr.fetch(100) #=> IndexError: index 100 outside of array bounds: -6...6
 *     arr.fetch(100, "oops") #=> "oops"
 *
 *  The special methods #first and #last will return the first and last
 *  elements of an array, respectively.
 *
 *     arr.first #=> 1
 *     arr.last  #=> 6
 *
 *  To return the first +n+ elements of an array, use #take
 *
 *     arr.take(3) #=> [1, 2, 3]
 *
 *  #drop does the opposite of #take, by returning the elements after +n+
 *  elements have been dropped:
 *
 *     arr.drop(3) #=> [4, 5, 6]
 *
 *  == Obtaining Information about an Array
 *
 *  Arrays keep track of their own length at all times.  To query an array
 *  about the number of elements it contains, use #length, #count or #size.
 *
 *    browsers = ['Chrome', 'Firefox', 'Safari', 'Opera', 'IE']
 *    browsers.length #=> 5
 *    browsers.count #=> 5
 *
 *  To check whether an array contains any elements at all
 *
 *    browsers.empty? #=> false
 *
 *  To check whether a particular item is included in the array
 *
 *    browsers.include?('Konqueror') #=> false
 *
 *  == Adding Items to Arrays
 *
 *  Items can be added to the end of an array by using either #push or #<<
 *
 *    arr = [1, 2, 3, 4]
 *    arr.push(5) #=> [1, 2, 3, 4, 5]
 *    arr << 6    #=> [1, 2, 3, 4, 5, 6]
 *
 *  #unshift will add a new item to the beginning of an array.
 *
 *     arr.unshift(0) #=> [0, 1, 2, 3, 4, 5, 6]
 *
 *  With #insert you can add a new element to an array at any position.
 *
 *     arr.insert(3, 'apple')  #=> [0, 1, 2, 'apple', 3, 4, 5, 6]
 *
 *  Using the #insert method, you can also insert multiple values at once:
 *
 *     arr.insert(3, 'orange', 'pear', 'grapefruit')
 *     #=> [0, 1, 2, "orange", "pear", "grapefruit", "apple", 3, 4, 5, 6]
 *
 *  == Removing Items from an Array
 *
 *  The method #pop removes the last element in an array and returns it:
 *
 *     arr =  [1, 2, 3, 4, 5, 6]
 *     arr.pop #=> 6
 *     arr #=> [1, 2, 3, 4, 5]
 *
 *  To retrieve and at the same time remove the first item, use #shift:
 *
 *     arr.shift #=> 1
 *     arr #=> [2, 3, 4, 5]
 *
 *  To delete an element at a particular index:
 *
 *     arr.delete_at(2) #=> 4
 *     arr #=> [2, 3, 5]
 *
 *  To delete a particular element anywhere in an array, use #delete:
 *
 *     arr = [1, 2, 2, 3]
 *     arr.delete(2) #=> 2
 *     arr #=> [1,3]
 *
 *  A useful method if you need to remove +nil+ values from an array is
 *  #compact:
 *
 *     arr = ['foo', 0, nil, 'bar', 7, 'baz', nil]
 *     arr.compact  #=> ['foo', 0, 'bar', 7, 'baz']
 *     arr          #=> ['foo', 0, nil, 'bar', 7, 'baz', nil]
 *     arr.compact! #=> ['foo', 0, 'bar', 7, 'baz']
 *     arr          #=> ['foo', 0, 'bar', 7, 'baz']
 *
 *  Another common need is to remove duplicate elements from an array.
 *
 *  It has the non-destructive #uniq, and destructive method #uniq!
 *
 *     arr = [2, 5, 6, 556, 6, 6, 8, 9, 0, 123, 556]
 *     arr.uniq #=> [2, 5, 6, 556, 8, 9, 0, 123]
 *
 *  == Iterating over Arrays
 *
 *  Like all classes that include the Enumerable module, Array has an each
 *  method, which defines what elements should be iterated over and how.  In
 *  case of Array's #each, all elements in the Array instance are yielded to
 *  the supplied block in sequence.
 *
 *  Note that this operation leaves the array unchanged.
 *
 *     arr = [1, 2, 3, 4, 5]
 *     arr.each { |a| print a -= 10, " " }
 *     # prints: -9 -8 -7 -6 -5
 *     #=> [1, 2, 3, 4, 5]
 *
 *  Another sometimes useful iterator is #reverse_each which will iterate over
 *  the elements in the array in reverse order.
 *
 *     words = %w[first second third fourth fifth sixth]
 *     str = ""
 *     words.reverse_each { |word| str += "#{word} " }
 *     p str #=> "sixth fifth fourth third second first "
 *
 *  The #map method can be used to create a new array based on the original
 *  array, but with the values modified by the supplied block:
 *
 *     arr.map { |a| 2*a }   #=> [2, 4, 6, 8, 10]
 *     arr                   #=> [1, 2, 3, 4, 5]
 *     arr.map! { |a| a**2 } #=> [1, 4, 9, 16, 25]
 *     arr                   #=> [1, 4, 9, 16, 25]
 *
 *  == Selecting Items from an Array
 *
 *  Elements can be selected from an array according to criteria defined in a
 *  block.  The selection can happen in a destructive or a non-destructive
 *  manner.  While the destructive operations will modify the array they were
 *  called on, the non-destructive methods usually return a new array with the
 *  selected elements, but leave the original array unchanged.
 *
 *  === Non-destructive Selection
 *
 *     arr = [1, 2, 3, 4, 5, 6]
 *     arr.select { |a| a > 3 }     #=> [4, 5, 6]
 *     arr.reject { |a| a < 3 }     #=> [3, 4, 5, 6]
 *     arr.drop_while { |a| a < 4 } #=> [4, 5, 6]
 *     arr                          #=> [1, 2, 3, 4, 5, 6]
 *
 *  === Destructive Selection
 *
 *  #select! and #reject! are the corresponding destructive methods to #select
 *  and #reject
 *
 *  Similar to #select vs. #reject, #delete_if and #keep_if have the exact
 *  opposite result when supplied with the same block:
 *
 *     arr.delete_if { |a| a < 4 } #=> [4, 5, 6]
 *     arr                         #=> [4, 5, 6]
 *
 *     arr = [1, 2, 3, 4, 5, 6]
 *     arr.keep_if { |a| a < 4 } #=> [1, 2, 3]
 *     arr                       #=> [1, 2, 3]
 *
 */

void
Init_Array(void)
{
#undef rb_intern
#define rb_intern(str) rb_intern_const(str)

    rb_cArray  = rb_define_class("Array", rb_cObject);
    rb_include_module(rb_cArray, rb_mEnumerable);

    rb_define_alloc_func(rb_cArray, empty_ary_alloc);
    rb_define_singleton_method(rb_cArray, "[]", rb_ary_s_create, -1);
    rb_define_singleton_method(rb_cArray, "try_convert", rb_ary_s_try_convert, 1);
    rb_define_method(rb_cArray, "initialize", rb_ary_initialize, -1);
    rb_define_method(rb_cArray, "initialize_copy", rb_ary_replace, 1);

    rb_define_method(rb_cArray, "inspect", rb_ary_inspect, 0);
    rb_define_alias(rb_cArray,  "to_s", "inspect");
    rb_define_method(rb_cArray, "to_a", rb_ary_to_a, 0);
    rb_define_method(rb_cArray, "to_h", rb_ary_to_h, 0);
    rb_define_method(rb_cArray, "to_ary", rb_ary_to_ary_m, 0);
    rb_define_method(rb_cArray, "frozen?",  rb_ary_frozen_p, 0);

    rb_define_method(rb_cArray, "==", rb_ary_equal, 1);
    rb_define_method(rb_cArray, "eql?", rb_ary_eql, 1);
    rb_define_method(rb_cArray, "hash", rb_ary_hash, 0);

    rb_define_method(rb_cArray, "[]", rb_ary_aref, -1);
    rb_define_method(rb_cArray, "[]=", rb_ary_aset, -1);
    rb_define_method(rb_cArray, "at", rb_ary_at, 1);
    rb_define_method(rb_cArray, "fetch", rb_ary_fetch, -1);
    rb_define_method(rb_cArray, "first", rb_ary_first, -1);
    rb_define_method(rb_cArray, "last", rb_ary_last, -1);
    rb_define_method(rb_cArray, "concat", rb_ary_concat_multi, -1);
    rb_define_method(rb_cArray, "<<", rb_ary_push, 1);
    rb_define_method(rb_cArray, "push", rb_ary_push_m, -1);
    rb_define_alias(rb_cArray,  "append", "push");
    rb_define_method(rb_cArray, "pop", rb_ary_pop_m, -1);
    rb_define_method(rb_cArray, "shift", rb_ary_shift_m, -1);
    rb_define_method(rb_cArray, "unshift", rb_ary_unshift_m, -1);
    rb_define_alias(rb_cArray,  "prepend", "unshift");
    rb_define_method(rb_cArray, "insert", rb_ary_insert, -1);
    rb_define_method(rb_cArray, "each", rb_ary_each, 0);
    rb_define_method(rb_cArray, "each_index", rb_ary_each_index, 0);
    rb_define_method(rb_cArray, "reverse_each", rb_ary_reverse_each, 0);
    rb_define_method(rb_cArray, "length", rb_ary_length, 0);
    rb_define_alias(rb_cArray,  "size", "length");
    rb_define_method(rb_cArray, "empty?", rb_ary_empty_p, 0);
    rb_define_method(rb_cArray, "find_index", rb_ary_index, -1);
    rb_define_method(rb_cArray, "index", rb_ary_index, -1);
    rb_define_method(rb_cArray, "rindex", rb_ary_rindex, -1);
    rb_define_method(rb_cArray, "join", rb_ary_join_m, -1);
    rb_define_method(rb_cArray, "reverse", rb_ary_reverse_m, 0);
    rb_define_method(rb_cArray, "reverse!", rb_ary_reverse_bang, 0);
    rb_define_method(rb_cArray, "rotate", rb_ary_rotate_m, -1);
    rb_define_method(rb_cArray, "rotate!", rb_ary_rotate_bang, -1);
    rb_define_method(rb_cArray, "sort", rb_ary_sort, 0);
    rb_define_method(rb_cArray, "sort!", rb_ary_sort_bang, 0);
    rb_define_method(rb_cArray, "sort_by!", rb_ary_sort_by_bang, 0);
    rb_define_method(rb_cArray, "collect", rb_ary_collect, 0);
    rb_define_method(rb_cArray, "collect!", rb_ary_collect_bang, 0);
    rb_define_method(rb_cArray, "map", rb_ary_collect, 0);
    rb_define_method(rb_cArray, "map!", rb_ary_collect_bang, 0);
    rb_define_method(rb_cArray, "select", rb_ary_select, 0);
    rb_define_method(rb_cArray, "select!", rb_ary_select_bang, 0);
    rb_define_method(rb_cArray, "keep_if", rb_ary_keep_if, 0);
    rb_define_method(rb_cArray, "values_at", rb_ary_values_at, -1);
    rb_define_method(rb_cArray, "delete", rb_ary_delete, 1);
    rb_define_method(rb_cArray, "delete_at", rb_ary_delete_at_m, 1);
    rb_define_method(rb_cArray, "delete_if", rb_ary_delete_if, 0);
    rb_define_method(rb_cArray, "reject", rb_ary_reject, 0);
    rb_define_method(rb_cArray, "reject!", rb_ary_reject_bang, 0);
    rb_define_method(rb_cArray, "zip", rb_ary_zip, -1);
    rb_define_method(rb_cArray, "transpose", rb_ary_transpose, 0);
    rb_define_method(rb_cArray, "replace", rb_ary_replace, 1);
    rb_define_method(rb_cArray, "clear", rb_ary_clear, 0);
    rb_define_method(rb_cArray, "fill", rb_ary_fill, -1);
    rb_define_method(rb_cArray, "include?", rb_ary_includes, 1);
    rb_define_method(rb_cArray, "<=>", rb_ary_cmp, 1);

    rb_define_method(rb_cArray, "slice", rb_ary_aref, -1);
    rb_define_method(rb_cArray, "slice!", rb_ary_slice_bang, -1);

    rb_define_method(rb_cArray, "assoc", rb_ary_assoc, 1);
    rb_define_method(rb_cArray, "rassoc", rb_ary_rassoc, 1);

    rb_define_method(rb_cArray, "+", rb_ary_plus, 1);
    rb_define_method(rb_cArray, "*", rb_ary_times, 1);

    rb_define_method(rb_cArray, "-", rb_ary_diff, 1);
    rb_define_method(rb_cArray, "&", rb_ary_and, 1);
    rb_define_method(rb_cArray, "|", rb_ary_or, 1);

    rb_define_method(rb_cArray, "max", rb_ary_max, -1);
    rb_define_method(rb_cArray, "min", rb_ary_min, -1);

    rb_define_method(rb_cArray, "uniq", rb_ary_uniq, 0);
    rb_define_method(rb_cArray, "uniq!", rb_ary_uniq_bang, 0);
    rb_define_method(rb_cArray, "compact", rb_ary_compact, 0);
    rb_define_method(rb_cArray, "compact!", rb_ary_compact_bang, 0);
    rb_define_method(rb_cArray, "flatten", rb_ary_flatten, -1);
    rb_define_method(rb_cArray, "flatten!", rb_ary_flatten_bang, -1);
    rb_define_method(rb_cArray, "count", rb_ary_count, -1);
    rb_define_method(rb_cArray, "shuffle!", rb_ary_shuffle_bang, -1);
    rb_define_method(rb_cArray, "shuffle", rb_ary_shuffle, -1);
    rb_define_method(rb_cArray, "sample", rb_ary_sample, -1);
    rb_define_method(rb_cArray, "cycle", rb_ary_cycle, -1);
    rb_define_method(rb_cArray, "permutation", rb_ary_permutation, -1);
    rb_define_method(rb_cArray, "combination", rb_ary_combination, 1);
    rb_define_method(rb_cArray, "repeated_permutation", rb_ary_repeated_permutation, 1);
    rb_define_method(rb_cArray, "repeated_combination", rb_ary_repeated_combination, 1);
    rb_define_method(rb_cArray, "product", rb_ary_product, -1);

    rb_define_method(rb_cArray, "take", rb_ary_take, 1);
    rb_define_method(rb_cArray, "take_while", rb_ary_take_while, 0);
    rb_define_method(rb_cArray, "drop", rb_ary_drop, 1);
    rb_define_method(rb_cArray, "drop_while", rb_ary_drop_while, 0);
    rb_define_method(rb_cArray, "bsearch", rb_ary_bsearch, 0);
    rb_define_method(rb_cArray, "bsearch_index", rb_ary_bsearch_index, 0);
    rb_define_method(rb_cArray, "any?", rb_ary_any_p, 0);
    rb_define_method(rb_cArray, "dig", rb_ary_dig, -1);
    rb_define_method(rb_cArray, "sum", rb_ary_sum, -1);

    id_random = rb_intern("random");
    id_div = rb_intern("div");
}
