typedef uintptr_t VALUE;
static VALUE const_WindowsHeap;
VALUE rb_ary_new(void);
VALUE rb_ary_push(VALUE, VALUE);
extern VALUE *rb_cObject __attribute__((import));
VALUE rb_const_get(VALUE, VALUE);
void rb_define_method(VALUE, char*, VALUE(*)(), int);
VALUE rb_funcall(VALUE recv, unsigned int id, int nargs, ...);
VALUE rb_intern(char*);
VALUE rb_iv_get(VALUE, char*);
VALUE rb_hash_aset(VALUE, VALUE, VALUE);
VALUE rb_hash_aref(VALUE, VALUE);
VALUE rb_uint2inum(VALUE);
VALUE rb_num2ulong(VALUE);
char *rb_string_value_ptr(VALUE*);
VALUE rb_gc_enable(void);
VALUE rb_gc_disable(void);

#include "winheap.h"

#define INT2FIX(i) (((i) << 1) | 1)

static VALUE m_WindowsHeap23scan_heap_segment(VALUE self, VALUE vfirst, VALUE vlen)
{
	char *heapcpy;
	struct _HEAP_ENTRY *he;
	VALUE chunks;
	VALUE first = rb_num2ulong(vfirst);
	VALUE len = vlen >> 1;
	VALUE off;
	VALUE page;
	VALUE sz;

	chunks = rb_iv_get(self, "@chunks");
	page = rb_funcall(self, rb_intern("pagecache"), 2, vfirst, INT2FIX(len));
	heapcpy = rb_string_value_ptr(&page);

	rb_gc_disable();
	off = 0;
	while (off < len) {
		he = heapcpy + off;
		if (he->Flags & 1) {
			sz = (VALUE)he->Size*8;
			if (sz > he->UnusedBytes)
				sz -= he->UnusedBytes;
			else
				sz = 0;
			rb_hash_aset(chunks, rb_uint2inum(first+off+sizeof(*he)), INT2FIX(sz));
		}
		off += he->Size*8;
	}
	rb_gc_enable();

	return 4;
}

static VALUE m_WindowsHeap23scan_heap_segment_xr(VALUE self, VALUE vfirst, VALUE vlen)
{
	char *heapcpy;
	struct _HEAP_ENTRY *he;
	VALUE chunks;
	VALUE first = rb_num2ulong(vfirst);
	VALUE len = vlen >> 1;
	VALUE off;
	VALUE page;
	VALUE xrchunksto = rb_iv_get(self, "@xrchunksto");
	VALUE xrchunksfrom = rb_iv_get(self, "@xrchunksfrom");

	chunks = rb_iv_get(self, "@chunks");
	page = rb_funcall(self, rb_intern("pagecache"), 2, vfirst, INT2FIX(len));
	heapcpy = rb_string_value_ptr(&page);

	rb_gc_disable();
	off = 0;
	VALUE *ptr0, base, cklen;
	while (off < len) {
		he = heapcpy + off;
		// address of the chunk
		base = first + off + sizeof(*he);
		if ((he->Flags & 1) && 
		    (((cklen = rb_hash_aref(chunks, rb_uint2inum(base)))|4) != 4)) {
			cklen /= 2*sizeof(void*);	// /2 == FIX2INT
			// pointer to the data for the chunk in our copy of the heap from pagecache
			ptr0 = (VALUE*)(heapcpy + off + sizeof(*he));
			VALUE tabto = 0;
			VALUE tabfrom;
			while (cklen--) {
				VALUE p = *ptr0++;
				//if (p == base)	// ignore self-references
				//	continue;
				if ((rb_hash_aref(chunks, rb_uint2inum(p))|4) != 4) {
					if (!tabto) {
						tabto = rb_ary_new();
						rb_hash_aset(xrchunksto, rb_uint2inum(base), tabto);
					}
					rb_ary_push(tabto, rb_uint2inum(p));

					tabfrom = rb_hash_aref(xrchunksfrom, rb_uint2inum(p));
					if ((tabfrom|4) == 4) {
						tabfrom = rb_ary_new();
						rb_hash_aset(xrchunksfrom, rb_uint2inum(p), tabfrom);
					}
					rb_ary_push(tabfrom, rb_uint2inum(base));
				}
			}
		}
		if (!he->Size)
			break;
		off += he->Size*8;
	}
	rb_gc_enable();

	return 4;
}

static void do_init_once(void)
{
	const_WindowsHeap = rb_const_get(*rb_cObject, rb_intern("Metasm"));
	const_WindowsHeap = rb_const_get(const_WindowsHeap, rb_intern("WindowsHeap"));
	rb_define_method(const_WindowsHeap, "scan_heap_segment", m_WindowsHeap23scan_heap_segment, 2);
	rb_define_method(const_WindowsHeap, "scan_heap_segment_xr", m_WindowsHeap23scan_heap_segment_xr, 2);
}

int Init_compiled_heapscan_win __attribute__((export))(void)
{
	do_init_once();
	return 0;
}
