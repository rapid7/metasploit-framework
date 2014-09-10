#ifdef __ELF__
asm .pt_gnu_stack rw;
#endif
typedef uintptr_t VALUE;
static VALUE const_File;
static VALUE const_LinuxHeap;
VALUE rb_ary_new(void);
VALUE rb_ary_push(VALUE, VALUE);
extern VALUE *rb_cObject __attribute__((import));
VALUE rb_const_get(VALUE, VALUE);
void rb_define_method(VALUE, char*, VALUE(*)(), int);
VALUE rb_funcall(VALUE recv, unsigned int id, int nargs, ...);
VALUE rb_gv_get(const char*);
VALUE rb_intern(char*);
VALUE rb_ivar_get(VALUE, unsigned int);
VALUE rb_iv_get(VALUE, char*);
void *rb_method_node(VALUE, unsigned int);
VALUE rb_obj_as_string(VALUE);
VALUE rb_str_append(VALUE, VALUE);
VALUE rb_str_cat2(VALUE, const char*);
VALUE rb_str_new2(const char*);
VALUE rb_hash_aset(VALUE, VALUE, VALUE);
VALUE rb_hash_aref(VALUE, VALUE);
VALUE rb_uint2inum(VALUE);
VALUE rb_num2ulong(VALUE);
char *rb_string_value_ptr(VALUE*);


int printf(char*, ...);

static VALUE heap_entry(void *heap, VALUE idx, VALUE psz)
{
	if (psz == 4)
		return (VALUE)(((__int32*)heap)[idx]);
	return (VALUE)(((__int64*)heap)[idx]);
}

static VALUE m_LinuxHeap23scan_heap(VALUE self, VALUE vbase, VALUE vlen, VALUE ar)
{
	VALUE *heap;
	VALUE chunks;
	VALUE base = rb_num2ulong(vbase);
	VALUE len = vlen >> 1;
	VALUE sz, clen;
	VALUE page;
	VALUE psz = rb_iv_get(self, "@ptsz") >> 1;
	VALUE ptr = 0;

	chunks = rb_iv_get(self, "@chunks");
	page = rb_funcall(self, rb_intern("pagecache"), 2, vbase, vlen);
	heap = rb_string_value_ptr(&page);

	sz = heap_entry(heap, 1, psz);
	if (heap_entry(heap, 0, psz) != 0 || (sz & 1) != 1)
		return 4;

	base += 8;

	for (;;) {
		clen = sz & -8;
		ptr += clen/psz;
		if (ptr >= len/psz || clen == 0)
			break;
		
		sz = heap_entry(heap, ptr+1, psz);
		if (sz & 1)
			rb_hash_aset(chunks, rb_uint2inum(base), ((clen-psz)<<1)|1);
		base += clen;
	}

	rb_funcall(self, rb_intern("del_fastbin"), 1, ar);

	return 4;
}



static VALUE m_LinuxHeap23scan_heap_xr(VALUE self, VALUE vbase, VALUE vlen)
{
	VALUE *heap;
	VALUE chunks, xrchunksto, xrchunksfrom;
	VALUE psz = rb_iv_get(self, "@ptsz") >> 1;
	VALUE base = rb_num2ulong(vbase) + 2*psz;
	VALUE len = vlen >> 1;
	VALUE sz, clen;
	VALUE page;

	chunks = rb_iv_get(self, "@chunks");
	xrchunksto = rb_iv_get(self, "@xrchunksto");
	xrchunksfrom = rb_iv_get(self, "@xrchunksfrom");
	page = rb_funcall(self, rb_intern("pagecache"), 2, vbase, vlen);
	heap = rb_string_value_ptr(&page);

	sz = heap_entry(heap, 1, psz);
	if (heap_entry(heap, 0, psz) != 0 || (sz & 1) != 1)
		return 4;

	/* re-walk the heap, simpler than iterating over @chunks */
	VALUE ptr = 0;
	VALUE ptr0, ptrl;
	for (;;) {
		clen = sz & -8;
		ptr0 = ptr+2;
		ptrl = clen/psz-1;
		ptr += clen/psz;
		if (ptr >= len/psz || clen == 0)
			break;
		
		sz = heap_entry(heap, ptr+1, psz);
		if ((sz & 1) &&
		    ((rb_hash_aref(chunks, rb_uint2inum(base))|4) != 4)) {
			VALUE tabto = 0;
			VALUE tabfrom;
			while (ptrl--) {
				VALUE p = heap_entry(heap, ptr0++, psz);
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
		base += clen;
	}
	return 4;
}



static void do_init_once(void)
{
	const_LinuxHeap = rb_const_get(*rb_cObject, rb_intern("Metasm"));
	const_LinuxHeap = rb_const_get(const_LinuxHeap, rb_intern("LinuxHeap"));
	rb_define_method(const_LinuxHeap, "scan_heap", m_LinuxHeap23scan_heap, 3);
	rb_define_method(const_LinuxHeap, "scan_heap_xr", m_LinuxHeap23scan_heap_xr, 2);
}



int Init_compiled_heapscan_lin __attribute__((export))(void)
{
	do_init_once();
	return 0;
}
