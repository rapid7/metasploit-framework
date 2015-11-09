/*
	ruby-kissfft: a simple ruby module embedding the Kiss FFT library
	Copyright (C) 2009-2010 Rapid7, Inc - H D Moore <hdm[at]metasploit.com>
	
	Derived from "psdpng.c" from the KissFFT tools directory
	Copyright (C) 2003-2006 Mark Borgerding
*/

#include "ruby.h"


#include <stdlib.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "kiss_fft.h"
#include "kiss_fftr.h"

static VALUE rb_cKissFFT;

#define KISS_VERSION "1.2.8-1.0"


static VALUE
rbkiss_s_version(VALUE class)
{
	return rb_str_new2(KISS_VERSION);	
}

#define CHECKNULL(p) if ( (p)==NULL ) do { fprintf(stderr,"CHECKNULL failed @ %s(%d): %s\n",__FILE__,__LINE__,#p );exit(1);} while(0)

static VALUE
rbkiss_s_fftr(VALUE class, VALUE r_nfft, VALUE r_rate, VALUE r_buckets, VALUE r_data)
{
	kiss_fftr_cfg cfg=NULL;
	kiss_fft_scalar *tbuf;
	kiss_fft_cpx *fbuf;
	float *mag2buf;
	int i;
	int avgctr=0;
	int nrows=0;

	int nfft;
	int rate;
	int navg;
	int nfreqs;

	int inp_len;
	int inp_idx;

	// Result set
	VALUE res;
	VALUE tmp;
	VALUE set;
	res = rb_ary_new();

	if(TYPE(r_nfft) != T_FIXNUM) {
		return Qnil;
	}
	nfft=NUM2INT(r_nfft);

	if(TYPE(r_rate) != T_FIXNUM) {
		return Qnil;
	}
	rate=NUM2INT(r_rate);

	if(TYPE(r_buckets) != T_FIXNUM) {
		return Qnil;
	}
	navg=NUM2INT(r_buckets);

	if(TYPE(r_data) != T_ARRAY) {
		return Qnil;
	}

	if(RARRAY_LEN(r_data) == 0) {
		return Qnil;
	}

	if(TYPE(RARRAY_PTR(r_data)[0]) != T_FIXNUM ) {
		return Qnil;
	}	

	nfreqs=nfft/2+1;

	CHECKNULL( cfg=kiss_fftr_alloc(nfft,0,0,0) );
	CHECKNULL( tbuf=(kiss_fft_scalar*)malloc(sizeof(kiss_fft_scalar)*(nfft + 2) ) );
	CHECKNULL( fbuf=(kiss_fft_cpx*)malloc(sizeof(kiss_fft_cpx)*(nfft + 2)) );
	CHECKNULL( mag2buf=(float*)malloc(sizeof(float)*(nfft + 2) ));	

	memset(mag2buf,0,sizeof(mag2buf)*nfreqs);

	inp_len = RARRAY_LEN(r_data);
	inp_idx = 0;

	while(inp_idx < inp_len) {

		// Fill tbuf with nfft samples
		for(i=0;i<nfft;i++) {
			if(inp_idx + i >= inp_len) {
				tbuf[i] = 0;
			} else {
				if(TYPE(RARRAY_PTR(r_data)[ inp_idx + i ]) != T_FIXNUM) {
					tbuf[i] = 0;
				} else {
					tbuf[i] = NUM2INT( RARRAY_PTR(r_data)[ inp_idx + i ] );
				}
			}
		}


		/* do FFT */
		kiss_fftr(cfg,tbuf,fbuf);

		for (i=0;i<nfreqs;++i) {
			mag2buf[i] += fbuf[i].r * fbuf[i].r + fbuf[i].i * fbuf[i].i;
		}

		if (++avgctr == navg) {
			float eps = 1;
			avgctr=0;
			++nrows;

			// RESULTS
			set = rb_ary_new();
			for (i=0;i<nfreqs;++i) {
				float pwr = 10 * log10( mag2buf[i] / navg + eps );
				tmp = rb_ary_new();
				rb_ary_push(tmp, rb_float_new( (float)i * ( ( (float)rate / 2) / (float)nfreqs) ));
				rb_ary_push(tmp, rb_float_new( pwr));
				rb_ary_push(set, tmp);
			}
			rb_ary_push(res, set);
			memset(mag2buf,0,sizeof(mag2buf[0])*nfreqs);
		}
		inp_idx += nfft;
	}

	free(cfg);
	free(tbuf);	
	free(fbuf);
	free(mag2buf);
	return(res);		
}

void
Init_kissfft()
{
    // KissFFT
    rb_cKissFFT = rb_define_class("KissFFT", rb_cObject);
    rb_define_module_function(rb_cKissFFT, "version", rbkiss_s_version, 0);
    rb_define_module_function(rb_cKissFFT, "fftr", rbkiss_s_fftr, 4);
}
