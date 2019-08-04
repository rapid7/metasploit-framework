//
//  all_liboffsetfinder.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 09.03.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef all_liboffsetfinder_h
#define all_liboffsetfinder_h

#ifdef DEBUG
#define OFFSETFINDER64_VERSION_COMMIT_COUNT "Debug"
#define OFFSETFINDER64_VERSION_COMMIT_SHA "Build: " __DATE__ " " __TIME__

#include <stdint.h>
static uint64_t BIT_RANGE(uint64_t v, int begin, int end) { return ((v)>>(begin)) % (1 << ((end)-(begin)+1)); }
static uint64_t BIT_AT(uint64_t v, int pos){ return (v >> pos) % 2; }

#else
#define BIT_RANGE(v,begin,end) ( ((v)>>(begin)) % (1 << ((end)-(begin)+1)) )
#define BIT_AT(v,pos) ( (v >> pos) % 2 )
#endif

#define info(a ...) ({printf(a),printf("\n");})
#define log(a ...) ({if (dbglog) printf(a),printf("\n");})
#define warning(a ...) ({if (dbglog) printf("[WARNING] "), printf(a),printf("\n");})
#define error(a ...) ({printf("[Error] "),printf(a),printf("\n");})

#define safeFree(ptr) ({if (ptr) free(ptr),ptr=NULL;})

#define reterror(err) throw tihmstar::exception(__LINE__, err, LOCAL_FILENAME)
#define retcustomerror(err,except) throw tihmstar::except(__LINE__, err, LOCAL_FILENAME)
#define assure(cond) if ((cond) == 0) throw tihmstar::exception(__LINE__, "assure failed", LOCAL_FILENAME)
#define doassure(cond,code) do {if (!(cond)){(code);assure(cond);}} while(0)
#define retassure(cond, err) if ((cond) == 0) throw tihmstar::exception(__LINE__,err,LOCAL_FILENAME)
#define assureclean(cond) do {if (!(cond)){clean();assure(cond);}} while(0)


#endif /* all_liboffsetfinder_h */
