//
//  common.h
//  liboffsetfinder64
//
//  Created by tihmstar on 09.03.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef common_h
#define common_h

#include <stdint.h>
#include <vector>

namespace tihmstar{
    namespace patchfinder64{
        typedef uint8_t* loc_t;
        typedef uint64_t offset_t;
        
        struct text_t{
            patchfinder64::loc_t map;
            size_t size;
            patchfinder64::loc_t base;
            bool isExec;
        };
        using segment_t = std::vector<tihmstar::patchfinder64::text_t>;
    }
}

#endif /* common_h */
