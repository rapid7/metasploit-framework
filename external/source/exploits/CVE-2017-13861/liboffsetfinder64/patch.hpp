//
//  patch.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 09.03.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef patch_hpp
#define patch_hpp

#include "common.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

namespace tihmstar {
    namespace patchfinder64{
        
        class patch{
            bool _slideme;
            void(*_slidefunc)(class patch *patch, uint64_t slide);
        public:
            const loc_t _location;
            const void *_patch;
            const size_t _patchSize;
            patch(loc_t location, const void *patch, size_t patchSize, void(*slidefunc)(class patch *patch, uint64_t slide) = NULL);
            patch(const patch& cpy);
            void slide(uint64_t slide);
            ~patch();
        };
        
    }
}

#endif /* patch_hpp */
