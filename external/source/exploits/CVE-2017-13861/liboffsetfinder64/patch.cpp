//
//  patch.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 09.03.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include "patch.hpp"

using namespace tihmstar::patchfinder64;

patch::patch(loc_t location, const void *patch, size_t patchSize, void(*slidefunc)(class patch *patch, uint64_t slide)) : _location(location), _patchSize(patchSize), _slidefunc(slidefunc){
    _patch = malloc(_patchSize);
    memcpy((void*)_patch, patch, _patchSize);
    _slideme = (_slidefunc) ? true : false;
}

patch::patch(const patch& cpy) : _location(cpy._location), _patchSize(cpy._patchSize){
    _patch = malloc(_patchSize);
    memcpy((void*)_patch, cpy._patch, _patchSize);
    _slidefunc = cpy._slidefunc;
    _slideme = cpy._slideme;
}

void patch::slide(uint64_t slide){
    if (!_slideme)
        return;
    printf("sliding with %p\n",(void*)slide);
    _slidefunc(this,slide);
    _slideme = false; //only slide once
}

patch::~patch(){
    free((void*)_patch);
}
