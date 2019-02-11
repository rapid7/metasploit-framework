int InitPatchfinder(uint64_t base, const char *filename);
void TermPatchfinder(void);

// Fun part
uint64_t Find_allproc(void);
uint64_t Find_add_x0_x0_0x40_ret(void);
uint64_t Find_copyout(void);
uint64_t Find_bzero(void);
uint64_t Find_bcopy(void);
uint64_t Find_rootvnode(void);
uint64_t Find_trustcache(void);
uint64_t Find_amficache(void);
uint64_t Find_OSBoolean_True(void);
uint64_t Find_OSBoolean_False(void);
uint64_t Find_zone_map_ref(void);
uint64_t Find_osunserializexml(void);
uint64_t Find_smalloc(void);
uint64_t Find_sbops(void);
uint64_t Find_bootargs(void);
