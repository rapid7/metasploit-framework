#ifndef INC_USER_MANAGEMENT_H
#define INC_USER_MANAGEMENT_H

DWORD request_incognito_add_user(Remote *remote, Packet *packet);
DWORD request_incognito_add_group_user(Remote *remote, Packet *packet);
DWORD request_incognito_add_localgroup_user(Remote *remote, Packet *packet);

#endif