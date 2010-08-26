/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <grp.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <netdb.h>
#include <mntent.h>
#include <private/android_filesystem_config.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

/** Thread-specific state for the stubs functions
 **/

pthread_once_t   the_once = PTHREAD_ONCE_INIT;
pthread_key_t    the_key;

typedef struct {
    struct passwd  passwd;
    struct group   group;
    char*          group_members[2];
    char           app_name_buffer[32];
    char           group_name_buffer[32];
} stubs_state_t;

static void
stubs_state_free( void*  _s )
{
    stubs_state_t*  s = _s;
    free(s);
}

static stubs_state_t*
stubs_state_alloc( void )
{
    stubs_state_t*  s = calloc(1, sizeof *s);

    if (s != NULL) {
        s->group.gr_mem = s->group_members;
    }
    return s;
}

static void __stubs_key_init(void)
{
    pthread_key_create( &the_key, stubs_state_free );
}

static stubs_state_t*
__stubs_state(void)
{
    stubs_state_t*  s;

    pthread_once(&the_once, __stubs_key_init);
    s = pthread_getspecific(the_key);
    if (s == NULL) {
        s = stubs_state_alloc();
        if (s == NULL) {
            errno = ENOMEM;  /* just in case */
        } else {
            if ( pthread_setspecific(the_key, s) != 0 ) {
                stubs_state_free(s);
                errno = ENOMEM;
                s     = NULL;
            }
        }
    }
    return s;
}

static struct passwd*
android_iinfo_to_passwd( struct passwd          *pw,
                         struct android_id_info *iinfo )
{
    pw->pw_name  = (char*)iinfo->name;
    pw->pw_uid   = iinfo->aid;
    pw->pw_gid   = iinfo->aid;
    pw->pw_dir   = "/";
    pw->pw_shell = "/system/bin/sh";
    return pw;
}

static struct group*
android_iinfo_to_group( struct group *gr,
                        struct android_id_info *iinfo )
{
    gr->gr_name   = (char*) iinfo->name;
    gr->gr_gid    = iinfo->aid;
    gr->gr_mem[0] = gr->gr_name;
    gr->gr_mem[1] = NULL;
    return gr;
}

static struct passwd *
android_id_to_passwd( struct passwd *pw, unsigned id)
{
    struct android_id_info *iinfo = android_ids;
    unsigned n;
    for (n = 0; n < android_id_count; n++) {
        if (iinfo[n].aid == id) {
            return android_iinfo_to_passwd(pw, iinfo + n);
        }
    }
    return NULL;
}

static struct passwd*
android_name_to_passwd(struct passwd *pw, const char *name)
{
    struct android_id_info *iinfo = android_ids;
    unsigned n;
    for (n = 0; n < android_id_count; n++) {
        if (!strcmp(iinfo[n].name, name)) {
            return android_iinfo_to_passwd(pw, iinfo + n);
        }
    }
    return NULL;
}

static struct group*
android_id_to_group( struct group *gr, unsigned id )
{
    struct android_id_info *iinfo = android_ids;
    unsigned n;
    for (n = 0; n < android_id_count; n++) {
        if (iinfo[n].aid == id) {
            return android_iinfo_to_group(gr, iinfo + n);
        }
    }
    return NULL;
}

static struct group*
android_name_to_group( struct group *gr, const char *name )
{
    struct android_id_info *iinfo = android_ids;
    unsigned n;
    for (n = 0; n < android_id_count; n++) {
        if (!strcmp(iinfo[n].name, name)) {
            return android_iinfo_to_group(gr, iinfo + n);
        }
    }
    return NULL;
}

/* translate a user/group name like app_1234 into the
 * corresponding user/group id (AID_APP + 1234)
 * returns 0 and sets errno to ENOENT in case of error
 */
static unsigned
app_id_from_name( const char*  name )
{
    unsigned long  id;
    char*          end;

    if (memcmp(name, "app_", 4) != 0 || !isdigit(name[4]))
        goto FAIL;

    id = strtoul(name+4, &end, 10);
    if (*end != '\0')
        goto FAIL;

    id += AID_APP;

    /* check for overflow and that the value can be
     * stored in our 32-bit uid_t/gid_t */
    if (id < AID_APP || (unsigned)id != id)
        goto FAIL;

    return (unsigned)id;

FAIL:
    errno = ENOENT;
    return 0;
}

/* translate a uid into the corresponding app_<uid>
 * passwd structure (sets errno to ENOENT on failure)
 */
static struct passwd*
app_id_to_passwd(uid_t  uid, stubs_state_t*  state)
{
    struct passwd*  pw = &state->passwd;

    if (uid < AID_APP) {
        errno = ENOENT;
        return NULL;
    }

    snprintf( state->app_name_buffer, sizeof state->app_name_buffer,
              "app_%u", uid - AID_APP );

    pw->pw_name  = state->app_name_buffer;
    pw->pw_dir   = "/data";
    pw->pw_shell = "/system/bin/sh";
    pw->pw_uid   = uid;
    pw->pw_gid   = uid;

    return pw;
}

/* translate a gid into the corresponding app_<gid>
 * group structure (sets errno to ENOENT on failure)
 */
static struct group*
app_id_to_group(gid_t  gid, stubs_state_t*  state)
{
    struct group*  gr = &state->group;

    if (gid < AID_APP) {
        errno = ENOENT;
        return NULL;
    }

    snprintf(state->group_name_buffer, sizeof state->group_name_buffer,
             "app_%u", gid - AID_APP);

    gr->gr_name   = state->group_name_buffer;
    gr->gr_gid    = gid;
    gr->gr_mem[0] = gr->gr_name;
    gr->gr_mem[1] = NULL;

    return gr;
}


struct passwd*
getpwuid(uid_t uid)
{
    stubs_state_t*  state = __stubs_state();
    struct passwd*  pw;

    if (state == NULL)
        return NULL;

    pw = &state->passwd;

    if ( android_id_to_passwd(pw, uid) != NULL )
        return pw;

    return app_id_to_passwd(uid, state);
}

struct passwd*
getpwnam(const char *login)
{
    stubs_state_t*  state = __stubs_state();

    if (state == NULL)
        return NULL;

    if (android_name_to_passwd(&state->passwd, login) != NULL)
        return &state->passwd;

    return app_id_to_passwd( app_id_from_name(login), state );
}

int
getgrouplist (const char *user, gid_t group,
              gid_t *groups, int *ngroups)
{
    if (*ngroups < 1) {
        *ngroups = 1;
        return -1;
    }
    groups[0] = group;
    return (*ngroups = 1);
}

char*
getlogin(void)
{
    struct passwd *pw = getpwuid(getuid());

    if(pw) {
        return pw->pw_name;
    } else {
        return NULL;
    }
}

struct group*
getgrgid(gid_t gid)
{
    stubs_state_t*  state = __stubs_state();
    struct group*   gr;

    if (state == NULL)
        return NULL;

    gr = android_id_to_group(&state->group, gid);
    if (gr != NULL)
        return gr;

    return app_id_to_group(gid, state);
}

struct group*
getgrnam(const char *name)
{
    stubs_state_t*  state = __stubs_state();
    unsigned        id;

    if (state == NULL)
        return NULL;

    if (android_name_to_group(&state->group, name) != 0)
        return &state->group;

    return app_id_to_group( app_id_from_name(name), state );
}


struct netent* getnetbyname(const char *name)
{
    fprintf(stderr, "FIX ME! implement getgrnam() %s:%d\n", __FILE__, __LINE__);
    return NULL;
}

void endpwent(void)
{
}

struct mntent* getmntent(FILE* f)
{
    fprintf(stderr, "FIX ME! implement getmntent() %s:%d\n", __FILE__, __LINE__);
    return NULL;
}

char* ttyname(int fd)
{
    fprintf(stderr, "FIX ME! implement ttyname() %s:%d\n", __FILE__, __LINE__);
    return NULL;
}

int ttyname_r(int fd, char *buf, size_t buflen)
{
    fprintf(stderr, "FIX ME! implement ttyname_r() %s:%d\n", __FILE__, __LINE__);
    return -ERANGE;
}

struct netent *getnetbyaddr(uint32_t net, int type)
{
    fprintf(stderr, "FIX ME! implement %s() %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
    return NULL;
}

struct protoent *getprotobyname(const char *name)
{
    fprintf(stderr, "FIX ME! implement %s() %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
    return NULL;
}

struct protoent *getprotobynumber(int proto)
{
    fprintf(stderr, "FIX ME! implement %s() %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
    return NULL;
}

char* getusershell(void)
{
    fprintf(stderr, "FIX ME! implement %s() %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
    return NULL;
}

void setusershell(void)
{
    fprintf(stderr, "FIX ME! implement %s() %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
}

void endusershell(void)
{
    fprintf(stderr, "FIX ME! implement %s() %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
}

