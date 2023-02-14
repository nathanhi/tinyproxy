/* tinyproxy - A fast light-weight HTTP proxy
 * Copyright (C) 1998 Steven Young <sdyoung@miranda.org>
 * Copyright (C) 1999-2005 Robert James Kaes <rjkaes@users.sourceforge.net>
 * Copyright (C) 2000 Chris Lightfoot <chris@ex-parrot.com>
 * Copyright (C) 2002 Petr Lampa <lampa@fit.vutbr.cz>
 * Copyright (C) 2009 Michael Adam <obnox@samba.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * Routines for handling the list of upstream proxies.
 */

#include "upstream.h"
#include "heap.h"
#include "log.h"
#include "base64.h"
#include "basicauth.h"
#include <proxy.h>

#ifdef UPSTREAM_SUPPORT
const char *
proxy_type_name(proxy_type type)
{
    switch(type) {
        case PT_NONE: return "none";
        case PT_HTTP: return "http";
        case PT_SOCKS4: return "socks4";
        case PT_SOCKS5: return "socks5";
        case PT_PAC: return "pac";
        default: return "unknown";
    }
}


const char* upstream_build_error_string(enum upstream_build_error ube) {
        static const char *emap[] = {
        [UBE_SUCCESS] = "",
        [UBE_OOM] = "Unable to allocate memory in upstream_build()",
        [UBE_USERLEN] = "User / pass in upstream config too long",
        [UBE_EDOMAIN] = "Nonsense upstream none rule: empty domain",
        [UBE_INVHOST] = "Nonsense upstream rule: invalid host or port",
        [UBE_INVPARAMS] = "Nonsense upstream rule: invalid parameters",
        [UBE_NETMASK] = "Nonsense upstream rule: failed to parse netmask",
        [UBE_NOLIBPROXY] = "This version of tinyproxy is compiled without support for libproxy and cannot handle PAC URLs",
        [UBE_INVPACURL] = "Invalid PAC upstream URL",
        };
        return emap[ube];
}

/**
 * Construct an upstream struct from input data.
 */
static struct upstream *upstream_build (const char *host, int port, char *domain,
                        const char *user, const char *pass,
			proxy_type type, enum upstream_build_error *ube)
{
        struct upstream *up;

        *ube = UBE_SUCCESS;
        up = (struct upstream *) safemalloc (sizeof (struct upstream));
        if (!up) {
                *ube = UBE_OOM;
                return NULL;
        }

        up->type = type;
        up->target.type = HST_NONE;
        up->host = up->ua.user = up->pass = NULL;
        if (user) {
                if (type == PT_HTTP) {
                        char b[BASE64ENC_BYTES((256+2)-1) + 1];
                        ssize_t ret;
                        ret = basicauth_string(user, pass, b, sizeof b);
                        if (ret == 0) {
                                *ube = UBE_USERLEN;
                                return NULL;
                        }
                        up->ua.authstr = safestrdup (b);
                } else {
                        up->ua.user = safestrdup (user);
                        up->pass = safestrdup (pass);
                }
        }

        if (domain == NULL) {
                if (type == PT_NONE) {
                e_nonedomain:;
                        *ube = UBE_EDOMAIN;
                        goto fail;
                }
                if (type == PT_PAC) {
                e_invpacurl:;
                        *ube = UBE_INVPACURL;
                        goto fail;
                }
                if (!host || !host[0] || port < 1) {
                        *ube = UBE_INVHOST;
                        goto fail;
                }

                up->host = safestrdup (host);
                up->port = port;

                log_message (LOG_INFO, "Added upstream %s %s:%d for [default]",
                             proxy_type_name(type), host, port);
        } else {
                if (type == PT_NONE) {
                        if (!domain[0]) goto e_nonedomain;
                } else if (type == PT_PAC) {
                        if (!domain[0]) goto e_invpacurl;
                        return up;
                } else {
                        if (!host || !host[0] || !domain[0]) {
                                *ube = UBE_INVPARAMS;
                                goto fail;
                        }
                        up->host = safestrdup (host);
                        up->port = port;
                }

                if (hostspec_parse(domain, &up->target)
                   || up->target.type == HST_NONE) {
                        *ube = UBE_NETMASK;
                        goto fail;
                }

                if (type == PT_NONE)
                        log_message (LOG_INFO, "Added upstream none for %s", domain);
                else
                        log_message (LOG_INFO, "Added upstream %s %s:%d for %s",
                                     proxy_type_name(type), host, port, domain);
        }

        return up;

fail:
        safefree (up->ua.user);
        safefree (up->pass);
        safefree (up->host);
        if(up->target.type == HST_STRING)
                safefree (up->target.address.string);
        safefree (up);

        return NULL;
}

/*
 * Add an entry to the upstream list
 */
enum upstream_build_error upstream_add (
                   const char *host, int port, char *domain,
                   const char *user, const char *pass,
                   proxy_type type, struct upstream **upstream_list)
{
        struct upstream *up;
        enum upstream_build_error ube;

        up = upstream_build (host, port, domain, user, pass, type, &ube);
        if (up == NULL) {
                return ube;
        }

        if (up->target.type == HST_NONE) {   /* always add default to end */
                struct upstream *tmp = *upstream_list;

                while (tmp) {
                        if (tmp->target.type == HST_NONE) {
                                log_message (LOG_WARNING,
                                             "Duplicate default upstream");
                                goto upstream_cleanup;
                        }

                        if (!tmp->next) {
                                up->next = NULL;
                                tmp->next = up;
                                return ube;
                        }

                        tmp = tmp->next;
                }
        }

        up->next = *upstream_list;
        *upstream_list = up;

        return ube;

upstream_cleanup:
        safefree (up->host);
        if(up->target.type == HST_STRING)
                safefree (up->target.address.string);
        safefree (up);

        return ube;
}

/*
 * Check if a host is in the upstream list
 */
struct upstream *upstream_get (char *host, struct upstream *up)
{
        int i;
        char **proxies;
        pxProxyFactory *pf = NULL;
        struct upstream *libproxy_up = NULL;
        libproxy_up = (struct upstream *) safemalloc (sizeof (struct upstream));
        while (up) {
                fprintf(stderr, "UPSTREAM \"type\": %d (%d)\n", up->type, PT_PAC);
                fprintf(stderr, "request_for_host: %s\n", host);
                if (up->type == PT_PAC) {
                        pf = px_proxy_factory_new();
                        proxies = px_proxy_factory_get_proxies(pf, "http://proxy.example.com");
                        for (i=0; proxies[i]; i++) {
                                if (!strncmp("direct", proxies[i], 6)) {
                                        fprintf(stderr, "PAC: %s is DIRECT\n", host);
                                        continue;
                                } else if (!strncmp("http", proxies[i], 4)) {
                                        /* TODO: safe_free if next==NULL */
                                        proxies[i] = proxies[i]+7;
                                        fprintf(stderr, "UPSTREAM PAC: %s\n", proxies[i]);
                                        libproxy_up->next = NULL;
                                        libproxy_up->host = "127.0.0.1";
                                        libproxy_up->port = 8080;
                                        libproxy_up->type = PT_HTTP;
                                } else {
                                        /* TODO: Add support for other protos */
                                        break;
                                }
                        }
                        px_proxy_factory_free(pf);
                        /*safe_free(proxies);*/
                        if (libproxy_up != NULL) {
                                up = libproxy_up;
                                break;
                        }
                }

                if (up->target.type == HST_NONE)
                        break;

                if (hostspec_match(host, &up->target))
                        break;

                up = up->next;
        }

        if (up && (!up->host))
                up = NULL;

        if (up)
                log_message (LOG_INFO, "Found upstream proxy %s %s:%d for %s",
                             proxy_type_name(up->type), up->host, up->port, host);
        else
                log_message (LOG_INFO, "No upstream proxy for %s", host);

        return up;
}

void free_upstream_list (struct upstream *up)
{
        while (up) {
                struct upstream *tmp = up;
                up = up->next;
                if(tmp->target.type == HST_STRING)
                        safefree (tmp->target.address.string);
                safefree (tmp->host);
                safefree (tmp);
        }
}

#endif
