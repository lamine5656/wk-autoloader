/*
 * HTTP Server - serves the cached frontend files from the generated file
 * registry and handles the /install route (installs the homescreen app once
 * the cache is complete and shuts the server down).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include <microhttpd.h>

#include "wkali.h"
#include "http_server.h"
#include "file_registry.h"
#include "inflate.h"
#include "app_installer.h"
#include "webkit_cleaner.h"
#include "simulate_corrupt.h"

/* CORS is intentionally `*`: the installer page is also served from the PC
 * host (manuals.playstation.net over HTTPS), which cross-origin XHRs this
 * on-console server (http://127.0.0.1:18182) for /version and
 * /install. The server binds 127.0.0.1 only and lives for seconds.
 * Do not restrict unless that flow changes. */
#define CORS_ORIGIN "*"

/* Shared flag — set to 0 by a successful /install or /exit, read by the main loop.
 * atomic so the store in a connection thread is visible to the main loop. */
atomic_int http_keep_running = 1;

/* Set to 1 only when /install succeeds so shutdown knows to notify success. */
atomic_int install_completed = 0;

/* Set to 1 by a successful /clear-webkit-data, read by the main loop to
 * re-launch the browser. atomic so the store in a connection thread is
 * visible to the main loop. */
atomic_int webkit_data_cleared = 0;

/* Active exploit chosen for this installation session ("poops", "relapse", or "umtx2"). */
static char active_exploit[16] = {0};

static void add_cors_headers(struct MHD_Response *resp) {
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", CORS_ORIGIN);
}

static const FileEntry *registry_lookup(const char *url) {
    if (strcmp(url, ROUTE_INDEX) == 0)
        return file_registry_find(ROUTE_INDEX_HTML);
    return file_registry_find(url);
}

/* ── Inflated-entry cache ──────────────────────────────────────────────
 * puff (src/inflate.c, vendored) inflates byte-at-a-time and is slow:
 * re-inflating the large registry entries on every request added visible
 * latency to first load (AppCache downloads everything) and to every
 * repair/retry pass. MHD serves requests from a thread pool, so the
 * cache is guarded by a mutex; the inflate itself runs outside the lock
 * so parallel first downloads of different files still overlap. Only
 * entries >= WKALI_CACHE_MIN_SIZE are cached (small ones inflate in
 * microseconds) and the total is capped to keep installer-process memory
 * bounded; anything not cached takes the per-request inflate path.
 * Cached buffers are shared and must never be freed by the request
 * handler — every downstream mutation (manifest filter, prompt-page
 * copy, test hook) already copies first and only frees MUST_FREE
 * buffers. */
#define WKALI_CACHE_MIN_SIZE (8u * 1024u)
#define WKALI_CACHE_MAX_BYTES (12u * 1024u * 1024u)
#define WKALI_CACHE_MAX_ENTRIES 16

static pthread_mutex_t infl_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static const FileEntry *infl_cache_entries[WKALI_CACHE_MAX_ENTRIES];
static unsigned char *infl_cache_bufs[WKALI_CACHE_MAX_ENTRIES];
static size_t infl_cache_count;
static size_t infl_cache_bytes;

/* Forward declarations (placed before any use, for C99 strict mode). */
static unsigned char *inflated_for(const FileEntry *entry);
static void pre_inflate_js_files(void);

/* Pre-inflate and cache the large JS entries so the first AppCache request
 * never pays the slow byte-at-a-time puff cost on the PS5. Called once after
 * the MHD daemon starts, before the browser begins caching. */
static void pre_inflate_js_files(void) {
    unsigned int i;
    for (i = 0; i < file_registry_count; i++) {
        const FileEntry *e = &file_registry[i];
        /* Only JS that is worth caching (>= 8 Ko). Small JS inflate in
         * microseconds and is cheaper to pay on demand than to burn cache
         * slots on tiny files. */
        if (e->compressed && e->orig_size >= WKALI_CACHE_MIN_SIZE &&
            strcmp(e->content_type, "application/javascript") == 0) {
            (void)inflated_for(e); /* warms the cache */
        }
    }
}

/* Returns the shared inflated buffer for a registry entry, inflating and
 * caching it on first use. Returns NULL when the entry is not worth
 * caching (small), the cache budget is exhausted, or inflate failed —
 * the caller then takes the per-request inflate path. */
static unsigned char *inflated_for(const FileEntry *entry) {
    unsigned char *buf = NULL;
    size_t i;
    int eligible;

    pthread_mutex_lock(&infl_cache_lock);
    for (i = 0; i < infl_cache_count; i++) {
        if (infl_cache_entries[i] == entry) {
            pthread_mutex_unlock(&infl_cache_lock);
            return infl_cache_bufs[i];
        }
    }
    eligible = (entry->orig_size >= WKALI_CACHE_MIN_SIZE &&
                infl_cache_count < WKALI_CACHE_MAX_ENTRIES &&
                infl_cache_bytes + entry->orig_size <= WKALI_CACHE_MAX_BYTES);
    pthread_mutex_unlock(&infl_cache_lock);

    if (!eligible)
        return NULL;

    {
        unsigned char *fresh = malloc(entry->orig_size + 1);
        unsigned long destlen = entry->orig_size;
        unsigned long sourcelen = entry->size;

        if (!fresh)
            return NULL;
        if (puff(fresh, &destlen, entry->data, &sourcelen) != 0) {
            free(fresh);
            return NULL;
        }
        fresh[destlen] = '\0';

        pthread_mutex_lock(&infl_cache_lock);
        /* Another connection may have stored this entry while we inflated. */
        for (i = 0; i < infl_cache_count; i++) {
            if (infl_cache_entries[i] == entry) {
                buf = infl_cache_bufs[i];
                break;
            }
        }
        if (!buf && infl_cache_count < WKALI_CACHE_MAX_ENTRIES &&
            infl_cache_bytes + entry->orig_size <= WKALI_CACHE_MAX_BYTES) {
            infl_cache_entries[infl_cache_count] = entry;
            infl_cache_bufs[infl_cache_count] = fresh;
            infl_cache_count++;
            infl_cache_bytes += entry->orig_size;
            wkali_log("[WKALI] inflate cache: +%u bytes (%u total)\n",
                      (unsigned)entry->orig_size, (unsigned)infl_cache_bytes);
            buf = fresh;
            fresh = NULL;
        }
        pthread_mutex_unlock(&infl_cache_lock);

        if (fresh) {
            /* Cache full (or raced): let the caller inflate per request. */
            free(fresh);
            return NULL;
        }
        return buf;
    }
}

enum MHD_Result http_on_request(void *cls, struct MHD_Connection *conn,
                                const char *url, const char *method,
                                const char *version, const char *upload_data,
                                size_t *upload_data_size, void **con_cls) {

    (void)cls;
    (void)version;
    (void)upload_data;
    (void)upload_data_size;
    float fw = 0.0f;
    char fw_str[16] = {0};
    const char *ua = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "User-Agent");
    if (ua) {
        const char *ps5 = strstr(ua, "PlayStation 5/");
        if (ps5) {
            size_t i = 0;
            const char *p = ps5 + 14;
            while ((p[i] >= '0' && p[i] <= '9') || p[i] == '.') {
                if (i < sizeof(fw_str) - 1) fw_str[i] = p[i];
                i++;
            }
            fw_str[i < sizeof(fw_str) ? i : sizeof(fw_str) - 1] = '\0';
            fw = strtof(fw_str, NULL);
        }
    }
    const char *fw_arg = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "fw");
    if (fw == 0.0f && fw_arg) {
        strncpy(fw_str, fw_arg, sizeof(fw_str) - 1);
        fw = strtof(fw_arg, NULL);
    }
    const char *exploit_arg = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "exploit");
    if (exploit_arg && (strcmp(exploit_arg, "poops") == 0 ||
                        strcmp(exploit_arg, "relapse") == 0 ||
                        strcmp(exploit_arg, "umtx2") == 0)) {
        strncpy(active_exploit, exploit_arg, sizeof(active_exploit) - 1);
        active_exploit[sizeof(active_exploit) - 1] = '\0';
    }


    /* Handle CORS Preflight (OPTIONS) */
    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response *resp =
            MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
        add_cors_headers(resp);
        MHD_add_response_header(resp, "Access-Control-Allow-Methods",
                                "GET, OPTIONS");
        MHD_add_response_header(resp, "Access-Control-Allow-Headers",
                                "Content-Type");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    /* ── Initial call for a new request ────────────────────── */
    if (*con_cls == NULL) {
        *con_cls = (void *)1;
        return MHD_YES;
    }

    struct MHD_Response *resp = NULL;
    int http_status = MHD_HTTP_OK;

    if (strcmp(url, ROUTE_INSTALL) == 0) {
        /* Called by the installer page once the AppCache is fully cached. The
         * homescreen app is only installed/updated now — never on startup —
         * so a shortcut is never created for a partial cache. On failure the
         * server stays up and the page tells the user to re-run the installer. */
        int err = wkali_install_app_if_needed();
        if (err == 0) {
            wkali_log("[WKALI] App installed. Stopping server...\n");
            resp = MHD_create_response_from_buffer(strlen("OK"), (void *)"OK",
                                                   MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(resp, "Content-Type", "text/plain");
            http_status = MHD_HTTP_OK;
            atomic_store(&install_completed, 1);
            atomic_store(&http_keep_running, 0);
        } else {
            wkali_log("[WKALI] App install failed (%d). Staying up.\n", err);
            const char *fail = "Install failed";
            resp = MHD_create_response_from_buffer(strlen(fail), (void *)fail,
                                                   MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(resp, "Content-Type", "text/plain");
            http_status = MHD_HTTP_INTERNAL_SERVER_ERROR;
        }
    } else if (strcmp(url, ROUTE_EXIT) == 0) {
        wkali_log("[WKALI] Exit requested by client. Stopping server...\n");
        resp = MHD_create_response_from_buffer(2, (void *)"OK",
                                               MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "text/plain");
        http_status = MHD_HTTP_OK;
        atomic_store(&http_keep_running, 0);
    } else if (strcmp(url, ROUTE_VERSION) == 0) {
        resp = MHD_create_response_from_buffer(strlen(WKAL_FULL_VERSION),
                                               (void *)WKAL_FULL_VERSION,
                                               MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "text/plain");
        extern int sceUserServiceGetForegroundUser(int *);
        int uid = -1;
        if (sceUserServiceGetForegroundUser(&uid) == 0 && uid > 0) {
            char uid_hdr[32];
            snprintf(uid_hdr, sizeof(uid_hdr), "%08x", (unsigned int)uid);
            MHD_add_response_header(resp, "X-User-Id", uid_hdr);
        }
    } else if (strcmp(url, "/logs") == 0) {
        const char *pos_str = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "pos");
        size_t pos = 0;
        if (pos_str) pos = (size_t)strtoull(pos_str, NULL, 10);

        char *logs = malloc(16384 + 64);
        if (logs) {
            size_t copied = wkali_wait_logs(&pos, logs, 16384);
            /* Append the new pos as an HTTP header so the client knows */
            resp = MHD_create_response_from_buffer(copied, (void *)logs, MHD_RESPMEM_MUST_FREE);
            char pos_hdr[64];
            snprintf(pos_hdr, sizeof(pos_hdr), "%zu", pos);
            MHD_add_response_header(resp, "X-Log-Pos", pos_hdr);
            MHD_add_response_header(resp, "Content-Type", "text/plain");
        } else {
            const char *oom = "500 Internal Server Error\n";
            resp = MHD_create_response_from_buffer(strlen(oom), (void *)oom, MHD_RESPMEM_PERSISTENT);
        }
    } else if (strcmp(url, ROUTE_CLEAR_WEBKIT_DATA) == 0) {
        int err = wkali_clear_webkit_data();
        if (err == 0) {
            active_exploit[0] = '\0';
            wkali_log("[WKALI] WebKit data cleared successfully. Will re-launch browser.\n");
            simulate_on_clear_success();
            resp = MHD_create_response_from_buffer(2, (void *)"OK",
                                                   MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(resp, "Content-Type", "text/plain");
            http_status = MHD_HTTP_OK;
            atomic_store(&webkit_data_cleared, 1);
        } else {
            wkali_log("[WKALI] WebKit data clear failed.\n");
            const char *fail = "Clear failed";
            resp = MHD_create_response_from_buffer(strlen(fail), (void *)fail,
                                                   MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(resp, "Content-Type", "text/plain");
            http_status = MHD_HTTP_INTERNAL_SERVER_ERROR;
        }
    } else if (strcmp(url, "/selected_exploit") == 0 ||
               (strlen(url) >= 17 && strcmp(url + strlen(url) - 17, "/selected_exploit") == 0)) {
        const char *sel = exploit_arg ? exploit_arg :
                          (active_exploit[0] ? active_exploit :
                          (fw > 0.0f && fw <= 5.50f ? "umtx2" : "relapse"));
        resp = MHD_create_response_from_buffer(strlen(sel), (void *)sel,
                                               MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "text/plain");
        http_status = MHD_HTTP_OK;
    } else {
        const FileEntry *entry = registry_lookup(url);
        if (entry) {
            if (strcmp(url, "/") != 0 && strcmp(url, "/index.html") != 0 && strcmp(url, "/logs") != 0) {
                wkali_log("[HTTP] Serving %s (size: %zu)\n", url, entry->size);
            }
            void *payload = (void *)entry->data;
            size_t payload_size = entry->size;
            enum MHD_ResponseMemoryMode mem_mode = MHD_RESPMEM_PERSISTENT;
            unsigned char *decompressed = NULL;

            if (entry->compressed) {
                /* L92 speed fast path: serve a previously inflated copy of
                 * this entry from the shared cache (PERSISTENT) — no
                 * per-request puff, no malloc. Falls back below when the
                 * entry is small, the cache budget is used up, or inflation
                 * failed. */
                unsigned char *cached = inflated_for(entry);
                if (cached) {
                    payload = cached;
                    payload_size = entry->orig_size;
                    mem_mode = MHD_RESPMEM_PERSISTENT;
                } else {
                /* Inflate the raw-DEFLATE blob (src/inflate.c, vendored puff)
                 * into a fresh heap buffer; MHD frees it with MUST_FREE. */
                decompressed = malloc(entry->orig_size + 1);
                if (!decompressed) {
                    const char *oom = "503 Out of Memory\n";
                    resp = MHD_create_response_from_buffer(strlen(oom),
                                                           (void *)oom,
                                                           MHD_RESPMEM_PERSISTENT);
                    MHD_add_response_header(resp, "Content-Type", "text/plain");
                    http_status = MHD_HTTP_SERVICE_UNAVAILABLE;
                    add_cors_headers(resp);
                    enum MHD_Result ret = MHD_queue_response(conn, http_status, resp);
                    MHD_destroy_response(resp);
                    return ret;
                }
                unsigned long destlen = entry->orig_size;
                unsigned long sourcelen = entry->size;
                int err = puff(decompressed, &destlen, entry->data, &sourcelen);
                if (err != 0) {
                    free(decompressed);
                    const char *bad = "500 Inflate Error\n";
                    resp = MHD_create_response_from_buffer(strlen(bad),
                                                           (void *)bad,
                                                           MHD_RESPMEM_PERSISTENT);
                    MHD_add_response_header(resp, "Content-Type", "text/plain");
                    http_status = MHD_HTTP_INTERNAL_SERVER_ERROR;
                    add_cors_headers(resp);
                    enum MHD_Result ret = MHD_queue_response(conn, http_status, resp);
                    MHD_destroy_response(resp);
                    return ret;
                }
                decompressed[destlen] = '\0';
                payload = decompressed;
                payload_size = destlen;
                mem_mode = MHD_RESPMEM_MUST_FREE;
                } /* end per-request inflate fallback */
            }

            /* When on firmware supported by both Poops and Relapse (7.00 - 12.00),
               the installer page must ask the user which exploit to install BEFORE
               proceeding with caching. If no exploit has been chosen yet, strip
               manifest="..." from index.html so WebKit does NOT start caching.
               Note: 9.05 and 11.40 are supported ONLY by Poops (not Relapse). */
            int is_poops_only = (strcmp(fw_str, "9.05") == 0 || strcmp(fw_str, "11.40") == 0);
            int is_dual_fw = (!is_poops_only && fw >= 7.00f && fw <= 12.00f) ||
                             (fw == 0.0f && strcmp(WKALI_FORCE_EXPLOIT, "auto") == 0);
            int prompt_user = (strcmp(WKALI_FORCE_EXPLOIT, "auto") == 0) && is_dual_fw &&
                              (exploit_arg == NULL) && (active_exploit[0] == '\0');

            if ((strcmp(url, ROUTE_INDEX) == 0 || strcmp(url, ROUTE_INDEX_HTML) == 0) && prompt_user) {
                char *copy = malloc(payload_size + 1);
                if (copy) {
                    memcpy(copy, payload, payload_size);
                    copy[payload_size] = '\0';
                    if (mem_mode == MHD_RESPMEM_MUST_FREE) {
                        free(payload);
                    }
                    payload = copy;
                    mem_mode = MHD_RESPMEM_MUST_FREE;

                    char *manifest_attr = strstr((char *)payload, " manifest=\"/cache.appcache\"");
                    if (manifest_attr) {
                        memset(manifest_attr, ' ', strlen(" manifest=\"/cache.appcache\""));
                    }
                }
            }

            /* Dynamically strip incompatible exploit files from the cache manifest */
            if (strcmp(url, ROUTE_CACHE_MANIFEST) == 0) {
                const char *chosen = NULL;
                if (strcmp(WKALI_FORCE_EXPLOIT, "auto") != 0) {
                    chosen = WKALI_FORCE_EXPLOIT;
                } else if (exploit_arg) {
                    chosen = exploit_arg;
                } else if (active_exploit[0] != '\0') {
                    chosen = active_exploit;
                } else if (fw > 0.0f && fw <= 5.50f) {
                    chosen = "umtx2";
                } else if (fw > 12.00f) {
                    chosen = "relapse";
                } else {
                    chosen = "relapse";
                }

                wkali_log("[WKALI] AppCache manifest: caching %s exploit\n", chosen);

                char *filtered = malloc(payload_size + 1);
                if (filtered) {
                    char *src = (char *)payload;
                    char *dst = filtered;
                    size_t remaining = payload_size;

                    while (remaining > 0) {
                        char *nl = memchr(src, '\n', remaining);
                        size_t line_len = nl ? (size_t)(nl - src) + 1 : remaining;

                        char line[1024];
                        size_t copy_len = line_len < sizeof(line) ? line_len : sizeof(line) - 1;
                        memcpy(line, src, copy_len);
                        line[copy_len] = '\0';

                        int keep = 1;
                        if (strcmp(chosen, "umtx2") == 0) {
                            if (strstr(line, "/slopkit/") || strstr(line, "/relapse/")) keep = 0;
                        } else if (strcmp(chosen, "poops") == 0) {
                            if (strstr(line, "/umtx2/") || strstr(line, "/relapse/")) keep = 0;
                        } else if (strcmp(chosen, "relapse") == 0) {
                            if (strstr(line, "/umtx2/") || strstr(line, "/slopkit/")) keep = 0;
                        }

                        if (keep) {
                            memcpy(dst, src, line_len);
                            dst += line_len;
                        }

                        src += line_len;
                        remaining -= line_len;
                    }

                    if (mem_mode == MHD_RESPMEM_MUST_FREE) free(payload);
                    payload = filtered;
                    payload_size = dst - filtered;
                    mem_mode = MHD_RESPMEM_MUST_FREE;
                }
            }


            /* Test simulation hook (no-op unless compiled with SIMULATE=1|2) */
            simulate_corrupt_manifest(url, &payload, &payload_size, &mem_mode);

            resp = MHD_create_response_from_buffer(payload_size, payload,
                                                   mem_mode);
            MHD_add_response_header(resp, "Content-Type", entry->content_type);
            if (strcmp(url, ROUTE_CACHE_MANIFEST) == 0 ||
                strstr(entry->content_type, "text/html") != NULL) {
                MHD_add_response_header(resp, "Cache-Control",
                                        "no-cache, must-revalidate");
            }
        } else {
            const char *not_found = "404 Not Found\n";
            resp = MHD_create_response_from_buffer(strlen(not_found),
                                                   (void *)not_found,
                                                   MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(resp, "Content-Type", "text/plain");
            http_status = MHD_HTTP_NOT_FOUND;
        }
    }

    if (!resp)
        return MHD_NO;

    add_cors_headers(resp);
    enum MHD_Result ret = MHD_queue_response(conn, http_status, resp);
    MHD_destroy_response(resp);

    return ret;
}
