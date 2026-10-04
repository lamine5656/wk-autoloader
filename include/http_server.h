/* Shared HTTP server state — declared in http_server.c, referenced by main.c. */
#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <stdatomic.h>
#include "file_registry.h"

/* Pre-inflate and cache the large JS entries so the first AppCache request
 * never pays the slow byte-at-a-time puff cost on the PS5. Called once after
 * the MHD daemon starts, before the browser begins caching. */
void pre_inflate_js_files(void);

/* Shared flags — defined in http_server.c, read/written by main.c. */
extern atomic_int http_keep_running;
extern atomic_int install_completed;
extern atomic_int webkit_data_cleared;

#endif /* HTTP_SERVER_H */
