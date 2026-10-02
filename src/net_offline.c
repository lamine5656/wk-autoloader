/*
 * Offline network bring-up (Relapse KASLR leak support without Wi-Fi/cable).
 *
 * The Relapse chain leaks the kernel base through an AF_ROUTE routing
 * socket: it writes an RTM_GET request whose RTA_DST must be an interface
 * address and reads the leaked kernel pointer out of the reply. Before
 * doing so it enumerates interfaces with netgetiflist and aborts with
 * "kaslr: no interface has an address" when none has an IPv4 address —
 * which happens whenever Wi-Fi is off and/or no cable is connected, even
 * though no packet ever leaves the console.
 *
 * This module runs in the privileged payload process, before the browser
 * opens: it finds an interface that exists but has no IPv4 address and
 * assigns it a synthetic private address (10.77.0.2/24) and brings it up,
 * so the leak can proceed fully offline. Interfaces that already have an
 * address (real Wi-Fi/Ethernet setups) are never touched.
 *
 * The relapse copy also carries a loopback fallback (see
 * tools/patch_relapse_offline.py) for the corner case where no interface
 * could be configured at all.
 */

#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "wkali.h"

/* Synthetic configuration. The values only need to be valid enough for the
 * kernel to install an interface route that RTM_GET can look up; nothing is
 * ever sent through them. 10.77.x.x is deep in private space and extremely
 * unlikely to collide with a home LAN. */
#define WKALI_OFFLINE_ADDR 10, 77, 0, 2
#define WKALI_OFFLINE_BCAST 10, 77, 0, 255
#define WKALI_OFFLINE_MASK 255, 255, 255, 0

/* Candidate interface names, most likely first (PS5 is FreeBSD-based:
 * eth*/wlan* are the usual Sony names, the rest are generic driver names).
 * A name without a driver simply fails SIOCGIFFLAGS (ENXIO) and is skipped. */
static const char *const wk_if_candidates[] = {
    "eth0", "eth1", "wlan0", "wlan1",
    "wm0", "em0", "igb0", "ix0", "ixl0", "re0", "rl0",
    "alc0", "ale0", "msk0", "bge0", "bce0", "dc0", "fxp0",
    "ue0", "axe0", "ure0", "usb0", "en0", NULL
};

static void wk_fill_sin(struct sockaddr *sa, unsigned char a, unsigned char b,
                        unsigned char c, unsigned char d) {
    struct sockaddr_in *sin = (struct sockaddr_in *)sa;
    unsigned char ip[4];

    memset(sin, 0, sizeof(*sin));
    ip[0] = a;
    ip[1] = b;
    ip[2] = c;
    ip[3] = d;
    sin->sin_len = (unsigned char)sizeof(*sin);
    sin->sin_family = AF_INET;
    memcpy(&sin->sin_addr, ip, 4);
}

/* Returns 1 when `name` currently has a non-zero IPv4 address. */
static int wk_if_has_address(int s, const char *name) {
    struct ifreq ifr;
    struct sockaddr_in *sin;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFADDR, &ifr) != 0)
        return 0;
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    return sin->sin_family == AF_INET && sin->sin_addr.s_addr != 0;
}

int wkali_ensure_interface_address(void) {
    int s, i;
    const char *name;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        wkali_log("[WKALI] net-offline: socket(AF_INET, SOCK_DGRAM) failed\n");
        return -1;
    }

    /* Pass 1 — is a real configuration already in place? Leave it untouched. */
    for (i = 0; (name = wk_if_candidates[i]) != NULL; i++) {
        if (wk_if_has_address(s, name)) {
            wkali_log("[WKALI] net-offline: %s already has an IPv4 address, network untouched\n",
                      name);
            close(s);
            return 0;
        }
    }

    /* Pass 2 — no address anywhere: bring an interface up, synthetically. */
    for (i = 0; (name = wk_if_candidates[i]) != NULL; i++) {
        struct ifreq ifr;
        struct ifaliasreq ifra;

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
        if (ioctl(s, SIOCGIFFLAGS, &ifr) != 0)
            continue; /* interface does not exist / driver not loaded */

        ifr.ifr_flags |= IFF_UP;
        if (ioctl(s, SIOCSIFFLAGS, &ifr) != 0) {
            wkali_log("[WKALI] net-offline: SIOCSIFFLAGS(UP) failed on %s\n", name);
            continue;
        }

        memset(&ifra, 0, sizeof(ifra));
        strncpy(ifra.ifra_name, name, IFNAMSIZ - 1);
        wk_fill_sin(&ifra.ifra_addr, WKALI_OFFLINE_ADDR);
        wk_fill_sin(&ifra.ifra_broadaddr, WKALI_OFFLINE_BCAST);
        wk_fill_sin(&ifra.ifra_mask, WKALI_OFFLINE_MASK);
        if (ioctl(s, SIOCAIFADDR, &ifra) != 0) {
            wkali_log("[WKALI] net-offline: SIOCAIFADDR failed on %s\n", name);
            continue;
        }

        if (wk_if_has_address(s, name)) {
            wkali_log("[WKALI] net-offline: %s configured with 10.77.0.2/24 — relapse leaks KASLR with no network\n",
                      name);
            close(s);
            return 0;
        }
    }

    close(s);
    wkali_log("[WKALI] net-offline: no interface could be configured — relapse will try the loopback fallback\n");
    return -1;
}
