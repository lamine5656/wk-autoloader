/*
 * Offline network bring-up (Relapse KASLR leak support without Wi-Fi/cable).
 *
 * The Relapse chain leaks the kernel base through an AF_ROUTE routing
 * socket: it writes an RTM_GET request whose RTA_DST must be an address
 * that has a route, and reads the leaked kernel pointer out of the reply.
 * Before doing so it enumerates interfaces with netgetiflist and aborts
 * with "kaslr: no interface has an address" when none has an IPv4 address
 * — which happens whenever Wi-Fi is off and/or no cable is connected, even
 * though no packet ever leaves the console.
 *
 * This module runs in the privileged payload process, before the browser
 * opens: it finds an interface that exists but has no IPv4 address and
 * assigns it a synthetic private address (10.77.0.2/24) and brings it up,
 * so the leak can proceed fully offline. Interfaces that already have an
 * address (real Wi-Fi/Ethernet setups) are never touched.
 *
 * Assigning the address alone is not always enough: the PS5 kernel can
 * skip the connected-route installation on SIOCAIFADDR, and a routing
 * lookup without a matching route is rejected (ESRCH) — the leak then dies
 * with "kaslr: routing socket rejected the request". So after configuring
 * the interface this module verifies the lookup with the very RTM_GET the
 * exploit performs and, when it is rejected, installs a simulated network:
 * a host route for the synthetic address (anchored on the always-present
 * loopback route), a subnet route, and a default route through it. The
 * leak is route-independent — it reads a kernel return address from the
 * reply — so any resolvable destination makes it work.
 *
 * The relapse copy also carries a loopback retry fallback (see
 * tools/patch_relapse_offline.py) as the last-resort safety net.
 */

#include <errno.h>
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
 * eth0/wlan0 are the usual Sony names, the rest are generic driver names).
 * A name without a driver simply fails SIOCGIFFLAGS (ENXIO) and is skipped. */
static const char *const wk_if_candidates[] = {
    "eth0", "eth1", "wlan0", "wlan1",
    "wm0", "em0", "igb0", "ix0", "ixl0", "re0", "rl0",
    "alc0", "ale0", "msk0", "bge0", "bce0", "dc0", "fxp0",
    "ue0", "axe0", "ure0", "usb0", "en0", NULL
};

/* --- routing messages (PS5 layout, as observed by the exploit itself) ---- */

/* The PS5 kernel's routing messages use a 152-byte header: the exploit
 * writes its RTA_DST sockaddr at offset 152 of its RTM_GET, so sockaddrs
 * start there for every rt_msghdr variant. */
#define WK_RTM_HDR_LEN 152
#define WK_RTM_GET_LEN 496 /* 152 + dst(88) + author(256), same as relapse */
#define WK_RTM_ADD_LEN 208 /* 152 + dst(16) + gateway(16) + netmask(16) */

#define WK_RTM_ADD 0x1
#define WK_RTM_GET 0x4
#define WK_RTA_DST 0x1
#define WK_RTA_GATEWAY 0x2
#define WK_RTA_NETMASK 0x4
#define WK_RTA_AUTHOR 0x40
#define WK_RTF_UP 0x1
#define WK_RTF_GATEWAY 0x2
#define WK_RTF_HOST 0x4
#define WK_RTF_STATIC 0x800

/* BSD routing domain; defined in sys/socket.h on FreeBSD, guarded in case
 * the SDK's headers omit it (same value the exploit hardcodes). */
#ifndef AF_ROUTE
#define AF_ROUTE 17
#endif

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

static void wk_put_u32(unsigned char *p, unsigned int v) {
    memcpy(p, &v, sizeof(v));
}

/* Build an RTM_ADD: header + DST/GATEWAY/NETMASK sockaddrs in RTA index
 * order starting at the 152-byte header. */
static void wk_build_rtm_add(unsigned char *msg, unsigned int msglen, int seq,
                             const unsigned char dst4[4],
                             const unsigned char gw4[4],
                             const unsigned char mask4[4],
                             unsigned int addrs, unsigned int flags) {
    memset(msg, 0, msglen);
    msg[0] = (unsigned char)(msglen & 0xff);
    msg[1] = (unsigned char)((msglen >> 8) & 0xff);
    msg[2] = 5; /* RTM_VERSION */
    msg[3] = WK_RTM_ADD;
    wk_put_u32(&msg[8], flags);      /* rtm_flags */
    wk_put_u32(&msg[12], addrs);     /* rtm_addrs */
    wk_put_u32(&msg[20], (unsigned int)seq); /* rtm_seq */
    wk_fill_sin((struct sockaddr *)&msg[WK_RTM_HDR_LEN],
                dst4[0], dst4[1], dst4[2], dst4[3]);
    wk_fill_sin((struct sockaddr *)&msg[WK_RTM_HDR_LEN + 16],
                gw4[0], gw4[1], gw4[2], gw4[3]);
    wk_fill_sin((struct sockaddr *)&msg[WK_RTM_HDR_LEN + 32],
                mask4[0], mask4[1], mask4[2], mask4[3]);
}

/* Mirror of relapse's leakKernelBase() RTM_GET (same length, same addrs,
 * same 88-byte dst sockaddr at 152, same AF_INET6 author at 240): the
 * kernel resolves the lookup synchronously inside write(), so a negative
 * return means no route covers the destination and the KASLR leak would
 * abort with "routing socket rejected the request". */
static int wk_route_lookup_ok(int rs, const unsigned char ip4[4]) {
    unsigned char msg[WK_RTM_GET_LEN];

    memset(msg, 0, sizeof(msg));
    msg[0] = (unsigned char)(sizeof(msg) & 0xff);
    msg[1] = (unsigned char)((sizeof(msg) >> 8) & 0xff);
    msg[2] = 5; /* RTM_VERSION */
    msg[3] = WK_RTM_GET;
    wk_put_u32(&msg[12], WK_RTA_DST | WK_RTA_AUTHOR);
    wk_put_u32(&msg[20], 0x1234); /* rtm_seq */
    msg[152] = 88;                /* DST_LEN, same as relapse */
    msg[153] = 2;                 /* AF_INET */
    wk_put_u32(&msg[156], ((unsigned int)ip4[3] << 24) |
                              ((unsigned int)ip4[2] << 16) |
                              ((unsigned int)ip4[1] << 8) |
                              (unsigned int)ip4[0]);
    msg[240] = 255; /* author sockaddr: AF_INET6, rest zero — same as relapse */
    msg[241] = 28;  /* AF_INET6 */
    return write(rs, msg, sizeof(msg)) >= 0;
}

/* The kernel echoes processed messages back to the sender's routing socket
 * (SO_USELOOPBACK is on by default); drain the acks so later lookups on the
 * same socket see a clean queue. */
static void wk_drain_rtm(int rs) {
    unsigned char buf[512];
    int i;

    for (i = 0; i < 8; i++) {
        if (recv(rs, buf, sizeof(buf), MSG_DONTWAIT) <= 0)
            break;
    }
}

/* Simulate a connected network in the routing table. Gateways are added in
 * dependency order, because the kernel refuses a gateway it cannot resolve:
 * the loopback address (whose connected route always exists) anchors the
 * host route, the host route anchors the subnet route, and the subnet
 * anchors the default route. Nothing is ever sent through any of them. */
static void wk_simulate_network(void) {
    static const unsigned char self_ip[4] = {10, 77, 0, 2};
    static const unsigned char net_ip[4] = {10, 77, 0, 0};
    static const unsigned char mask24[4] = {255, 255, 255, 0};
    static const unsigned char mask32[4] = {255, 255, 255, 255};
    static const unsigned char zero4[4] = {0, 0, 0, 0};
    static const unsigned char lo4[4] = {127, 0, 0, 1};
    unsigned char msg[WK_RTM_ADD_LEN];
    int rs;

    rs = socket(AF_ROUTE, SOCK_RAW, 0);
    if (rs < 0) {
        wkali_log("[WKALI] net-offline: routing socket unavailable — the JS loopback retry covers the leak\n");
        return;
    }

    if (wk_route_lookup_ok(rs, self_ip)) {
        wkali_log("[WKALI] net-offline: route lookup OK — KASLR leak will proceed\n");
        close(rs);
        return;
    }

    wkali_log("[WKALI] net-offline: kernel has no route for 10.77.0.2 — simulating a connected network\n");

    /* host route 10.77.0.2/32 via loopback: anchors every other gateway */
    wk_build_rtm_add(msg, sizeof(msg), 1, self_ip, lo4, mask32,
                     WK_RTA_DST | WK_RTA_GATEWAY | WK_RTA_NETMASK,
                     WK_RTF_UP | WK_RTF_HOST | WK_RTF_GATEWAY | WK_RTF_STATIC);
    if (write(rs, msg, sizeof(msg)) < 0)
        wkali_log("[WKALI] net-offline: host route add rejected (errno %d)\n", errno);

    /* subnet route 10.77.0.0/24 via 10.77.0.2 */
    wk_build_rtm_add(msg, sizeof(msg), 2, net_ip, self_ip, mask24,
                     WK_RTA_DST | WK_RTA_GATEWAY | WK_RTA_NETMASK,
                     WK_RTF_UP | WK_RTF_GATEWAY | WK_RTF_STATIC);
    if (write(rs, msg, sizeof(msg)) < 0)
        wkali_log("[WKALI] net-offline: subnet route add rejected (errno %d)\n", errno);

    /* default route 0.0.0.0/0 via 10.77.0.2 — every lookup now resolves */
    wk_build_rtm_add(msg, sizeof(msg), 3, zero4, self_ip, zero4,
                     WK_RTA_DST | WK_RTA_GATEWAY | WK_RTA_NETMASK,
                     WK_RTF_UP | WK_RTF_GATEWAY | WK_RTF_STATIC);
    if (write(rs, msg, sizeof(msg)) < 0)
        wkali_log("[WKALI] net-offline: default route add rejected (errno %d)\n", errno);

    wk_drain_rtm(rs);

    if (wk_route_lookup_ok(rs, self_ip))
        wkali_log("[WKALI] net-offline: simulated network up — route lookup OK, KASLR leak will proceed\n");
    else
        wkali_log("[WKALI] net-offline: lookup still rejected — the JS loopback retry covers the leak\n");
    close(rs);
}

/* --- interface bring-up --------------------------------------------------- */

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
            wk_simulate_network();
            close(s);
            return 0;
        }
    }

    close(s);
    wkali_log("[WKALI] net-offline: no interface could be configured — relapse will retry the leak via loopback\n");
    return -1;
}
