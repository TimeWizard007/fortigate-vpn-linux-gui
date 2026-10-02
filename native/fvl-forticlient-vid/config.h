/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Minimal config.h so this out-of-tree plugin can compile against
 * strongSwan 5.9.13 headers. Matches Ubuntu 24.04 charon ABI; it is
 * not a patched strongSwan build. Must be passed with gcc -include. */
#ifndef CONFIG_H
#define CONFIG_H

#define CONFIG_H_INCLUDED 1

/* Ubuntu 24.04 glibc provides explicit_bzero(3). Distro libstrongswan
 * 5.9.13 is built with HAVE_EXPLICIT_BZERO, so it does not export
 * memwipe_noinline. This out-of-tree plugin must match that, or
 * inlined memwipe()/chunk_clear() will fail at charon dlopen. */
#define _DEFAULT_SOURCE 1
#define HAVE_EXPLICIT_BZERO 1

#define VERSION "5.9.13"
#define PREFIX "/usr"
#define IPSEC_DIR "/usr/lib/ipsec"
#define PLUGINDIR "/usr/lib/ipsec/plugins"
#define IPSEC_PIDDIR "/run"
#define DEV_RANDOM "/dev/random"
#define DEV_URANDOM "/dev/urandom"

#define HAVE_DLFCN_H 1
#define HAVE_STDINT_H 1
#define HAVE_STDBOOL_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_PARAM_H 1
#define HAVE_PTHREAD 1
#define HAVE_SYSLOG 1
#define HAVE_CLOCK_GETTIME 1
#define HAVE_BACKTRACE 1
#define HAVE_DLADDR 1
#define HAVE_PRCTL 1
#define HAVE_LINUX_SOCKET_H 1
#define HAVE_SIGWAITINFO 1
#define HAVE_CLOSEFROM 1
#define HAVE_QSORT_R 1
#define HAVE_QSORT_R_GNU 1
#define HAVE_PTHREAD_RWLOCK_INIT 1
#define HAVE_PTHREAD_SPIN_INIT 1
#define HAVE_PTHREAD_CONDATTR_INIT 1
#define HAVE_CONDATTR_CLOCK_MONOTONIC 1
#define HAVE_SEM_TIMEDWAIT 1
#define HAVE_ALLOCA_H 1
#define CAPABILITIES 1
#define CAPABILITIES_NATIVE 1
#define DEBUG 1
#define USE_IKEV1
#define USE_IKEV2

#endif /* CONFIG_H */
