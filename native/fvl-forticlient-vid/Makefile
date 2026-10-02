# SPDX-License-Identifier: GPL-3.0-or-later
# Out-of-tree charon plugin. Headers come from fetched strongSwan 5.9.13
# source; the plugin links against the distro libcharon/libstrongswan.
PLUGIN_NAME = fvl-forticlient-vid
SONAME = libstrongswan-$(PLUGIN_NAME).so
ROOT ?= $(CURDIR)/../..
SS_SRC ?= $(ROOT)/downloads/strongswan-5.9.13

CC ?= gcc
CFLAGS ?= -O2 -fPIC -Wall -Wextra
CPPFLAGS += -include $(CURDIR)/config.h \
	-I$(CURDIR) \
	-I$(SS_SRC)/src/libstrongswan \
	-I$(SS_SRC)/src/libcharon \
	-I$(SS_SRC)/src/include
LDFLAGS ?= -shared -Wl,-z,relro,-z,now
LIBS ?= -L/usr/lib/ipsec -lcharon -lstrongswan
IPSEC_LIBDIR ?= /usr/lib/ipsec
CHECK_SYMBOLS ?= $(ROOT)/scripts/check-fvl-forticlient-vid-symbols.sh

.PHONY: all clean check-symbols

all: $(SONAME) check-symbols

$(SONAME): fvl_forticlient_vid_plugin.c fvl_forticlient_vid_plugin.h config.h
	@test -d "$(SS_SRC)/src/libcharon" || { \
		echo "error: strongSwan 5.9.13 headers not found at $(SS_SRC)" >&2; \
		echo "Run scripts/build-fvl-forticlient-vid.sh first." >&2; \
		exit 1; \
	}
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ fvl_forticlient_vid_plugin.c $(LIBS)

check-symbols: $(SONAME)
	@test -x "$(CHECK_SYMBOLS)" || { \
		echo "error: missing $(CHECK_SYMBOLS)" >&2; \
		exit 1; \
	}
	IPSEC_LIBDIR="$(IPSEC_LIBDIR)" "$(CHECK_SYMBOLS)" "$(CURDIR)/$(SONAME)"

clean:
	rm -f $(SONAME) *.o
