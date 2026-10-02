/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef FVL_FORTICLIENT_VID_PLUGIN_H_
#define FVL_FORTICLIENT_VID_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct fvl_forticlient_vid_plugin_t fvl_forticlient_vid_plugin_t;

/**
 * Application-owned charon plugin for FortiGate IKEv2 SSO compatibility.
 * Adds FortiClient Vendor IDs to outbound initiator IKE_SA_INIT and
 * removes N(EAP_ONLY) and N(MSG_ID_SYN_SUP) from the first outbound
 * initiator IKE_AUTH, then adds one empty N(INITIAL_CONTACT), private
 * Notify 0xF100 (license-info), a 16-attribute empty CFG_REQUEST
 * matching golden FortiClient, and repositions 0xF100 immediately after
 * INITIAL_CONTACT and before AUTH/CFG_REQUEST. Incoming CFG_REPLY
 * split-include narrows CHILD_SA remote TS when FortiGate leaves TSr
 * at 0.0.0.0/0. Loaded only by the private runtime.
 */
struct fvl_forticlient_vid_plugin_t {
	plugin_t plugin;
};

#endif /* FVL_FORTICLIENT_VID_PLUGIN_H_ */
