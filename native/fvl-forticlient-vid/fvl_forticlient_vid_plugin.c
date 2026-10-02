/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Private charon plugin for FortiGate IKEv2 SSO compatibility:
 * 1. Emit the three golden FortiClient Vendor IDs on outbound initiator
 *    IKE_SA_INIT only.
 * 2. Remove N(EAP_ONLY) (type 16417) and N(MSG_ID_SYN_SUP) (type 16420)
 *    from the first outbound initiator IKE_AUTH, then add one empty
 *    N(INITIAL_CONTACT) (type 16384) and private Notify 0xF100 / 61696
 *    whose data is the 0600 license-info blob (including the trailing
 *    NUL). Charon logs INITIAL_CONTACT as N(INIT_CONTACT).
 * 3. Replace the first IKE_AUTH CFG_REQUEST with the golden FortiClient
 *    16 empty request attributes (CP payload length 72). Log types and
 *    count only; never attribute values.
 * 4. Reposition the existing Notify 0xF100 immediately after
 *    INITIAL_CONTACT and before AUTH/CFG_REQUEST. Disable strongSwan
 *    payload sorting on this message so generate() does not move 0xF100
 *    after TSr.
 * 5. Omit the initiator AUTH payload from the first outbound initiator
 *    IKE_AUTH (MID 1) only. Later IKE_AUTH / EAP-MSCHAPv2 messages are
 *    not modified by this hook. IKEv2 SSO swanctl uses EAP-only local
 *    authentication plus remote PSK so child_create waits for
 *    COND_AUTHENTICATED instead of failing on an intermediate EAP
 *    IKE_AUTH that has no SA payload.
 * 6. Parse incoming CFG_REPLY for FortiGate split-include and DNS
 *    attributes. When TSr remains 0.0.0.0/0, replace the initiator's
 *    effective remote TS list on NARROW_INITIATOR_POST_NOAUTH
 *    (IKE_AUTH CHILD_SA) and NARROW_INITIATOR_POST_AUTH (rekey).
 *    Do not change CP16 request types. Log count, prefixes, DNS
 *    servers/domains. Never log secrets.
 *
 * Exact raw 16-byte Vendor ID values from FortiClient 7.4.8.2066. Do
 * not regenerate them from display strings. Do not log license-info
 * field values.
 */

#include "fvl_forticlient_vid_plugin.h"

#include <daemon.h>
#include <encoding/message.h>
#include <encoding/payloads/notify_payload.h>
#include <encoding/payloads/vendor_id_payload.h>
#include <encoding/payloads/cp_payload.h>
#include <encoding/payloads/configuration_attribute.h>
#include <attributes/attributes.h>
#include <crypto/proposal/proposal.h>
#include <collections/linked_list.h>
#include <library.h>
#include <bus/bus.h>
#include <threading/mutex.h>
#include <selectors/traffic_selector.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

typedef struct private_fvl_forticlient_vid_plugin_t private_fvl_forticlient_vid_plugin_t;

struct private_fvl_forticlient_vid_plugin_t {
	fvl_forticlient_vid_plugin_t public;
	listener_t listener;
	mutex_t *mutex;
	linked_list_t *unity_include;
	linked_list_t *rfc_subnet;
	linked_list_t *fortinet_540c;
	linked_list_t *local_lan;
	linked_list_t *dns_servers;
	linked_list_t *dns_domains;
	linked_list_t *selected;
	char source[32];
	bool split;
};

#define FVL_FORTINET_540C 21516
#define FVL_PREFIX_LEN 32
#define FVL_DOMAIN_LEN 128

/* Private-use IKEv2 notify. 5.9.13 notify_type_t has no named constant. */
#define FVL_LICENSE_NOTIFY_TYPE 61696
#define FVL_LICENSE_INFO_MAX 8192

/* Forticlient Connect License — not MD5 of the display name. */
static const uint8_t vid_connect_license[] = {
	0x4c, 0x53, 0x42, 0x7b, 0x6d, 0x46, 0x5d, 0x1b,
	0x33, 0x7b, 0xb7, 0x55, 0xa3, 0x7a, 0x7f, 0xef,
};

/* Fortinet Endpoint Control = MD5("Fortinet Endpoint Control") */
static const uint8_t vid_endpoint_control[] = {
	0xb4, 0xf0, 0x1c, 0xa9, 0x51, 0xe9, 0xda, 0x8d,
	0x0b, 0xaf, 0xbb, 0xd3, 0x4a, 0xd3, 0x04, 0x4e,
};

/* Forticlient EAP Extension = MD5("Forticlient EAP Extension") */
static const uint8_t vid_eap_extension[] = {
	0xc1, 0xdc, 0x43, 0x50, 0x47, 0x6b, 0x98, 0xa4,
	0x29, 0xb9, 0x17, 0x81, 0x91, 0x4c, 0xa4, 0x3e,
};

static const struct {
	const uint8_t *bytes;
	size_t len;
} fvl_vids[] = {
	{ vid_connect_license, sizeof(vid_connect_license) },
	{ vid_endpoint_control, sizeof(vid_endpoint_control) },
	{ vid_eap_extension, sizeof(vid_eap_extension) },
};

/*
 * Golden FortiClient first IKE_AUTH CFG_REQUEST: 16 empty 4-byte
 * attributes, payload length 72. Trailing 13 types are PROVEN from
 * ipsec.exe CFG_REQUEST encoder 0x140046e86 (add rbp,0x34). Types 1
 * and 2 are PROVEN empty CFG_REQUEST constructors. Type 7 is the
 * remaining ncfg slot (dedicated empty Request IKEV2_CFG_APPLICATION_VERSION
 * path; not in the trailing 13; 16-13=3). Fortinet 0x540a/0x540b/0x540c
 * have no strongSwan names.
 */
static const uint16_t fvl_cp_request_types[] = {
	INTERNAL_IP4_ADDRESS,	/* 1 */
	INTERNAL_IP4_NETMASK,	/* 2 */
	APPLICATION_VERSION,	/* 7 */
	INTERNAL_IP4_DNS,	/* 3 */
	INTERNAL_IP4_NBNS,	/* 4 */
	INTERNAL_IP4_SUBNET,	/* 13 */
	INTERNAL_IP6_ADDRESS,	/* 8 */
	INTERNAL_IP6_DNS,	/* 10 */
	INTERNAL_IP6_NBNS,	/* 11 */
	INTERNAL_IP6_SUBNET,	/* 15 */
	INTERNAL_DNS_DOMAIN,	/* 25 */
	0x540c,	/* 21516 Fortinet private; meaning unknown */
	UNITY_LOCAL_LAN,	/* 28678 / 0x7006 */
	0x540a,	/* 21514 auto-negotiate */
	0x540b,	/* 21515 KEEP_ALIVE */
	UNITY_SAVE_PASSWD,	/* 28673 / 0x7001 */
};

_Static_assert(sizeof(fvl_cp_request_types) / sizeof(fvl_cp_request_types[0]) == 16,
	"golden FortiClient CFG_REQUEST has 16 empty attributes");

static bool message_has_vid(message_t *message, chunk_t wanted)
{
	enumerator_t *enumerator;
	payload_t *payload;
	bool found = FALSE;

	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		vendor_id_payload_t *vid;
		chunk_t data;

		if (payload->get_type(payload) != PLV2_VENDOR_ID)
		{
			continue;
		}
		vid = (vendor_id_payload_t*)payload;
		data = vid->get_data(vid);
		if (chunk_equals(data, wanted))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

static bool add_forticlient_vids(message_t *message)
{
	unsigned int i;
	int added = 0;

	for (i = 0; i < countof(fvl_vids); i++)
	{
		chunk_t raw;
		payload_t *payload;

		raw = chunk_create((u_char*)fvl_vids[i].bytes, fvl_vids[i].len);
		if (message_has_vid(message, raw))
		{
			continue;
		}
		payload = (payload_t*)vendor_id_payload_create_data(
			PLV2_VENDOR_ID, chunk_clone(raw));
		if (payload == NULL)
		{
			return FALSE;
		}
		message->add_payload(message, payload);
		added++;
	}
	if (added > 0)
	{
		DBG1(DBG_IKE, "sending FortiClient compatibility vendor IDs (%d) "
			 "on IKE_SA_INIT", added);
	}
	return TRUE;
}

static void remove_compat_notifies(message_t *message)
{
	enumerator_t *enumerator;
	payload_t *payload;
	int eap_only = 0;
	int msg_id_syn = 0;

	/* RFC 5998 EAP_ONLY_AUTHENTICATION = 16417 and RFC 6311
	 * IKEV2_MESSAGE_ID_SYNC_SUPPORTED = 16420. strongSwan 5.9.13
	 * message_t.remove_payload_at() unlinks the current enumerator
	 * position and does not destroy the payload. AUTH, CP, SA, TS,
	 * and IDi are not touched. */
	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		notify_payload_t *notify;
		notify_type_t type;

		if (payload->get_type(payload) != PLV2_NOTIFY)
		{
			continue;
		}
		notify = (notify_payload_t*)payload;
		type = notify->get_notify_type(notify);
		if (type != EAP_ONLY_AUTHENTICATION &&
			type != IKEV2_MESSAGE_ID_SYNC_SUPPORTED)
		{
			continue;
		}
		message->remove_payload_at(message, enumerator);
		payload->destroy(payload);
		if (type == EAP_ONLY_AUTHENTICATION)
		{
			eap_only++;
		}
		else
		{
			msg_id_syn++;
		}
	}
	enumerator->destroy(enumerator);
	if (eap_only > 0)
	{
		DBG1(DBG_IKE, "FortiClient compatibility: removed EAP_ONLY from first IKE_AUTH");
	}
	if (msg_id_syn > 0)
	{
		DBG1(DBG_IKE, "FortiClient compatibility: removed MSG_ID_SYN_SUP from first IKE_AUTH");
	}
}

static bool message_has_notify(message_t *message, notify_type_t type)
{
	enumerator_t *enumerator;
	payload_t *payload;
	bool found = FALSE;

	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		notify_payload_t *notify;

		if (payload->get_type(payload) != PLV2_NOTIFY)
		{
			continue;
		}
		notify = (notify_payload_t*)payload;
		if (notify->get_notify_type(notify) == type)
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

static void add_initial_contact(message_t *message)
{
	notify_payload_t *notify;

	/* RFC 7296 INITIAL_CONTACT = 16384. 5.9.13 create-from-protocol
	 * helper with PLV2_NOTIFY and PROTO_NONE yields protocol ID 0, SPI
	 * size 0, empty notification data. message_t.add_payload() takes
	 * ownership; do not destroy the payload afterwards. Do not
	 * duplicate. */
	if (message_has_notify(message, INITIAL_CONTACT))
	{
		return;
	}
	notify = notify_payload_create_from_protocol_and_type(
		PLV2_NOTIFY, PROTO_NONE, INITIAL_CONTACT);
	if (notify == NULL)
	{
		return;
	}
	message->add_payload(message, (payload_t*)notify);
	DBG1(DBG_IKE, "FortiClient compatibility: added INITIAL_CONTACT to first IKE_AUTH");
}

/* Best-effort wipe of license-info bytes. Do not use strongSwan wipe
 * helpers: Ubuntu libstrongswan is built with HAVE_EXPLICIT_BZERO and
 * does not export the non-inline wipe symbol. glibc explicit_bzero is
 * preferred; memset_explicit is not in this libc. */
static void fvl_secure_wipe(void *ptr, size_t n)
{
	if (ptr == NULL || n == 0)
	{
		return;
	}
#if defined(__GLIBC__)
	explicit_bzero(ptr, n);
#else
	{
		volatile unsigned char *p = ptr;

		while (n > 0)
		{
			*p = 0;
			p++;
			n--;
		}
	}
#endif
}

static void fvl_chunk_clear(chunk_t *chunk)
{
	if (chunk == NULL || chunk->ptr == NULL)
	{
		return;
	}
	fvl_secure_wipe(chunk->ptr, chunk->len);
	chunk_free(chunk);
}

static chunk_t load_license_info(void)
{
	char *path;
	FILE *fp;
	uint8_t buf[FVL_LICENSE_INFO_MAX];
	size_t n;
	chunk_t data = chunk_empty;

	path = lib->settings->get_str(lib->settings,
		"%s.plugins.fvl-forticlient-vid.license_info", NULL, lib->ns);
	if (path == NULL || path[0] == '\0')
	{
		return chunk_empty;
	}
	fp = fopen(path, "rb");
	if (fp == NULL)
	{
		return chunk_empty;
	}
	n = fread(buf, 1, sizeof(buf), fp);
	fclose(fp);
	if (n == 0 || n >= sizeof(buf))
	{
		fvl_secure_wipe(buf, sizeof(buf));
		return chunk_empty;
	}
	data = chunk_clone(chunk_create(buf, n));
	fvl_secure_wipe(buf, sizeof(buf));
	return data;
}

static void add_license_notify(message_t *message)
{
	notify_payload_t *notify;
	chunk_t data;

	/* Private Notify 0xF100 / 61696. PROTO_NONE => protocol ID 0, SPI
	 * size 0. Data is the helper-written 0600 blob including the
	 * trailing NUL. Do not log the bytes. */
	if (message_has_notify(message, (notify_type_t)FVL_LICENSE_NOTIFY_TYPE))
	{
		return;
	}
	data = load_license_info();
	if (data.ptr == NULL || data.len == 0)
	{
		DBG1(DBG_IKE, "FortiClient compatibility: license-info missing; Notify 0xF100 not added");
		chunk_free(&data);
		return;
	}
	notify = notify_payload_create_from_protocol_and_type(
		PLV2_NOTIFY, PROTO_NONE, (notify_type_t)FVL_LICENSE_NOTIFY_TYPE);
	if (notify == NULL)
	{
		fvl_chunk_clear(&data);
		return;
	}
	notify->set_notification_data(notify, data);
	message->add_payload(message, (payload_t*)notify);
	DBG1(DBG_IKE, "FortiClient compatibility: added private Notify 0xF100");
	DBG1(DBG_IKE, "FortiClient compatibility: license-info payload length: %zu",
		 data.len);
	fvl_chunk_clear(&data);
}

static void rewrite_cp_request(message_t *message)
{
	enumerator_t *enumerator;
	payload_t *payload;
	cp_payload_t *old_cp = NULL;
	cp_payload_t *new_cp;
	unsigned int i;
	char types_buf[160];
	size_t used = 0;

	/* Replace the existing CFG_REQUEST so INTERNAL_IP4_ADDRESS and
	 * INTERNAL_IP4_DNS stay in the golden list without duplicates.
	 * generate() re-sorts CP after AUTH and before SA. Empty request
	 * values only; do not log attribute bytes. */
	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		cp_payload_t *cp;

		if (payload->get_type(payload) != PLV2_CONFIGURATION)
		{
			continue;
		}
		cp = (cp_payload_t*)payload;
		if (cp->get_type(cp) != CFG_REQUEST)
		{
			continue;
		}
		old_cp = cp;
		message->remove_payload_at(message, enumerator);
		break;
	}
	enumerator->destroy(enumerator);

	new_cp = cp_payload_create_type(PLV2_CONFIGURATION, CFG_REQUEST);
	if (new_cp == NULL)
	{
		if (old_cp != NULL)
		{
			old_cp->destroy(old_cp);
		}
		return;
	}
	for (i = 0; i < countof(fvl_cp_request_types); i++)
	{
		configuration_attribute_t *attr;

		attr = configuration_attribute_create_chunk(
			PLV2_CONFIGURATION_ATTRIBUTE,
			(configuration_attribute_type_t)fvl_cp_request_types[i],
			chunk_empty);
		if (attr == NULL)
		{
			new_cp->destroy(new_cp);
			if (old_cp != NULL)
			{
				old_cp->destroy(old_cp);
			}
			return;
		}
		new_cp->add_attribute(new_cp, attr);
	}
	if (old_cp != NULL)
	{
		old_cp->destroy(old_cp);
	}
	message->add_payload(message, (payload_t*)new_cp);

	types_buf[0] = '\0';
	for (i = 0; i < countof(fvl_cp_request_types); i++)
	{
		int n;

		n = snprintf(types_buf + used, sizeof(types_buf) - used, "%s%u",
			 i == 0 ? "" : ",",
			 (unsigned)fvl_cp_request_types[i]);
		if (n < 0 || (size_t)n >= sizeof(types_buf) - used)
		{
			break;
		}
		used += (size_t)n;
	}
	DBG1(DBG_IKE, "FortiClient compatibility: first IKE_AUTH CP request attributes: %u types %s",
		 (unsigned)countof(fvl_cp_request_types), types_buf);
}

static int count_payload_type(linked_list_t *list, payload_type_t type)
{
	enumerator_t *enumerator;
	payload_t *payload;
	int n = 0;

	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &payload))
	{
		if (payload->get_type(payload) == type)
		{
			n++;
		}
	}
	enumerator->destroy(enumerator);
	return n;
}

static int count_notify_type(linked_list_t *list, notify_type_t type)
{
	enumerator_t *enumerator;
	payload_t *payload;
	int n = 0;

	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &payload))
	{
		notify_payload_t *notify;

		if (payload->get_type(payload) != PLV2_NOTIFY)
		{
			continue;
		}
		notify = (notify_payload_t*)payload;
		if (notify->get_notify_type(notify) == type)
		{
			n++;
		}
	}
	enumerator->destroy(enumerator);
	return n;
}

static void append_payloads_of_type(message_t *message, linked_list_t *list,
									payload_type_t type)
{
	enumerator_t *enumerator;
	payload_t *payload;

	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &payload))
	{
		if (payload->get_type(payload) != type)
		{
			continue;
		}
		list->remove_at(list, enumerator);
		message->add_payload(message, payload);
	}
	enumerator->destroy(enumerator);
}

static void append_notifies_of_type(message_t *message, linked_list_t *list,
									notify_type_t type)
{
	enumerator_t *enumerator;
	payload_t *payload;

	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &payload))
	{
		notify_payload_t *notify;

		if (payload->get_type(payload) != PLV2_NOTIFY)
		{
			continue;
		}
		notify = (notify_payload_t*)payload;
		if (notify->get_notify_type(notify) != type)
		{
			continue;
		}
		list->remove_at(list, enumerator);
		message->add_payload(message, payload);
	}
	enumerator->destroy(enumerator);
}

static void restore_payloads(message_t *message, linked_list_t *list)
{
	payload_t *payload;

	while (list->remove_first(list, (void**)&payload) == SUCCESS)
	{
		message->add_payload(message, payload);
	}
}

/*
 * Move existing Notify 0xF100 to sit immediately after INITIAL_CONTACT
 * and before AUTH and CFG_REQUEST. AUTH is still present at this
 * step so the reorder can lock 0xF100 before CFG_REQUEST. strongSwan
 * 5.9.13 ike_auth_i_order would otherwise place unknown notifies after
 * TSr, so disable_sort() is required. If AUTH, IDi, INITIAL_CONTACT,
 * CFG_REQUEST, or a single 0xF100 is missing, restore the original
 * payload list and leave sorting enabled. omit_initiator_auth() then
 * strips AUTH from this first IKE_AUTH only.
 */
static void reposition_license_notify(message_t *message)
{
	enumerator_t *enumerator;
	payload_t *payload;
	linked_list_t *list;

	list = linked_list_create();
	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		message->remove_payload_at(message, enumerator);
		list->insert_last(list, payload);
	}
	enumerator->destroy(enumerator);

	if (count_notify_type(list, (notify_type_t)FVL_LICENSE_NOTIFY_TYPE) != 1 ||
		count_notify_type(list, INITIAL_CONTACT) < 1 ||
		count_payload_type(list, PLV2_ID_INITIATOR) < 1 ||
		count_payload_type(list, PLV2_AUTH) < 1 ||
		count_payload_type(list, PLV2_CONFIGURATION) < 1)
	{
		restore_payloads(message, list);
		list->destroy(list);
		DBG1(DBG_IKE, "FortiClient compatibility: Notify 0xF100 not repositioned");
		return;
	}

	append_payloads_of_type(message, list, PLV2_ID_INITIATOR);
	append_notifies_of_type(message, list, INITIAL_CONTACT);
	append_notifies_of_type(message, list, (notify_type_t)FVL_LICENSE_NOTIFY_TYPE);
	append_payloads_of_type(message, list, PLV2_AUTH);
	append_payloads_of_type(message, list, PLV2_CONFIGURATION);
	append_payloads_of_type(message, list, PLV2_SECURITY_ASSOCIATION);
	append_payloads_of_type(message, list, PLV2_TS_INITIATOR);
	append_payloads_of_type(message, list, PLV2_TS_RESPONDER);
	restore_payloads(message, list);
	list->destroy(list);
	message->disable_sort(message);
	DBG1(DBG_IKE, "FortiClient compatibility: repositioned Notify 0xF100 before CFG_REQUEST");
}

/*
 * Remove initiator AUTH from the serialized first IKE_AUTH only.
 * PSK stays configured on the connection. Later IKE_AUTH / EAP is
 * unchanged because this runs only for IKEv2 initiator MID 1.
 * Expected first IKE_AUTH order after this hook:
 * IDi, INITIAL_CONTACT, 0xF100, CFG_REQUEST, SA, TSi, TSr.
 */
static void omit_initiator_auth(message_t *message)
{
	enumerator_t *enumerator;
	payload_t *payload;
	int removed = 0;

	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		if (payload->get_type(payload) != PLV2_AUTH)
		{
			continue;
		}
		message->remove_payload_at(message, enumerator);
		payload->destroy(payload);
		removed++;
	}
	enumerator->destroy(enumerator);
	if (removed > 0)
	{
		DBG1(DBG_IKE, "FortiClient compatibility: omitted initiator AUTH from first IKE_AUTH");
	}
}

static private_fvl_forticlient_vid_plugin_t *plugin_from_listener(listener_t *listener)
{
	return (private_fvl_forticlient_vid_plugin_t*)(((char*)listener) -
		offsetof(private_fvl_forticlient_vid_plugin_t, listener));
}

static void clear_string_list(linked_list_t *list)
{
	char *item;

	while (list->remove_first(list, (void**)&item) == SUCCESS)
	{
		free(item);
	}
}

static void add_unique_string(linked_list_t *list, const char *value)
{
	enumerator_t *enumerator;
	char *item;

	if (value == NULL || value[0] == '\0')
	{
		return;
	}
	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &item))
	{
		if (strcmp(item, value) == 0)
		{
			enumerator->destroy(enumerator);
			return;
		}
	}
	enumerator->destroy(enumerator);
	item = strdup(value);
	if (item != NULL)
	{
		list->insert_last(list, item);
	}
}

static bool prefix_is_wildcard(const char *prefix)
{
	return prefix != NULL && strcmp(prefix, "0.0.0.0/0") == 0;
}

static int mask_to_prefixlen(uint32_t mask_n)
{
	uint32_t mask = ntohl(mask_n);
	int n = 0;

	while (mask & 0x80000000U)
	{
		n++;
		mask <<= 1;
	}
	return n;
}

static bool format_prefix(char *out, size_t out_len, const uint8_t *addr,
						  const uint8_t *mask)
{
	uint32_t addr_n, mask_n, network;
	int prefixlen;
	struct in_addr in;

	memcpy(&addr_n, addr, 4);
	memcpy(&mask_n, mask, 4);
	network = addr_n & mask_n;
	prefixlen = mask_to_prefixlen(mask_n);
	in.s_addr = network;
	return snprintf(out, out_len, "%s/%d", inet_ntoa(in), prefixlen) > 0;
}

static void parse_subnet_bytes(linked_list_t *list, chunk_t data, int stride)
{
	char prefix[FVL_PREFIX_LEN];

	while (data.len >= 8)
	{
		if (format_prefix(prefix, sizeof(prefix), data.ptr, data.ptr + 4))
		{
			add_unique_string(list, prefix);
		}
		if (stride > 0)
		{
			if (data.len < (size_t)stride)
			{
				break;
			}
			data = chunk_skip(data, stride);
			continue;
		}
		if (data.len >= 14)
		{
			data = chunk_skip(data, 14);
		}
		else
		{
			data = chunk_skip(data, 8);
		}
	}
}

static bool domain_allowed(const char *text)
{
	size_t i;

	if (text == NULL || text[0] == '\0' || strlen(text) >= FVL_DOMAIN_LEN)
	{
		return FALSE;
	}
	if (strcmp(text, ".") == 0 || strcmp(text, "~.") == 0)
	{
		return TRUE;
	}
	for (i = 0; text[i] != '\0'; i++)
	{
		char c = text[i];

		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' ||
			c == '~')
		{
			continue;
		}
		return FALSE;
	}
	return TRUE;
}

static void add_domain_chunk(linked_list_t *list, chunk_t data)
{
	char buf[FVL_DOMAIN_LEN];
	size_t len;

	if (data.len == 0)
	{
		return;
	}
	len = data.len < sizeof(buf) - 1 ? data.len : sizeof(buf) - 1;
	memcpy(buf, data.ptr, len);
	buf[len] = '\0';
	if (len > 0 && buf[len - 1] == '\0')
	{
		/* already terminated */
	}
	if (domain_allowed(buf))
	{
		add_unique_string(list, buf);
	}
}

static void add_dns_chunk(linked_list_t *list, chunk_t data)
{
	char buf[INET_ADDRSTRLEN];

	if (data.len != 4)
	{
		return;
	}
	if (inet_ntop(AF_INET, data.ptr, buf, sizeof(buf)) != NULL)
	{
		add_unique_string(list, buf);
	}
}

static void join_strings(linked_list_t *list, char *out, size_t out_len)
{
	enumerator_t *enumerator;
	char *item;
	size_t used = 0;
	bool first = TRUE;

	out[0] = '\0';
	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &item))
	{
		int n;

		n = snprintf(out + used, out_len - used, "%s%s", first ? "" : ",", item);
		if (n < 0 || (size_t)n >= out_len - used)
		{
			break;
		}
		used += (size_t)n;
		first = FALSE;
	}
	enumerator->destroy(enumerator);
	if (out[0] == '\0')
	{
		snprintf(out, out_len, "(none)");
	}
}

static void reset_cfg_state(private_fvl_forticlient_vid_plugin_t *this)
{
	clear_string_list(this->unity_include);
	clear_string_list(this->rfc_subnet);
	clear_string_list(this->fortinet_540c);
	clear_string_list(this->local_lan);
	clear_string_list(this->dns_servers);
	clear_string_list(this->dns_domains);
	clear_string_list(this->selected);
	this->source[0] = '\0';
	this->split = FALSE;
}

static bool list_has_wildcard(linked_list_t *list)
{
	enumerator_t *enumerator;
	char *item;
	bool found = FALSE;

	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &item))
	{
		if (prefix_is_wildcard(item))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

static void copy_list(linked_list_t *src, linked_list_t *dst)
{
	enumerator_t *enumerator;
	char *item;

	enumerator = src->create_enumerator(src);
	while (enumerator->enumerate(enumerator, &item))
	{
		add_unique_string(dst, item);
	}
	enumerator->destroy(enumerator);
}

static void classify_split(private_fvl_forticlient_vid_plugin_t *this)
{
	clear_string_list(this->selected);
	this->split = FALSE;
	snprintf(this->source, sizeof(this->source), "none");
	if (this->unity_include->get_count(this->unity_include) > 0)
	{
		copy_list(this->unity_include, this->selected);
		snprintf(this->source, sizeof(this->source), "UNITY_SPLIT_INCLUDE");
	}
	else if (this->rfc_subnet->get_count(this->rfc_subnet) > 0)
	{
		copy_list(this->rfc_subnet, this->selected);
		snprintf(this->source, sizeof(this->source), "INTERNAL_IP4_SUBNET");
	}
	else if (this->fortinet_540c->get_count(this->fortinet_540c) > 0)
	{
		copy_list(this->fortinet_540c, this->selected);
		snprintf(this->source, sizeof(this->source), "0x540c");
	}
	else if (this->local_lan->get_count(this->local_lan) > 0)
	{
		copy_list(this->local_lan, this->selected);
		snprintf(this->source, sizeof(this->source), "UNITY_LOCAL_LAN");
	}
	if (this->selected->get_count(this->selected) > 0 &&
		!list_has_wildcard(this->selected))
	{
		this->split = TRUE;
	}
	else
	{
		clear_string_list(this->selected);
		this->split = FALSE;
	}
}

static void log_cfg_reply(private_fvl_forticlient_vid_plugin_t *this)
{
	char prefixes[512];
	char servers[256];
	char domains[256];

	join_strings(this->selected, prefixes, sizeof(prefixes));
	join_strings(this->dns_servers, servers, sizeof(servers));
	join_strings(this->dns_domains, domains, sizeof(domains));
	DBG1(DBG_IKE,
		 "FortiClient compatibility: CFG_REPLY split-include count=%u prefixes=%s source=%s",
		 this->selected->get_count(this->selected), prefixes,
		 this->source[0] != '\0' ? this->source : "none");
	DBG1(DBG_IKE, "FortiClient compatibility: CFG_REPLY dns servers=%s domains=%s",
		 servers, domains);
	DBG1(DBG_IKE, "FortiClient compatibility: CFG_REPLY tunnel-mode=%s",
		 this->split ? "split" : "full");
}

static void parse_incoming_cfg_reply(private_fvl_forticlient_vid_plugin_t *this,
									 message_t *message)
{
	enumerator_t *payloads;
	payload_t *payload;
	bool seen = FALSE;

	payloads = message->create_payload_enumerator(message);
	while (payloads->enumerate(payloads, &payload))
	{
		cp_payload_t *cp;
		enumerator_t *attrs;
		configuration_attribute_t *ca;

		if (payload->get_type(payload) != PLV2_CONFIGURATION)
		{
			continue;
		}
		cp = (cp_payload_t*)payload;
		if (cp->get_type(cp) != CFG_REPLY)
		{
			continue;
		}
		if (!seen)
		{
			this->mutex->lock(this->mutex);
			reset_cfg_state(this);
			seen = TRUE;
		}
		attrs = cp->create_attribute_enumerator(cp);
		while (attrs->enumerate(attrs, &ca))
		{
			configuration_attribute_type_t type = ca->get_type(ca);
			chunk_t data = ca->get_chunk(ca);

			switch (type)
			{
				case INTERNAL_IP4_SUBNET:
					parse_subnet_bytes(this->rfc_subnet, data, 8);
					break;
				case INTERNAL_IP4_DNS:
					add_dns_chunk(this->dns_servers, data);
					break;
				case INTERNAL_DNS_DOMAIN:
					add_domain_chunk(this->dns_domains, data);
					break;
				case UNITY_SPLIT_INCLUDE:
					parse_subnet_bytes(this->unity_include, data, 14);
					break;
				case UNITY_LOCAL_LAN:
					parse_subnet_bytes(this->local_lan, data, 14);
					break;
				case UNITY_SPLITDNS_NAME:
				case UNITY_DEF_DOMAIN:
					add_domain_chunk(this->dns_domains, data);
					break;
				default:
					if ((uint16_t)type == FVL_FORTINET_540C)
					{
						DBG1(DBG_IKE,
							 "FortiClient compatibility: CFG_REPLY attr type=%u length=%zu",
							 (unsigned)type, data.len);
						parse_subnet_bytes(this->fortinet_540c, data, 0);
					}
					break;
			}
		}
		attrs->destroy(attrs);
	}
	payloads->destroy(payloads);
	if (seen)
	{
		classify_split(this);
		log_cfg_reply(this);
		this->mutex->unlock(this->mutex);
	}
}

static bool ts_is_ipv4_wildcard(traffic_selector_t *ts)
{
	chunk_t from, to;
	static const uint8_t zero[4] = { 0, 0, 0, 0 };
	static const uint8_t all[4] = { 255, 255, 255, 255 };

	if (ts == NULL || ts->get_type(ts) != TS_IPV4_ADDR_RANGE)
	{
		return FALSE;
	}
	from = ts->get_from_address(ts);
	to = ts->get_to_address(ts);
	return from.len == 4 && to.len == 4 &&
		memcmp(from.ptr, zero, 4) == 0 && memcmp(to.ptr, all, 4) == 0;
}

/*
 * True when the list still contains IPv4 0.0.0.0-255.255.255.255.
 * child_create select_and_install() intersects config/received first
 * (logged as "selecting traffic selectors for other"); that match is
 * still 0.0.0.0/0 on the FortiGate IKEv2 SSO path. The bus narrow hook
 * must then replace that list in-place.
 */
static bool remote_has_ipv4_wildcard(linked_list_t *remote)
{
	enumerator_t *enumerator;
	traffic_selector_t *ts;
	bool found = FALSE;

	enumerator = remote->create_enumerator(remote);
	while (enumerator->enumerate(enumerator, &ts))
	{
		if (ts_is_ipv4_wildcard(ts))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

/*
 * Replace the initiator's effective remote TS list with CFG_REPLY
 * split-include prefixes. child_create.c:
 *
 * - IKE_AUTH CHILD_SA (this SSO path): NARROW_INITIATOR_POST_NOAUTH
 *   after narrow_ts() and before set_policies().
 * - CREATE_CHILD_SA rekey: NARROW_INITIATOR_POST_AUTH.
 *
 * POST_AUTH alone never runs for the initial IKE_AUTH CHILD_SA, which
 * is why the previous hook left VIP/32 === 0.0.0.0/0.
 * Do not use PRE_* hooks: first IKE_AUTH must keep proposed TSr
 * 0.0.0.0/0 (frozen control plane). Do not edit child_cfg; the
 * authoritative list is the linked_list passed to this hook.
 */
static bool narrow_hook(listener_t *listener, ike_sa_t *ike_sa,
						child_sa_t *child_sa, narrow_hook_t type,
						linked_list_t *local, linked_list_t *remote)
{
	private_fvl_forticlient_vid_plugin_t *this = plugin_from_listener(listener);
	traffic_selector_t *ts;
	enumerator_t *enumerator;
	char *prefix;

	(void)ike_sa;
	(void)child_sa;
	(void)local;
	if (type != NARROW_INITIATOR_POST_NOAUTH &&
		type != NARROW_INITIATOR_POST_AUTH)
	{
		return TRUE;
	}
	this->mutex->lock(this->mutex);
	if (!this->split || this->selected->get_count(this->selected) == 0)
	{
		this->mutex->unlock(this->mutex);
		return TRUE;
	}
	if (!remote_has_ipv4_wildcard(remote))
	{
		DBG1(DBG_IKE,
			 "FortiClient compatibility: CHILD_SA remote TS already narrowed; split-include count=%u unused",
			 this->selected->get_count(this->selected));
		this->mutex->unlock(this->mutex);
		return TRUE;
	}
	while (remote->remove_first(remote, (void**)&ts) == SUCCESS)
	{
		ts->destroy(ts);
	}
	enumerator = this->selected->create_enumerator(this->selected);
	while (enumerator->enumerate(enumerator, &prefix))
	{
		ts = traffic_selector_create_from_cidr(prefix, 0, 0, 65535);
		if (ts != NULL)
		{
			remote->insert_last(remote, ts);
		}
	}
	enumerator->destroy(enumerator);
	DBG1(DBG_IKE,
		 "FortiClient compatibility: narrowed CHILD_SA remote TS to split-include count=%u",
		 this->selected->get_count(this->selected));
	this->mutex->unlock(this->mutex);
	return TRUE;
}

static bool ike_updown_hook(listener_t *listener, ike_sa_t *ike_sa, bool up)
{
	private_fvl_forticlient_vid_plugin_t *this = plugin_from_listener(listener);

	(void)ike_sa;
	if (!up)
	{
		this->mutex->lock(this->mutex);
		reset_cfg_state(this);
		this->mutex->unlock(this->mutex);
	}
	return TRUE;
}

static bool message_hook(listener_t *listener, ike_sa_t *ike_sa,
						 message_t *message, bool incoming, bool plain)
{
	private_fvl_forticlient_vid_plugin_t *this = plugin_from_listener(listener);
	exchange_type_t exchange;

	(void)ike_sa;
	if (!plain)
	{
		return TRUE;
	}
	if (message->get_major_version(message) != IKEV2_MAJOR_VERSION)
	{
		return TRUE;
	}
	if (incoming)
	{
		parse_incoming_cfg_reply(this, message);
		return TRUE;
	}
	if (!message->get_request(message))
	{
		return TRUE;
	}
	exchange = message->get_exchange_type(message);
	if (exchange == IKE_SA_INIT)
	{
		add_forticlient_vids(message);
		return TRUE;
	}
	if (exchange == IKE_AUTH && message->get_message_id(message) == 1)
	{
		remove_compat_notifies(message);
		add_initial_contact(message);
		add_license_notify(message);
		rewrite_cp_request(message);
		reposition_license_notify(message);
		omit_initiator_auth(message);
	}
	return TRUE;
}

METHOD(plugin_t, get_name, char*,
	private_fvl_forticlient_vid_plugin_t *this)
{
	(void)this;
	return "fvl-forticlient-vid";
}

static bool plugin_cb(private_fvl_forticlient_vid_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	(void)feature;
	(void)cb_data;
	if (reg)
	{
		charon->bus->add_listener(charon->bus, &this->listener);
	}
	else
	{
		charon->bus->remove_listener(charon->bus, &this->listener);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_fvl_forticlient_vid_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
		PLUGIN_PROVIDE(CUSTOM, "fvl-forticlient-vid"),
	};
	(void)this;
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_fvl_forticlient_vid_plugin_t *this)
{
	if (this->mutex != NULL)
	{
		this->mutex->lock(this->mutex);
		reset_cfg_state(this);
		this->mutex->unlock(this->mutex);
		this->mutex->destroy(this->mutex);
	}
	this->unity_include->destroy(this->unity_include);
	this->rfc_subnet->destroy(this->rfc_subnet);
	this->fortinet_540c->destroy(this->fortinet_540c);
	this->local_lan->destroy(this->local_lan);
	this->dns_servers->destroy(this->dns_servers);
	this->dns_domains->destroy(this->dns_domains);
	this->selected->destroy(this->selected);
	free(this);
}

plugin_t *fvl_forticlient_vid_plugin_create()
{
	private_fvl_forticlient_vid_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
		.listener = {
			.message = message_hook,
			.narrow = narrow_hook,
			.ike_updown = ike_updown_hook,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.unity_include = linked_list_create(),
		.rfc_subnet = linked_list_create(),
		.fortinet_540c = linked_list_create(),
		.local_lan = linked_list_create(),
		.dns_servers = linked_list_create(),
		.dns_domains = linked_list_create(),
		.selected = linked_list_create(),
	);
	return &this->public.plugin;
}
