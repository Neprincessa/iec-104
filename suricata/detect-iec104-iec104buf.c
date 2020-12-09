/* Copyright (C) 2015-2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
 
/*
 * TODO: Update the \author in this file and detect-iec104-iec104buf.h.
 * TODO: Update description in the \file section below.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */
 
/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Set up of the "iec104_iec104buf" keyword to allow content
 * inspections on the decoded iec104 application layer buffers.
 */
 
#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "app-layer-iec104.h"
#include "detect-iec104-iec104buf.h"
 
#define PARSE_REGEX_TYPE "^\\s*\"?\\s*type\\s*([I|S|U]+)\\s*\"?\\s*$"
static DetectParseRegex type_parse_regex;
 
static int DetectIEC104IEC104bufSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t flow_flags,
        void *txv, const int list_id);
#ifdef UNITTESTS
static void DetectIEC104IEC104bufRegisterTests(void);
#endif
static int g_iec104_iec104buf_id = 0;
 
void DetectIEC104Free(DetectEngineCtx *de_ctx, void *ptr)
{
    SCEnter();
    DetectIEC104 *iec104 = (DetectIEC104 *) ptr;

    if (iec104) {
        SCFree(iec104);
    }
}
 
static DetectIEC104 *DetectIEC104TypeParse(DetectEngineCtx *de_ctx, const char *iec104str)
{
    SCEnter();
    DetectIEC104 *iec104 = NULL;
 
    char arg[MAX_SUBSTRINGS];
    char *ptr = arg;
    int ov[MAX_SUBSTRINGS];
    int res;
    int ret;
 
    ret = DetectParsePcreExec(&type_parse_regex, iec104str, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 1)
        goto error;
 
    res = pcre_copy_substring(iec104str, ov, MAX_SUBSTRINGS, 1, ptr, MAX_SUBSTRINGS);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
 
    /* We have a correct IEC104 function option */
    iec104 = (DetectIEC104 *) SCCalloc(1, sizeof(DetectIEC104));
    if (unlikely(iec104 == NULL))
        goto error;
 
    if ((char)*ptr != 'U' && (char)*ptr != 'I' && (char)*ptr != 'S') {
        SCLogError(SC_ERR_INVALID_VALUE, "Invalid value for iec104 type: %c", (char)*ptr);
        goto error;
    }
	
	iec104->type = (char)*ptr;
 
    SCLogNotice("will look for iec104 function %c", iec104->type);
 
    SCReturnPtr(iec104, "DetectIEC104");

error:
    if (iec104 != NULL)
        DetectIEC104Free(de_ctx, iec104);
 
    SCReturnPtr(NULL, "DetectIEC104");
}
 
 
 
int DetectIEC104Match(DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    uint8_t* payload = p->payload;
    uint8_t* payload_len = p->payload_len;
    DetectIEC104* iec104 = (DetectIEC104*)ctx;

    SCLogNotice("THIS IS MSG FROM MATCH");
 
    if (payload_len < 1) {
        SCLogNotice("payload length is too small");
        return 0;
    }
 
    if (PKT_IS_PSEUDOPKT(p)) {
        SCLogNotice("Pseudopkt detect");
        return 0; 
    }
 
    if (!PKT_IS_TCP(p)) {
        SCLogNotice("Transport protocol does not TCP");
        return 0; 
    }
 
    if (*payload != 0x68) {
        SCLogNotice("Protocol type not match with IEC104 protocol: %d", *(payload));
        return 0;
    }
 
	bool match = false;
 
    uint8_t type = *(payload + 2);
    if (iec104->type == 'U') {
		match = type & 3 == 3; 
	}
	else if (iec104->type == 'I') {
		match = type & 3 == 0; 
	}
	else if (iec104->type == 'S') {
		match = type & 3 == 1; 
	}
	else {
        SCLogNotice("Invalid struct!");
    } 
	
	if (!match) {
		SCLogNotice("Packet does not pass the filtering by type, actual type = %d, rule = %c", type, iec104->type);
	}
	else {
		SCLogNotice("PACKET PASSED the filtering, DETECT");
	}
 
    
    return match ? 1 : 0;
}
 
static int DetectIEC104IEC104bufSetup(DetectEngineCtx *de_ctx, Signature *s,
    const char *str) // THIS S**T HAS BEEN SHANGED
{
    SCEnter();
 
    /* store list id. Content, pcre, etc will be added to the list at this
     * id. */
    s->init_data->list = g_iec104_iec104buf_id;
 
    /* set the app proto for this signature. This means it will only be
     * evaluated against flows that are ALPROTO_IEC104 */
 
    DetectIEC104    *iec104 = NULL;
    SigMatch        *sm = NULL;
 
    if (DetectSignatureSetAppProto(s, ALPROTO_IEC104) != 0)
        SCReturnInt(-1);
 
    if ((iec104 = DetectIEC104TypeParse(de_ctx, str)) == NULL) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid iec104 option");
        if (iec104 != NULL)
            DetectIEC104Free(de_ctx, iec104);
 
        if (sm != NULL)
            SCFree(sm);
 
        SCReturnInt(-1);
    }
 
    /* Okay so far so good, lets get this into a SigMatch and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
    {
        if (iec104 != NULL)
            DetectIEC104Free(de_ctx, iec104);
 
        if (sm != NULL)
            SCFree(sm);
 
        SCReturnInt(-1);
    }
 
    sm->type    = DETECT_AL_IEC104_IEC104BUF;
    sm->ctx     = (void *) iec104;
 
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH); //g_iec104_id);

    SCLogNotice("THIS IS MSG FROm SETUP");
 
    SCReturnInt(0);
}
 
/** \internal
 *  \brief get the data to inspect from the transaction.
 *  This function gets the data, sets up the InspectionBuffer object
 *  and applies transformations (if any).
 *
 *  \retval buffer or NULL in case of error
 */
/*static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t flow_flags,
        void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const IEC104Transaction  *tx = (IEC104Transaction *)txv;
        const uint8_t *data = NULL;
        uint32_t data_len = 0;
 
        if (flow_flags & STREAM_TOSERVER) {
            data = tx->request_buffer;
            data_len = tx->request_buffer_len;
        } else if (flow_flags & STREAM_TOCLIENT) {
            data = tx->response_buffer;
            data_len = tx->response_buffer_len;
        } else {
            return NULL; 
        }
 
        InspectionBufferSetup(buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
 
    return buffer;
}*/

void DetectIEC104IEC104bufRegister(void) //
{
        SCEnter();    
 
    sigmatch_table[DETECT_AL_IEC104_IEC104BUF].name = "iec104";
    sigmatch_table[DETECT_AL_IEC104_IEC104BUF].desc = "IEC104 content modififier to match on the iec104 buffers";
    sigmatch_table[DETECT_AL_IEC104_IEC104BUF].Match = DetectIEC104Match;
    sigmatch_table[DETECT_AL_IEC104_IEC104BUF].Setup = DetectIEC104IEC104bufSetup;
    sigmatch_table[DETECT_AL_IEC104_IEC104BUF].Free = DetectIEC104Free;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_IEC104_IEC104BUF].RegisterTests =
        DetectIEC104IEC104bufRegisterTests;
#endif
 
    sigmatch_table[DETECT_AL_IEC104_IEC104BUF].flags |= SIGMATCH_NOOPT;
 
    DetectSetupParseRegexes(PARSE_REGEX_TYPE, &type_parse_regex);
 
    SCLogNotice("IEC104 application layer detect registered.");
}
 
#ifdef UNITTESTS
#include "tests/detect-iec104-iec104buf.c"
#endif