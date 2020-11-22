/* Copyright (C) 2015-2020 Open Information Security Foundation
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

/**
 * \file
 *
 * \author XXX Yourname <youremail@yourdomain>
 *
 * XXX Short description of the purpose of this keyword
 */

#include "suricata-common.h"
#include "util-unittest.h"
#include "util-byte.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-iec104.h"

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([0-9]+)?\\s*,s*([0-9]+)?\\s*$"
static DetectParseRegex parse_regex;

/* Prototypes of functions registered in DetectIec104Register below */
static int DetectIec104Match (DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectIec104Setup (DetectEngineCtx *, Signature *, const char *);
static void DetectIec104Free (DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectIec104RegisterTests (void);
#endif

/**
 * \brief Registration function for iec104: keyword
 *
 * This function is called once in the 'lifetime' of the engine.
 */
void DetectIec104Register(void) {
    /* keyword name: this is how the keyword is used in a rule */
    sigmatch_table[DETECT_IEC104].name = "iec104";
    /* description: listed in "suricata --list-keywords=all" */
    sigmatch_table[DETECT_IEC104].desc = "give an introduction into how a detection module works";
    /* link to further documentation of the keyword. Normally on the Suricata redmine/wiki */
    sigmatch_table[DETECT_IEC104].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Developers_Guide";
    /* match function is called when the signature is inspected on a packet */
    sigmatch_table[DETECT_IEC104].Match = DetectIec104Match;
    /* setup function is called during signature parsing, when the iec104
     * keyword is encountered in the rule */
    sigmatch_table[DETECT_IEC104].Setup = DetectIec104Setup;
    /* free function is called when the detect engine is freed. Normally at
     * shutdown, but also during rule reloads. */
    sigmatch_table[DETECT_IEC104].Free = DetectIec104Free;
#ifdef UNITTESTS
    /* registers unittests into the system */
    sigmatch_table[DETECT_IEC104].RegisterTests = DetectIec104RegisterTests;
#endif
    /* set up the PCRE for keyword parsing */
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \brief This function is used to match IEC104 rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectIec104Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectIec104Match (DetectEngineThreadCtx *det_ctx, Packet *p,
                                const Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    const DetectIec104Data *iec104d = (const DetectIec104Data *) ctx;
#if 0
    if (PKT_IS_PSEUDOPKT(p)) {
        /* fake pkt */
    }

    if (PKT_IS_IPV4(p)) {
        /* ipv4 pkt */
    } else if (PKT_IS_IPV6(p)) {
        /* ipv6 pkt */
    } else {
        SCLogDebug("packet is of not IPv4 or IPv6");
        return ret;
    }
#endif
    /* packet payload access */
    if (p->payload != NULL && p->payload_len > 0) {
        if (iec104d->arg1 == p->payload[0] &&
            iec104d->arg2 == p->payload[p->payload_len - 1])
        {
            ret = 1;
        }
    }

    return ret;
}

/**
 * \brief This function is used to parse iec104 options passed via iec104: keyword
 *
 * \param iec104str Pointer to the user provided iec104 options
 *
 * \retval iec104d pointer to DetectIec104Data on success
 * \retval NULL on failure
 */
static DetectIec104Data *DetectIec104Parse (const char *iec104str)
{
    char arg1[4] = "";
    char arg2[4] = "";
    int ov[MAX_SUBSTRINGS];

    int ret = DetectParsePcreExec(&parse_regex, iec104str, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        return NULL;
    }

    ret = pcre_copy_substring((char *) iec104str, ov, MAX_SUBSTRINGS, 1, arg1, sizeof(arg1));
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        return NULL;
    }
    SCLogDebug("Arg1 \"%s\"", arg1);

    ret = pcre_copy_substring((char *) iec104str, ov, MAX_SUBSTRINGS, 2, arg2, sizeof(arg2));
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        return NULL;
    }
    SCLogDebug("Arg2 \"%s\"", arg2);

    DetectIec104Data *iec104d = SCMalloc(sizeof (DetectIec104Data));
    if (unlikely(iec104d == NULL))
        return NULL;

    if (ByteExtractStringUint8(&iec104d->arg1, 10, 0, (const char *)arg1) < 0) {
        SCFree(iec104d);
        return NULL;
    }
    if (ByteExtractStringUint8(&iec104d->arg2, 10, 0, (const char *)arg2) < 0) {
        SCFree(iec104d);
        return NULL;
    }
    return iec104d;
}

/**
 * \brief parse the options from the 'iec104' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param iec104str pointer to the user provided iec104 options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectIec104Setup (DetectEngineCtx *de_ctx, Signature *s, const char *iec104str)
{
    DetectIec104Data *iec104d = DetectIec104Parse(iec104str);
    if (iec104d == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectIec104Free(de_ctx, iec104d);
        return -1;
    }

    sm->type = DETECT_IEC104;
    sm->ctx = (void *)iec104d;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

/**
 * \brief this function will free memory associated with DetectIec104Data
 *
 * \param ptr pointer to DetectIec104Data
 */
static void DetectIec104Free(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectIec104Data *iec104d = (DetectIec104Data *)ptr;

    /* do more specific cleanup here, if needed */

    SCFree(iec104d);
}

#ifdef UNITTESTS
#include "tests/detect-iec104.c"
#endif
