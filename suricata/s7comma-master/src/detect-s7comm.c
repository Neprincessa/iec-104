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

/**
 * \file
 *
 * \author XXX Yourname <youremail@yourdomain>
 *
 * XXX Short description of the purpose of this keyword
 */

#include "suricata-common.h"
#include "util-unittest.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-s7comm.h"

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([0-9]+)?\\s*,s*([0-9]+)?\\s*$"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/* Prototypes of functions registered in DetectS7commRegister below */
static int DetectS7commMatch (DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectS7commSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectS7commFree (void *);
#ifdef UNITTESTS
static void DetectS7commRegisterTests (void);
#endif

/**
 * \brief Registration function for s7comm: keyword
 *
 * This function is called once in the 'lifetime' of the engine.
 */
void DetectS7commRegister(void) {
    /* keyword name: this is how the keyword is used in a rule */
    sigmatch_table[DETECT_S7COMM].name = "s7comm";
    /* description: listed in "suricata --list-keywords=all" */
    sigmatch_table[DETECT_S7COMM].desc = "just get payload";	//мб начнем просто с извелечения полезной нагрузки?
    /* link to further documentation of the keyword. Normally on the Suricata redmine/wiki */
    sigmatch_table[DETECT_S7COMM].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Developers_Guide";	//на самом деле средне полезная ссылка, но хоть что-то
    /* match function is called when the signature is inspected on a packet 
	вот те функи, которые нужно реализовать. Выглядить несожно))*/
    sigmatch_table[DETECT_S7COMM].Match = DetectS7commMatch;
    /* setup function is called during signature parsing, when the s7comm
     * keyword is encountered in the rule */
    sigmatch_table[DETECT_S7COMM].Setup = DetectS7commSetup;
    /* free function is called when the detect engine is freed. Normally at
     * shutdown, but also during rule reloads. */
    sigmatch_table[DETECT_S7COMM].Free = DetectS7commFree;
#ifdef UNITTESTS
    /* registers unittests into the system */
    sigmatch_table[DETECT_S7COMM].RegisterTests = DetectS7commRegisterTests;
#endif
    /* set up the PCRE for keyword parsing */
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
}

/**
 * \brief This function is used to match S7COMM rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectS7commData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectS7commMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
                                const Signature *s, const SigMatchCtx *ctx)		//функа возвращаю да/нет в зависимоти от того попали мы в правило или нет
{
    int ret = 0;
    const DetectS7commData *s7commd = (const DetectS7commData *) ctx;
	
    if (PKT_IS_PSEUDOPKT(p)) {
        return 0; /* fake pkt */
    }

    if (PKT_IS_IPV4(p)) {
        /* ipv4 pkt */
    } else if (PKT_IS_IPV6(p)) {
        /* ipv6 pkt */
    } else {
        SCLogDebug("packet is of not IPv4 or IPv6");
        return ret; //return 0;
    }
	
    /* packet payload access */
    if (p->payload != NULL && p->payload_len > 0) {
        if (s7commd->arg1 == p->payload[0] &&
            s7commd->arg2 == p->payload[p->payload_len - 1])
        {
            ret = 1;
        }
    }

    return ret;	//return 0;
}

/**
 * \brief This function is used to parse s7comm options passed via s7comm: keyword
 *
 * \param s7commstr Pointer to the user provided s7comm options
 *
 * \retval s7commd pointer to DetectS7commData on success
 * \retval NULL on failure
 */
static DetectS7commData *DetectS7commParse (const char *s7commstr)		//надеюсь, тут нужно разбирать пакет на кусочки, главная функа по факту
{
    char arg1[4] = "";
    char arg2[4] = "";
#define MAX_SUBSTRINGS 30
    int ov[MAX_SUBSTRINGS];

    int ret = pcre_exec(parse_regex, parse_regex_study,
                    s7commstr, strlen(s7commstr),
                    0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        return NULL;
    }

    ret = pcre_copy_substring((char *) s7commstr, ov, MAX_SUBSTRINGS, 1, arg1, sizeof(arg1));
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        return NULL;
    }
    SCLogDebug("Arg1 \"%s\"", arg1);

    ret = pcre_copy_substring((char *) s7commstr, ov, MAX_SUBSTRINGS, 2, arg2, sizeof(arg2));
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        return NULL;
    }
    SCLogDebug("Arg2 \"%s\"", arg2);

    DetectS7commData *s7commd = SCMalloc(sizeof (DetectS7commData));
    if (unlikely(s7commd == NULL))
        return NULL;

    s7commd->arg1 = (uint8_t)atoi(arg1);
    s7commd->arg2 = (uint8_t)atoi(arg2);

    return s7commd;
}

/**
 * \brief parse the options from the 's7comm' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param s7commstr pointer to the user provided s7comm options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectS7commSetup (DetectEngineCtx *de_ctx, Signature *s, const char *s7commstr)		//закидывает результаты парсинга DetectS7commParse в список. Не особо надо что-то менять
{
    DetectS7commData *s7commd = DetectS7commParse(s7commstr);
    if (s7commd == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectS7commFree(s7commd);
        return -1;
    }

    sm->type = DETECT_S7COMM;
    sm->ctx = (void *)s7commd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

/**
 * \brief this function will free memory associated with DetectS7commData
 *
 * \param ptr pointer to DetectS7commData
 */
static void DetectS7commFree(void *ptr)
{
    DetectS7commData *s7commd = (DetectS7commData *)ptr;

    /* do more specific cleanup here, if needed 
	Я думаю не надо нам, поэтому эта функа готова, УРА*/

    SCFree(s7commd);
}

#ifdef UNITTESTS
#include "tests/detect-s7comm.c"
#endif
