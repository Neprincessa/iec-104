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

#include "../suricata-common.h"
#include "../util-unittest.h"

#include "../detect-parse.h"
#include "../detect-engine.h"

#include "../detect-iec104.h"

/**
 * \test test keyword parsing
 */

static int DetectIec104ParseTest01 (void)
{
    DetectIec104Data *iec104d = DetectIec104Parse("1,10");
    FAIL_IF_NULL(iec104d);
    FAIL_IF(!(iec104d->arg1 == 1 && iec104d->arg2 == 10));
    DetectIec104Free(NULL, iec104d);
    PASS;
}

/**
 * \test test signature parsing
 */

static int DetectIec104SignatureTest01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (iec104:1,10; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectIec104
 */
void DetectIec104RegisterTests(void)
{
    UtRegisterTest("DetectIec104ParseTest01", DetectIec104ParseTest01);
    UtRegisterTest("DetectIec104SignatureTest01",
                   DetectIec104SignatureTest01);
}
