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

/*
 * TODO: Update \author in this file and in output-json-iec104.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer IEC104.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-iec104.h"
#include "output-json-iec104.h"

typedef struct LogIEC104FileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogIEC104FileCtx;

typedef struct LogIEC104LogThread_ {
    LogFileCtx *file_ctx;
    LogIEC104FileCtx *iec104log_ctx;
    MemBuffer          *buffer;
} LogIEC104LogThread;

static int JsonIEC104Logger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    IEC104Transaction *iec104tx = tx;
    LogIEC104LogThread *thread = thread_data;

    SCLogNotice("Logging iec104 transaction %"PRIu64".", iec104tx->tx_id);

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_PACKET, "iec104", NULL);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(js, "iec104");

    /* Log the request buffer. */
    if (iec104tx->request_buffer != NULL) {
        jb_set_string_from_bytes(js, "request", iec104tx->request_buffer,
                iec104tx->request_buffer_len);
    }

    /* Log the response buffer. */
    if (iec104tx->response_buffer != NULL) {
        jb_set_string_from_bytes(js, "response", iec104tx->response_buffer,
                iec104tx->response_buffer_len);
    }

    /* Close iec104. */
    jb_close(js);

    MemBufferReset(thread->buffer);
    OutputJsonBuilderBuffer(js, thread->file_ctx, &thread->buffer);

    jb_free(js);
    return TM_ECODE_OK;
}

static void OutputIEC104LogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogIEC104FileCtx *iec104log_ctx = (LogIEC104FileCtx *)output_ctx->data;
    SCFree(iec104log_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputIEC104LogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogIEC104FileCtx *iec104log_ctx = SCCalloc(1, sizeof(*iec104log_ctx));
    if (unlikely(iec104log_ctx == NULL)) {
        return result;
    }
    iec104log_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(iec104log_ctx);
        return result;
    }
    output_ctx->data = iec104log_ctx;
    output_ctx->DeInit = OutputIEC104LogDeInitCtxSub;

    SCLogNotice("IEC104 log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_IEC104);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonIEC104LogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogIEC104LogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogIEC104.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        goto error_exit;
    }

    thread->iec104log_ctx = ((OutputCtx *)initdata)->data;
    thread->file_ctx = LogFileEnsureExists(thread->iec104log_ctx->file_ctx, t->id);
    if (!thread->file_ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonIEC104LogThreadDeinit(ThreadVars *t, void *data)
{
    LogIEC104LogThread *thread = (LogIEC104LogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonIEC104LogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_IEC104, "eve-log", "JsonIEC104Log",
        "eve-log.iec104", OutputIEC104LogInitSub, ALPROTO_IEC104,
        JsonIEC104Logger, JsonIEC104LogThreadInit,
        JsonIEC104LogThreadDeinit, NULL);

    SCLogNotice("IEC104 JSON logger registered.");
}
