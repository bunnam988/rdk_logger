/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file rdk_log_suppressor_summary.h
 * @brief Internal header — summary formatter used by the engine.
 */

#ifndef _RDK_LOG_SUPPRESSOR_SUMMARY_H
#define _RDK_LOG_SUPPRESSOR_SUMMARY_H

#include "rdk_log_suppressor.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Format a [SUPPRESS] summary string into @p out.
 *
 * AC-2 format:
 *   Single-message:  [SUPPRESS] "<message>" repeated N times
 *                    (behavior detail, HH:MM:SS-HH:MM:SS)
 *   Multi-message:   [SUPPRESS] L-message pattern repeated N times
 *                    (behavior detail, HH:MM:SS-HH:MM:SS)
 *
 * Only called when repeat_count > 0 (i.e. something was actually suppressed).
 *
 * @param[in]  state      Current engine state (pattern_length, repeat_count, timestamps).
 * @param[in]  config     Suppressor config (max_pattern_length for bounds check).
 * @param[out] out        Output buffer for the formatted summary line.
 * @param[in]  out_sz     Size of @p out in bytes.
 * @param[out] ts_out     If non-NULL and event is sporadic, receives a malloc'd
 *                        timestamp string ("  At: ...\\n"). Caller must free().
 *                        Set to NULL if no timestamps to report.
 */
void rdk_suppressor_format_summary(
    const rdk_suppressor_state_t  *state,
    const rdk_suppressor_config_t *config,
    char                          *out,
    size_t                         out_sz,
    char                         **ts_out);

#ifdef __cplusplus
}
#endif

#endif /* _RDK_LOG_SUPPRESSOR_SUMMARY_H */
