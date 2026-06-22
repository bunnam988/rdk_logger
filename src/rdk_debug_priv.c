/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
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
 * @file rdk_debug_priv.c
 */


/**
* @defgroup rdk_logger
* @{
* @defgroup src
* @{
**/

#include <time.h>
#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "rdk_debug_priv.h"
#include "rdk_dynamic_logger.h"
#include "rdk_log_suppressor.h"
#include "log4c.h"
#include <log4c/appender_type_rollingfile.h>
#include <log4c/rollingpolicy.h>
#include <log4c/rollingpolicy_type_sizewin.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_SYSTEMD
#include <systemd/sd-journal.h>
#endif //HAVE_SYSTEMD

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif //HAVE_SYSLOG_H


log4c_category_t* gRootCat = NULL;
int gRootPriority = LOG4C_PRIORITY_WARN;
const char* gRootCatName = "LOG.RDK";
static pthread_mutex_t gLoggingMutex = PTHREAD_MUTEX_INITIALIZER;

/* 1024 is allowed; but lets leave some space for timestamp  */
#define LOG4C_MSG_BUFFER_SIZE   980

/* Define the priority as -ve to avoid printing */
#define LOG4C_PRIORITY_NONE     -1

/* Suppressor config — read once at init, immutable after (AC-4) */
static rdk_suppressor_config_t g_suppressor_config;

/**
 * Declare format/layout APIs.
 */
static const char* rdk_plaintext(const log4c_layout_t* a_layout, const log4c_logging_event_t* a_event);
static const char* rdk_with_ts(const log4c_layout_t* a_layout, const log4c_logging_event_t* a_event);
static const char* rdk_detail_with_ts(const log4c_layout_t* a_layout, const log4c_logging_event_t* a_event);
static const char* rdk_detail_without_ts(const log4c_layout_t* a_layout, const log4c_logging_event_t* a_event);
static const char* rdk_detail_format_handler(const log4c_layout_t* layout, const log4c_logging_event_t* event, bool isTimed);

/**
 * Initialize Layout API.
 */
static const log4c_layout_type_t log4c_layout_type_rdk_plaintext = {"format_plaintext", rdk_plaintext};
static const log4c_layout_type_t log4c_layout_type_rdk_with_ts = {"format_with_ts", rdk_with_ts};
static const log4c_layout_type_t log4c_layout_type_rdk_detail_with_ts = {"format_detail_with_ts", rdk_detail_with_ts};
static const log4c_layout_type_t log4c_layout_type_rdk_detail_without_ts = {"format_detail_without_ts", rdk_detail_without_ts};

// For backward Compatibility
static const log4c_layout_type_t log4c_layout_type_comcast_dated  = {"comcast_dated_nocr", rdk_detail_with_ts};

/**
 * Initialize Appender API.
 */
static int to_console_open(log4c_appender_t * appender);
static int to_console_append(log4c_appender_t* appender, const log4c_logging_event_t* event);
static int to_console_close(log4c_appender_t * appender);

static int to_syslog_open(log4c_appender_t * appender);
static int to_syslog_append(log4c_appender_t* appender, const log4c_logging_event_t* event);
static int to_syslog_close(log4c_appender_t * appender);

static int to_journal_open(log4c_appender_t * appender);
static int to_journal_append(log4c_appender_t* appender, const log4c_logging_event_t* event);
static int to_journal_close(log4c_appender_t * appender);

static const log4c_appender_type_t log4c_appender_type_to_console = {"to_console",
                                                                     to_console_open,
                                                                     to_console_append,
                                                                     to_console_close
                                                                    };

static const log4c_appender_type_t log4c_appender_type_to_syslog = {"to_syslog",
                                                                     to_syslog_open,
                                                                     to_syslog_append,
                                                                     to_syslog_close
                                                                    };

static const log4c_appender_type_t log4c_appender_type_to_journal = {"to_journal",
                                                                     to_journal_open,
                                                                     to_journal_append,
                                                                     to_journal_close
                                                                    };

static int rdk_logLevel_to_log4c_priority(rdk_LogLevel level)
{
     switch (level)
     {
        case RDK_LOG_FATAL:  return LOG4C_PRIORITY_FATAL;   // 000
        case RDK_LOG_ERROR:  return LOG4C_PRIORITY_ERROR;   // 300
        case RDK_LOG_WARN:   return LOG4C_PRIORITY_WARN;    // 400
        case RDK_LOG_NOTICE: return LOG4C_PRIORITY_NOTICE;  // 500
        case RDK_LOG_INFO:   return LOG4C_PRIORITY_INFO;    // 600
        case RDK_LOG_DEBUG:  return LOG4C_PRIORITY_DEBUG;   // 700
        case RDK_LOG_TRACE:  return LOG4C_PRIORITY_TRACE;   // 800
        case RDK_LOG_NONE:   return LOG4C_PRIORITY_UNKNOWN; // 1000
     }
     return LOG4C_PRIORITY_UNKNOWN;
}

#if defined(HAVE_SYSTEMD) || defined(HAVE_SYSLOG_H)
static int get_syslog_priority(int log4c_pr)
{
    int priority;
    switch(log4c_pr)
    {
    case LOG4C_PRIORITY_FATAL:
        priority = LOG_EMERG;
        break;
    case LOG4C_PRIORITY_ERROR:
        priority = LOG_ERR;
        break;
    case LOG4C_PRIORITY_WARN:
        priority = LOG_WARNING;
        break;
    case LOG4C_PRIORITY_NOTICE:
        priority = LOG_NOTICE;
        break;
    case LOG4C_PRIORITY_INFO:
        priority = LOG_INFO;
        break;
    case LOG4C_PRIORITY_DEBUG:
    case LOG4C_PRIORITY_TRACE:
    default:
        priority = LOG_DEBUG;
        break;
    }
    return priority;
}
#endif /* HAVE_SYSTEMD */

static void trim(char *instr, char* outstr)
{
    char *ptr = instr;
    char *endptr = instr + strlen(instr)-1;
    int length;

    /* Advance pointer to first non-whitespace char */
    while (isspace(*ptr))
        ptr++;

    if (ptr > endptr)
    {
        /*
         * avoid breaking things when there are
         * no non-space characters in instr (JIRA OCORI-2028)
         */
        outstr[0] = '\0';
        return;
    }

    /* Move end pointer toward the front to first non-whitespace char */
    while (isspace(*endptr))
        endptr--;

    length = endptr + 1 - ptr;
    strncpy(outstr,ptr,length);
    outstr[length] = '\0';

}

rdk_Error rdk_logger_parse_config( const char * path)
{
    FILE* f = NULL;
    const int line_buf_len = 256;
    char lineBuffer[line_buf_len];

    if (!path)
    {
        printf("Invalid config file\n");
        return RDK_FAILURE;
    }


    /* Open the env file */
    if ((f = fopen( path,"r")) == NULL)
    {
        printf("**    ERROR!  Could not open configuration file (%s)!    **\n", path);
        return RDK_FAILURE;
    }

    memset(lineBuffer, 0, line_buf_len);
    /* Read each line of the file */
    while (fgets(lineBuffer, line_buf_len, f) != NULL)
    {
        char name[line_buf_len];
        char value[line_buf_len];
        char trimname[line_buf_len];
        char trimvalue[line_buf_len];
        char *equals;
        int length;

        /* Ignore comment lines */
        if (lineBuffer[0] == '#')
            continue;

        /* Ignore lines that do not have an '=' char */
        if ((equals = strchr(lineBuffer,'=')) == NULL)
            continue;

        /* Read the property and store in the cache */
        length = equals - lineBuffer;
        strncpy(name, lineBuffer,length);
        name[length] = '\0'; /* have to null-term */

        length = lineBuffer + strlen(lineBuffer) - equals + 1;
        strncpy(value, equals+1, length);
        value[length] = '\0' ;

        /* Trim all whitespace from name and value strings */
        trim(name, trimname);
        trim(value, trimvalue);

#define COMP_SIGNATURE "LOG.RDK."
#define COMP_SIGNATURE_LEN 8
        if (strcmp("LOG.RDK.DEFAULT", trimname) == 0)
        {
            if (!gRootCat)
                gRootCat = log4c_category_get("LOG.RDK");

            if (gRootCat)
            {
                if (strcasecmp(trimvalue, "NONE") == 0)
                {
                    log4c_category_set_priority(gRootCat, LOG4C_PRIORITY_NONE);
                }
                else
                {
                    int lvl = rdk_logger_level_from_string(trimvalue);
                    if ((lvl >= RDK_LOG_FATAL) && (lvl < RDK_LOG_NONE))
                    {
                        log4c_category_set_priority(gRootCat, rdk_logLevel_to_log4c_priority(lvl));
                    }
                }
                gRootPriority = log4c_category_get_priority(gRootCat);
            }
        }
        else if (strncmp(COMP_SIGNATURE, trimname, COMP_SIGNATURE_LEN) == 0)
        {
            log4c_category_t* cat = log4c_category_get(trimname);
            if (cat)
            {
                if (strcasecmp(trimvalue, "NONE") == 0)
                {
                    log4c_category_set_priority(cat, LOG4C_PRIORITY_NONE);
                }
                else
                {
                    int lvl = rdk_logger_level_from_string(trimvalue);
                    if ((lvl >= RDK_LOG_FATAL) && (lvl < RDK_LOG_NONE))
                    {
                        log4c_category_set_priority(cat, rdk_logLevel_to_log4c_priority(lvl));
                    }
                    else
                    {
                        log4c_category_set_priority(cat, LOG4C_PRIORITY_NONE);
                    }
                }
            }
        }
    }

    fclose( f);
    return RDK_SUCCESS;
}

void rdk_dbg_priv_init(void)
{
    ///> These must be set before calling log4c_init so that the log4crc file
    ///> will configure them
    (void) log4c_layout_type_set(&log4c_layout_type_rdk_plaintext);
    (void) log4c_layout_type_set(&log4c_layout_type_rdk_with_ts);
    (void) log4c_layout_type_set(&log4c_layout_type_rdk_detail_with_ts);
    (void) log4c_layout_type_set(&log4c_layout_type_rdk_detail_without_ts);


    (void) log4c_appender_type_set(&log4c_appender_type_to_console);
    (void) log4c_appender_type_set(&log4c_appender_type_to_syslog);
    (void) log4c_appender_type_set(&log4c_appender_type_to_journal);


    if (log4c_init())
        fprintf(stderr, "log4c_init() failed?!");

    /* Register this for legacy Components */
    log4c_layout_t* legacy = log4c_layout_get("comcast_dated");
    if (NULL != legacy)
        (void) log4c_layout_set_type(legacy, &log4c_layout_type_comcast_dated);

    /* Read RFC parameters once at startup (AC-4: value fixed for process lifetime) */
    rdk_suppressor_read_config(&g_suppressor_config);
    rdk_suppressor_init(&g_suppressor_config);

    return;
}

rdk_Error rdk_dbg_priv_config(const char* debugConfigFile)
{
    rdk_Error ret = RDK_SUCCESS;
    if (debugConfigFile)
    {
        gRootCat = log4c_category_get(gRootCatName);
        if (!gRootCat)
        {
            gRootCat = log4c_category_new(gRootCatName);
            /* Get the root category */
            if (!gRootCat)
            {
                fprintf(stderr, "RDK Root Category Creation failed?!");
            }
        }
        /* Read the config file & populate pre-configured log levels */
        ret = rdk_logger_parse_config(debugConfigFile);
        /* Get the Root Priority */
        if (gRootCat)
            gRootPriority = log4c_category_get_priority(gRootCat);
    }
    else
    {
        fprintf(stderr, "Invalid conf file!");
        ret = RDK_FAILURE;
    }

    return ret;
}

rdk_Error rdk_dbg_priv_ext_init (const rdk_logger_ext_config_t* config)
{
    rdk_Error ret = RDK_SUCCESS;
    if (!config)
    {
        fprintf(stderr, "Error: config parameter is NULL\n");
        return RDK_FAILURE;
    }

    log4c_category_t* cat = NULL;
    log4c_appender_t* app = NULL;
    pthread_mutex_lock(&gLoggingMutex);
    if (config->pModuleName)
    {
        cat = log4c_category_get(config->pModuleName);
    }
    else
    {
        cat = gRootCat;
    }

    if (cat)
    {
        if ((RDKLOG_OUTPUT_FILE == config->output) && (config->pFilePolicy == NULL))
        {
            fprintf(stderr, "Error: file appender requires non-NULL file policy\n");
            app = NULL;
        }
        else
        {
            char app_name[128] = "";
            const char* cat_name = config->pModuleName ? config->pModuleName : gRootCatName;

            if (RDKLOG_OUTPUT_FILE == config->output)
            {
                snprintf(app_name, sizeof(app_name), "%s.file", cat_name);
            }
            else
            {
                snprintf(app_name, sizeof(app_name), "%s.print", cat_name);
            }

            app = log4c_appender_get(app_name);

            if (app)
            {
                if (RDKLOG_OUTPUT_CONSOLE == config->output)
                {
                    log4c_appender_set_type(app, log4c_appender_type_get("to_console"));
                }
                else if (RDKLOG_OUTPUT_SYSLOG == config->output)
                {
                    log4c_appender_set_type(app, log4c_appender_type_get("to_syslog"));
                }
                else if (RDKLOG_OUTPUT_JOURNAL == config->output)
                {
                    /* Set the Appender Type */
                    log4c_appender_set_type(app, log4c_appender_type_get("to_journal"));
                }
                else if (RDKLOG_OUTPUT_FILE == config->output)
                {
                    rdk_LogOutput_File *pPolicy = config->pFilePolicy;
                    /* Close the Appender to complete the existing file writing;
                     * Also, if the appender is NOT opened yet, log4c will take care of
                     * returning without no-op */
                    log4c_appender_close(app);

                    rollingfile_udata_t *oldData = log4c_appender_get_udata(app);
                    if (oldData)
                    {
                        free(oldData);
                        log4c_appender_set_udata(app, NULL);
                    }

                    /* Set the Appender Type */
                    log4c_appender_set_type(app, log4c_appender_type_get("rollingfile"));

                    rollingfile_udata_t *rudata = rollingfile_make_udata();
                    if (rudata)
                    {
                        rollingfile_udata_set_logdir(rudata, pPolicy->fileLocation);
                        rollingfile_udata_set_files_prefix(rudata, pPolicy->fileName);
                        if (pPolicy->fileCountMax > 0)
                        {
                            long maxBytes = (pPolicy->fileSizeMax > 0) ? pPolicy->fileSizeMax : ROLLINGPOLICY_SIZE_DEFAULT_MAX_FILE_SIZE;
                            char policy_name[128];
                            snprintf(policy_name, sizeof(policy_name), "%s.policy", app_name);

                            log4c_rollingpolicy_t *policy = log4c_rollingpolicy_get(policy_name);
                            if (policy)
                            {
                                log4c_rollingpolicy_set_type(policy, log4c_rollingpolicy_type_get("sizewin"));
                                rollingpolicy_sizewin_udata_t *sizewin_udata = sizewin_make_udata();
                                if (sizewin_udata)
                                {
                                    sizewin_udata_set_file_maxsize(sizewin_udata, maxBytes);
                                    sizewin_udata_set_max_num_files(sizewin_udata, pPolicy->fileCountMax);
                                    log4c_rollingpolicy_set_udata(policy, sizewin_udata);
                                }
                                rollingfile_udata_set_policy(rudata, policy);
                            }
                        }
                        log4c_appender_set_udata(app, rudata);
                    }
                }
            }
        }

        if (app)
        {
            log4c_layout_t* layoutObj = NULL;
            switch (config->format)
            {
                case RDKLOG_FORMAT_PLAINTEXT:
                {
                    layoutObj = log4c_layout_get("rdk_plaintext");
                    break;
                }
                case RDKLOG_FORMAT_WITH_TS:
                {
                    layoutObj = log4c_layout_get("rdk_with_ts");
                    break;
                }
                case RDKLOG_FORMAT_DETAIL_WITH_TS:
                {
                    layoutObj = log4c_layout_get("rdk_detail_with_ts");
                    break;
                }
                case RDKLOG_FORMAT_DETAIL_WITHOUT_TS:
                {
                    layoutObj = log4c_layout_get("rdk_detail_without_ts");
                    break;
                }
                default:
                {
                    layoutObj = log4c_layout_get("rdk_plaintext");
                    break;
                }
            }
            if (layoutObj)
            {
                log4c_appender_set_layout(app, layoutObj);
            }

            log4c_category_set_appender(cat, app);
            log4c_category_set_additivity(cat, 0);

            log4c_priority_level_t prio = rdk_logLevel_to_log4c_priority(config->loglevel);
            log4c_category_set_priority(cat, prio);
        }
        else
        {
            fprintf(stderr, "Failed to get or create log appender\n");
            ret = RDK_FAILURE;
        }
    }
    else
    {
        fprintf(stderr, "Failed to get or create log category\n");
        ret = RDK_FAILURE;
    }

    pthread_mutex_unlock(&gLoggingMutex);
    return ret;
}

void rdk_dbg_priv_deinit()
{
  gRootCat = NULL;
}

/**
 * Format the time into a fixed-length ISO 8601-style timestamp.
 *
 */
static void printTime(const struct tm *pTm, char *pBuff)
{
    sprintf(pBuff,"%02d-%02d-%02dT%02d:%02d:%02d",pTm->tm_year + 1900, pTm->tm_mon + 1, pTm->tm_mday, pTm->tm_hour, pTm->tm_min, pTm->tm_sec);
}

/**
 * @brief Function to check if a specific log level of a module is enabled.
 *
 * @param[in] module The module name or category for which the log level shall be checked (as mentioned in debug.ini).
 * @param[in] level The debug logging level.
 *
 * @return Returns true, if debug log level enabled successfully else returns false.
 */
bool rdk_logger_is_logLevel_enabled(const char *module, rdk_LogLevel level)
{
    bool isEnabled = false;
    log4c_category_t* cat = NULL;
    if (RDK_LOG_NONE == level)
    {
        return false;
    }
    else
    {
    
        pthread_mutex_lock(&gLoggingMutex);
        cat = log4c_category_get(module);
        if (cat)
        {
            int log4cPriority = rdk_logLevel_to_log4c_priority(level);
            if (log4c_category_is_priority_enabled(cat, log4cPriority))
            {
                isEnabled = true;
            }
        }
        else
        {
            /* Default case, return false */
            isEnabled = false;
        }
        pthread_mutex_unlock(&gLoggingMutex);
    }
    return isEnabled;
}

void rdk_dbg_priv_log_msg(rdk_LogLevel level, const char *module_name, const char* format, va_list args)
{
    log4c_category_t* cat = NULL;
    int prio = 0;

    /* Handling process request here. This is not a blocking call and it shall return immediately */
    rdk_dyn_log_process_pending_request();

    /* Check the incoming log level; dont print when it is RDK_LOG_NONE */
    if (RDK_LOG_NONE == level)
    {
        return;
    }

    pthread_mutex_lock(&gLoggingMutex);
    cat = log4c_category_get(module_name);
    if(!cat)
    {
        cat = gRootCat;
    }
    else
    {
        prio = log4c_category_get_priority(cat);
        if (LOG4C_PRIORITY_NOTSET ==  prio)
        {
            log4c_category_set_priority(cat, gRootPriority);
            prio = gRootPriority;
        }
    }

    /* To Ensure that we dont log at all when category is invalid */
    if(cat)
    {
        va_list localArg;
        char logMsg[LOG4C_MSG_BUFFER_SIZE];
        int n = 0;
        int log4cPriority = rdk_logLevel_to_log4c_priority(level);

        va_copy(localArg, args);
        n = vsnprintf(logMsg, LOG4C_MSG_BUFFER_SIZE, format, localArg);
        va_end(localArg);

        /* AC-3: Only pass messages that will actually be logged to the suppressor.
         * Messages filtered by the active log-level are completely invisible to
         * pattern tracking — not stored, not advancing state, not triggering summaries. */
        bool will_be_logged = log4c_category_is_priority_enabled(cat, log4cPriority);
        bool is_duplicate = false;

        if (will_be_logged && n > 0 && n <= LOG4C_MSG_BUFFER_SIZE)
        {
            char summary[RDK_SUPPRESSOR_MSG_SIZE] = {0};
            char *ts_line = NULL;
            rdk_suppress_action_t action =
                rdk_suppressor_process_message(module_name, logMsg, level, summary, &ts_line);

            if (action == RDK_SUPPRESS_DROP)
            {
                is_duplicate = true;
            }
            else if (action == RDK_SUPPRESS_SUMMARY)
            {
                /* AC-2: Emit summary line before the current message */
                log4c_category_log(cat, log4cPriority, "%s", summary);
                if (ts_line) {
                    log4c_category_log(cat, log4cPriority, "%s", ts_line);
                    free(ts_line);
                }
                /* is_duplicate stays false — current message must be written */
            }
            /* RDK_SUPPRESS_LOG: write normally */
        }

        /* Only log if not a duplicate */
        if (!is_duplicate)
        {
            if (n > LOG4C_MSG_BUFFER_SIZE)
            {
                // Lets allocate the memory and split into multiple chunks of LOG4C_MSG_BUFFER_SIZE
                char *p = (char*) malloc(n + 1);
                if (p)
                {
                    va_list reAllocArg;
                    int toPrint = 0;
                    int i = 0;

                    va_copy(reAllocArg, args);
                    n = vsnprintf(p, n+1, format, reAllocArg);
                    va_end(reAllocArg);

                    for (i = 0; i < n; i += toPrint)
                    {
                        toPrint = ((n - i) < LOG4C_MSG_BUFFER_SIZE) ? (n - i) : LOG4C_MSG_BUFFER_SIZE;
                        log4c_category_log(cat, log4cPriority, "%.*s\n", toPrint, p+i);
                    }
                    free(p);
                }
            }
            else
            {
                log4c_category_log(cat, log4cPriority, "%s", logMsg);
            }
        }
    }
    pthread_mutex_unlock(&gLoggingMutex);

    return;
}


bool rdk_dbg_priv_log_reconfig(const char *pModuleName, rdk_LogLevel logLevel)
{
    bool ret = true;
    log4c_category_t* cat = NULL;
    log4c_priority_level_t prio = gRootPriority; // default
    prio = rdk_logLevel_to_log4c_priority(logLevel);

    pthread_mutex_lock(&gLoggingMutex);
    if (pModuleName)
    {
        cat = log4c_category_get(pModuleName);

        if (cat) {
            log4c_category_set_priority(cat, prio);
        }
    }
    else
    {
        ret = false;
    }

    pthread_mutex_unlock(&gLoggingMutex);

    return ret;
}

/****************************************************************
 * Plain Text format with no ending carriage return / line feed
 */
static const char* rdk_plaintext(const log4c_layout_t* layout, const log4c_logging_event_t* event)
{
    (void) snprintf(event->evt_buffer.buf_data, event->evt_buffer.buf_size, "[%-5s] %s",
                                                                        log4c_priority_to_string(event->evt_priority),
                                                                        event->evt_msg);

    return event->evt_buffer.buf_data;
}

#define COMCAST_DATAED_BUFF_SIZE    40
/****************************************************************
 * With TimeStamp format with no ending carriage return / line feed
 */
static const char* rdk_with_ts(const log4c_layout_t* layout, const log4c_logging_event_t* event)
{
    struct tm tm;
    char timeBuff[COMCAST_DATAED_BUFF_SIZE] = {0};

    gmtime_r(&event->evt_timestamp.tv_sec, &tm);
    printTime(&tm,timeBuff);

    (void) snprintf(event->evt_buffer.buf_data, event->evt_buffer.buf_size, "%s.%06ld [%-5s] %s", timeBuff,
                                                                                                event->evt_timestamp.tv_usec,
                                                                                                log4c_priority_to_string(event->evt_priority),
                                                                                                event->evt_msg);

    return event->evt_buffer.buf_data;
}

/****************************************************************
 * Detailed format with/without timestamp no ending carriage return / line feed
 */
static const char* rdk_detail_format_handler(const log4c_layout_t* layout, const log4c_logging_event_t* event, bool isTimed)
{
    struct tm tm;
    char timeBuff[COMCAST_DATAED_BUFF_SIZE] = {0};

    /** Get the last part of the cagetory as "module" */
    char *p= (char *)(event->evt_category);
    if (NULL == p)
    {
        p = (char*)"UNKNOWN";
    }
    else
    {
        int len = strlen(p);
        if ( len > 0 && *p != '.' && *(p+len-1) !='.')
        {
            p = p + len - 1;
            while (p != (char *)(event->evt_category) && *p != '.') p--;
            if (*p == '.') p+=1;

        }
        else
        {
            p = (char*)"UNKNOWN";
        }
    }

    if (isTimed)
    {
        gmtime_r(&event->evt_timestamp.tv_sec, &tm);
        printTime(&tm,timeBuff);

        (void) snprintf(event->evt_buffer.buf_data, event->evt_buffer.buf_size, "%s.%06ld [%-5s] [%s] [%ld] %s",
                                                    timeBuff,
                                                    event->evt_timestamp.tv_usec,
                                                    log4c_priority_to_string(event->evt_priority),
                                                    p,
                                                    syscall(SYS_gettid),
                                                    event->evt_msg);
    }
    else
    {
        (void) snprintf(event->evt_buffer.buf_data, event->evt_buffer.buf_size, "[%-5s] [%s] [%ld] %s",
                                                    log4c_priority_to_string(event->evt_priority),
                                                    p,
                                                    syscall(SYS_gettid),
                                                    event->evt_msg);
    }

    return event->evt_buffer.buf_data;
}


/****************************************************************
 * Detailed format with timestamp
 */
static const char* rdk_detail_with_ts(const log4c_layout_t* layout, const log4c_logging_event_t* event)
{
    return rdk_detail_format_handler(layout, event, true);
}

/****************************************************************
 * Detailed format without timestamp
 */
static const char* rdk_detail_without_ts(const log4c_layout_t* layout, const log4c_logging_event_t* event)
{
    return rdk_detail_format_handler(layout, event, false);
}

/*****************************************************************/
static int to_console_open(log4c_appender_t* appender)
{
    FILE* fp = (FILE*)log4c_appender_get_udata(appender);

    if (fp)
        return 0;
    else
        fp = stdout;

    /** Set unbuffered mode */
    setbuf(fp, NULL);

    (void)log4c_appender_set_udata(appender, fp);
    return 0;
}

static int to_console_append(log4c_appender_t* appender, const log4c_logging_event_t* event)
{
    FILE* fp = (FILE*)log4c_appender_get_udata(appender);

    if (!fp)
        fp = stdout;

    fprintf(fp, "%s", event->evt_rendered_msg);
    (void)fflush(fp);

    return 0;
}

static int to_console_close(log4c_appender_t* appender)
{
    (void) appender;
    return 0;
}

static int to_syslog_open(log4c_appender_t * appender)
{
#ifdef HAVE_SYSLOG_H
    openlog(NULL, LOG_PID, LOG_USER);
#endif /* HAVE_SYSLOG_H */
    return 0;
}

static int to_syslog_append(log4c_appender_t* appender, const log4c_logging_event_t* event)
{
#ifdef HAVE_SYSLOG_H
    syslog(get_syslog_priority(event->evt_priority), "%s", event->evt_rendered_msg);
#endif /* HAVE_SYSLOG_H */
    return 0;
}

static int to_syslog_close(log4c_appender_t * appender)
{
    (void) appender;
    return 0;
}

static int to_journal_open(log4c_appender_t * appender)
{
    (void) appender;
    return 0;
}

static int to_journal_append(log4c_appender_t* appender, const log4c_logging_event_t* event)
{
#ifdef HAVE_SYSTEMD
    sd_journal_print(get_syslog_priority(event->evt_priority), "%s", event->evt_rendered_msg);
#endif /* HAVE_SYSTEMD */
    return 0;
}

static int to_journal_close(log4c_appender_t * appender)
{
    (void) appender;
    return 0;
}

/* End Of File */
