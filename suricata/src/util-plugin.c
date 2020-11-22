/* Copyright (C) 2020 Open Information Security Foundation
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

#include "suricata-common.h"
#include "suricata-plugin.h"
#include "util-plugin.h"

#ifdef HAVE_PLUGINS

#include <dlfcn.h>

typedef SCPlugin *(*SCPluginRegisterFunc)(void);

typedef struct PluginListNode_ {
    SCPlugin *plugin;
    void *lib;
    TAILQ_ENTRY(PluginListNode_) entries;
} PluginListNode;

/**
 * The list of loaded plugins.
 *
 * Currently only used as a place to stash the pointer returned from
 * dlopen, but could have other uses, such as a plugin unload destructor.
 */
static TAILQ_HEAD(, PluginListNode_) plugins = TAILQ_HEAD_INITIALIZER(plugins);

static TAILQ_HEAD(, SCPluginFileType_) output_types =
    TAILQ_HEAD_INITIALIZER(output_types);

static TAILQ_HEAD(, SCCapturePlugin_) capture_plugins = TAILQ_HEAD_INITIALIZER(capture_plugins);

static void InitPlugin(char *path)
{
    void *lib = dlopen(path, RTLD_NOW);
    if (lib == NULL) {
        SCLogNotice("Failed to open %s as a plugin: %s", path, dlerror());
    } else {
        SCLogNotice("Loading plugin %s", path);

        SCPluginRegisterFunc plugin_register = dlsym(lib, "SCPluginRegister");
        if (plugin_register == NULL) {
            SCLogError(SC_ERR_PLUGIN, "Plugin does not export SCPluginRegister function: %s", path);
            dlclose(lib);
            return;
        }
        SCPlugin *plugin = (*plugin_register)();
        if (plugin == NULL) {
            SCLogError(SC_ERR_PLUGIN, "Plugin registration failed: %s", path);
            dlclose(lib);
            return;
        }

        BUG_ON(plugin->name == NULL);
        BUG_ON(plugin->author == NULL);
        BUG_ON(plugin->license == NULL);
        BUG_ON(plugin->Init == NULL);

        PluginListNode *node = SCCalloc(1, sizeof(*node));
        if (node == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocated memory for plugin");
            dlclose(lib);
            return;
        }
        node->plugin = plugin;
        node->lib = lib;
        TAILQ_INSERT_TAIL(&plugins, node, entries);
        SCLogNotice("Initializing plugin %s; author=%s; license=%s", plugin->name, plugin->author,
                plugin->license);
        (*plugin->Init)();
    }
}

void SCPluginsLoad(const char *capture_plugin_name, const char *capture_plugin_args)
{
    ConfNode *conf = ConfGetNode("plugins");
    if (conf == NULL) {
        return;
    }
    ConfNode *plugin = NULL;
    TAILQ_FOREACH(plugin, &conf->head, next) {
        struct stat statbuf;
        if (stat(plugin->val, &statbuf) == -1) {
            SCLogError(SC_ERR_STAT, "Bad plugin path: %s: %s",
                plugin->val, strerror(errno));
            continue;
        }
        if (S_ISDIR(statbuf.st_mode)) {
            // coverity[toctou : FALSE]
            DIR *dir = opendir(plugin->val);
            if (dir == NULL) {
                SCLogError(SC_ERR_DIR_OPEN, "Failed to open plugin directory %s: %s",
                    plugin->val, strerror(errno));
                continue;
            }
            struct dirent *entry = NULL;
            char path[PATH_MAX];
            while ((entry = readdir(dir)) != NULL) {
                if (strstr(entry->d_name, ".so") != NULL) {
                    snprintf(path, sizeof(path), "%s/%s", plugin->val, entry->d_name);
                    InitPlugin(path);
                }
            }
            closedir(dir);
        } else {
            InitPlugin(plugin->val);
        }
    }

    if (run_mode == RUNMODE_PLUGIN) {
        SCCapturePlugin *capture = SCPluginFindCaptureByName(capture_plugin_name);
        if (capture == NULL) {
            FatalError(SC_ERR_PLUGIN, "No capture plugin found with name %s",
                    capture_plugin_name);
        }
        capture->Init(capture_plugin_args, RUNMODE_PLUGIN, TMM_RECEIVEPLUGIN,
                TMM_DECODEPLUGIN);
    }
}

/**
 * \brief Register an Eve/JSON file type plugin.
 *
 * \retval true if registered successfully, false if the plugin name
 *      conflicts with a built-in or previously registered
 *      plugin file type.
 *
 * TODO: As this is Eve specific, perhaps Eve should be in the filename.
 */
bool SCPluginRegisterFileType(SCPluginFileType *plugin)
{
    const char *builtin[] = {
        "regular",
        "syslog",
        "unix_dgram",
        "unix_stream",
        "redis",
        NULL,
    };
    for (int i = 0;; i++) {
        if (builtin[i] == NULL) {
            break;
        }
        if (strcmp(builtin[i], plugin->name) == 0) {
            SCLogNotice("Eve filetype plugin name \"%s\" conflicts "
                    "with built-in name", plugin->name);
            return false;
        }
    }

    SCPluginFileType *existing = NULL;
    TAILQ_FOREACH(existing, &output_types, entries) {
        if (strcmp(existing->name, plugin->name) == 0) {
            SCLogNotice("Eve filetype plugin name conflicts with previously "
                    "registered plugin: %s", plugin->name);
            return false;
        }
    }

    SCLogNotice("Registering JSON file type plugin %s", plugin->name);
    TAILQ_INSERT_TAIL(&output_types, plugin, entries);
    return true;
}

SCPluginFileType *SCPluginFindFileType(const char *name)
{
    SCPluginFileType *plugin = NULL;
    TAILQ_FOREACH(plugin, &output_types, entries) {
        if (strcmp(name, plugin->name) == 0) {
            return plugin;
        }
    }
    return NULL;
}

int SCPluginRegisterCapture(SCCapturePlugin *plugin)
{
    TAILQ_INSERT_TAIL(&capture_plugins, plugin, entries);
    SCLogNotice("Capture plugin registered: %s", plugin->name);
    return 0;
}

SCCapturePlugin *SCPluginFindCaptureByName(const char *name)
{
    SCCapturePlugin *plugin = NULL;
    TAILQ_FOREACH(plugin, &capture_plugins, entries) {
        if (strcmp(name, plugin->name) == 0) {
            return plugin;
        }
    }
    return plugin;
}
#endif
