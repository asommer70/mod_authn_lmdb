/* Copyright 2013 by Adam Sommer <asommer70@gmail.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * See LICENSE file.
 */

#include "apr_strings.h"
#include "apr_md5.h"            /* for apr_password_validate */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

#include "mod_auth.h"

#include <openssl/sha.h>
#include "lmdb.h"
#include <unistd.h>

module AP_MODULE_DECLARE_DATA authn_lmdb_module;

typedef struct {
    char *lmdb_dir;
} authn_lmdb_config_rec;

authn_lmdb_config_rec lmdb_conf;

static const char *set_authn_lmdb(cmd_parms *cmd, void *dummy, char *path)
{

    /*
     *
     * Check that the directory exists and it is in fact a directory.
     *
    */
    if (0 != access(path, F_OK)) {
        if (ENOENT == errno) {
            return apr_pstrcat(cmd->pool, "lmdb directory does not exist: ", path, NULL);
        }
        if (ENOTDIR == errno) {
             return apr_pstrcat(cmd->pool, "Invalid lmdb dir: ", path, NULL);
        }
    } else {
        lmdb_conf.lmdb_dir = path;
        return NULL;
    }
}

static const command_rec authn_lmdb_cmds[] =
{
    AP_INIT_TAKE1("AuthLmdbDir", 
        set_authn_lmdb, 
        NULL,
        OR_AUTHCFG, 
        "directory path containing lmdb files"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authn_lmdb_module;

static authn_status check_lmdb(request_rec *r, char *user, const char *password) {
    int rc;
    MDB_env *env;
    MDB_dbi dbi;
    MDB_val key, data;
    MDB_txn *txn;
    apr_status_t status;
   
    // Setup the lmdb "query struct".
    key.mv_size = strlen(user);
    key.mv_data = user;
    data.mv_size = SHA_DIGEST_LENGTH*2;

    // Setup the LMDB environment and DB connection.
    rc = mdb_env_create(&env);
    rc = mdb_env_open(env, lmdb_conf.lmdb_dir, MDB_RDONLY, 0664);
    if (rc) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, "Error with lmdb directory: %s", mdb_strerror(rc));
        return AUTH_GENERAL_ERROR;
    }

    // Query lmdb for the username.
    rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
    rc = mdb_open(txn, NULL, 0, &dbi);
    rc = mdb_get(txn, dbi, &key, &data);
    if (rc != 0) {
        mdb_txn_abort(txn);
        mdb_dbi_close(env, dbi);
        mdb_env_close(env);
        return AUTH_USER_NOT_FOUND;
    }

    // Check the password.
    status = apr_password_validate(password, (char *)data.mv_data);
    if (status != APR_SUCCESS) {
        mdb_txn_abort(txn);
        mdb_dbi_close(env, dbi);
        mdb_env_close(env);
        return AUTH_DENIED;
    }

    // Yay, everything checks out, so clean up and stuff.
    mdb_txn_abort(txn);
    mdb_dbi_close(env, dbi);
    mdb_env_close(env);
    return AUTH_GRANTED;
}

static const authn_provider authn_lmdb_provider =
{
    &check_lmdb,
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "lmdb", "0",
                         &authn_lmdb_provider);
}

module AP_MODULE_DECLARE_DATA authn_lmdb_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,	                     /* dir config creatr */
    NULL,                            /* dir merger --- default is to override */
    NULL,                            /* server config */
    NULL,                            /* merge server config */
    authn_lmdb_cmds,                 /* command apr_table_t */
    register_hooks                   /* register hooks */
};
