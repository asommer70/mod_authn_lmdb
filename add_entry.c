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

#include <stdio.h>
#include <openssl/sha.h>
#include "lmdb.h"
#include <unistd.h>
#include <string.h>
#include <apr-1.0/apr_sha1.h>
#include <termios.h>


int main(int argc, char * argv[]) {
	if ( argc != 4 ) {
        	printf( "Usage: %s <lmdb directory> <username> <password>\n\n", argv[0] );
        	return 1;
  	}

	int rc;
	MDB_env *env;
	MDB_dbi dbi;
	MDB_val key, data;
	MDB_txn *txn;

        // Setup the LMDB environment and DB connection.
	rc = mdb_env_create(&env);
	rc = mdb_env_open(env, argv[1], 0, 0664);
	if (rc) {
		fprintf(stderr, "mdb_env_open: (%d) %s\n", rc, mdb_strerror(rc));
	}
	rc = mdb_txn_begin(env, NULL, 0, &txn);
	rc = mdb_open(txn, NULL, 0, &dbi);

        char cpw[120];

        // Create the SHA1 hash using Apache apr library.
        apr_sha1_base64(argv[3], (int)strlen(argv[3]), cpw);

        // Setup the query structs.
	key.mv_size = strlen(argv[2]);
	key.mv_data = argv[2];
	data.mv_size = strlen(cpw);
	data.mv_data = &cpw;

	rc = mdb_put(txn, dbi, &key, &data, 0);
	if (rc) {
		fprintf(stderr, "mdb_put: (%d) %s\n", rc, mdb_strerror(rc));
	}
	rc = mdb_txn_commit(txn);
	if (rc) {
		fprintf(stderr, "mdb_txn_commit: (%d) %s\n", rc, mdb_strerror(rc));
	}

	mdb_close(env, dbi);
	mdb_env_close(env);
        printf("added user: %s\n", argv[2]);
    return 0;
}
