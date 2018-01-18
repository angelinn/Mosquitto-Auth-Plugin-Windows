/*
 * Copyright (c) 2013, 2014 Jan-Piet Mens <jp@mens.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of mosquitto nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "auth-plug.h"

#if LIBMOSQUITTO_VERSION_NUMBER >= 1004090
# define MOSQ_DENY_AUTH	MOSQ_ERR_PLUGIN_DEFER
# define MOSQ_DENY_ACL	MOSQ_ERR_PLUGIN_DEFER
#else
# define MOSQ_DENY_AUTH	MOSQ_ERR_AUTH
# define MOSQ_DENY_ACL	MOSQ_ERR_ACL_DENIED
#endif

#include "log.h"
#include "hash.h"
#include "backends.h"
#include "envs.h"

#include "be-jwt.h"

#include "userdata.h"
#include "cache.h"

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#define NBACKENDS	(5)


struct backend_p {
	void *conf;			/* Handle to backend */
	char *name;
	f_kill *kill;
	f_getuser *getuser;
	f_superuser *superuser;
	f_aclcheck *aclcheck;
};

int pbkdf2_check(char *password, char *hash);

int mosquitto_auth_plugin_version(void)
{
	log_init();
	_log(LOG_NOTICE, "*** auth-plug: startup");

	return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **userdata, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
	int i;
	char *backends = NULL, *p, *_p, *q;
	struct mosquitto_auth_opt *o;
	struct userdata *ud;
	int ret = MOSQ_ERR_SUCCESS;
	int nord;
	struct backend_p **bep;
#ifdef BE_PSK
	struct backend_p **pskbep;
	char *psk_database = NULL;
#endif

	log_init();

	OpenSSL_add_all_algorithms();

	*userdata = (struct userdata *)malloc(sizeof(struct userdata));
	if (*userdata == NULL) {
		perror("allocting userdata");
		return MOSQ_ERR_UNKNOWN;
	}

	memset(*userdata, 0, sizeof(struct userdata));
	ud = *userdata;
	ud->superusers = NULL;
	ud->fallback_be = -1;
	ud->anonusername = _strdup("anonymous");
	ud->acl_cacheseconds = 300;
	ud->auth_cacheseconds = 0;
	ud->acl_cachejitter = 0;
	ud->auth_cachejitter = 0;
	ud->aclcache = NULL;
	ud->authcache = NULL;

	/*
	 * Shove all options Mosquitto gives the plugin into a hash,
	 * and let the back-ends figure out if they have all they
	 * need upon init()
	 */

	for (i = 0, o = auth_opts; i < auth_opt_count; i++, o++) {
		// _log(LOG_DEBUG, "AuthOptions: key=%s, val=%s", o->key, o->value);

		p_add(o->key, o->value);

		if (!strcmp(o->key, "superusers"))
			ud->superusers = _strdup(o->value);
		if (!strcmp(o->key, "anonusername")) {
			free(ud->anonusername);
			ud->anonusername = _strdup(o->value);
		}
		if (!strcmp(o->key, "cacheseconds") || !strcmp(o->key, "acl_cacheseconds"))
			ud->acl_cacheseconds = atol(o->value);
		if (!strcmp(o->key, "auth_cacheseconds"))
			ud->auth_cacheseconds = atol(o->value);
		if (!strcmp(o->key, "acl_cachejitter"))
			ud->acl_cachejitter = atol(o->value);
		if (!strcmp(o->key, "auth_cacheijitter"))
			ud->auth_cachejitter = atol(o->value);
		if (!strcmp(o->key, "log_quiet")) {
			if (!strcmp(o->value, "false") || !strcmp(o->value, "0")) {
				log_quiet = 0;
			}
			else if (!strcmp(o->value, "true") || !strcmp(o->value, "1")) {
				log_quiet = 1;
			}
			else {
				_log(LOG_NOTICE, "Error: Invalid log_quiet value (%s).", o->value);
			}
		}
#if 0
		if (!strcmp(o->key, "topic_prefix"))
			ud->topicprefix = strdup(o->value);
#endif
	}

	/*
	 * Set up back-ends, and tell them to initialize themselves.
	 */


	backends = p_stab("backends");
	if (backends == NULL) {
		_fatal("No backends configured.");
	}

	_p = p = _strdup(backends);

	_log(LOG_NOTICE, "** Configured order: %s\n", p);

	ud->be_list = (struct backend_p **)malloc((sizeof(struct backend_p *)) * (NBACKENDS + 1));

	bep = ud->be_list;
	nord = 0;


	*bep = (struct backend_p *)malloc(sizeof(struct backend_p));
	memset(*bep, 0, sizeof(struct backend_p));
	(*bep)->name = strdup("jwt");
	(*bep)->conf = be_jwt_init();
	if ((*bep)->conf == NULL) {
		_fatal("%s init returns NULL", q);
	}
	(*bep)->kill = be_jwt_destroy;
	(*bep)->getuser = be_jwt_getuser;
	(*bep)->superuser = be_jwt_superuser;
	(*bep)->aclcheck = be_jwt_aclcheck;
	ud->fallback_be = ud->fallback_be == -1 ? nord : ud->fallback_be;
	// PSKSETUP;


	free(_p);

	return (ret);
}

int mosquitto_auth_plugin_cleanup(void *userdata, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
	struct userdata *ud = (struct userdata *)userdata;

	if (ud->superusers)
		free(ud->superusers);
	if (ud->anonusername)
		free(ud->anonusername);
	if (ud->aclcache != NULL) {
		struct cacheentry *a, *tmp;

		HASH_ITER(hh, ud->aclcache, a, tmp) {
			HASH_DEL(ud->aclcache, a);
			free(a);
		}
	}

	if (ud->authcache != NULL) {
		struct cacheentry *a, *tmp;

		HASH_ITER(hh, ud->authcache, a, tmp) {
			HASH_DEL(ud->authcache, a);
			free(a);
		}
	}

	if (ud->be_list) {
		struct backend_p **bep;

		for (bep = ud->be_list; bep && *bep; bep++) {
			(*bep)->kill((*bep)->conf);
			free((*bep)->name);
			free(*bep);
		}
		free(ud->be_list);
	}

	free(ud);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *userdata, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *userdata, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
	return MOSQ_ERR_SUCCESS;
}


int mosquitto_auth_unpwd_check(void *userdata, const char *username, const char *password)
{
	struct userdata *ud = (struct userdata *)userdata;
	struct backend_p **bep;
	char *phash = NULL, *backend_name = NULL;
	int match, authenticated = FALSE, nord, granted, rc, has_error = FALSE;

	if (!username || !*username || !password || !*password)
		return MOSQ_DENY_AUTH;

	_log(LOG_DEBUG, "mosquitto_auth_unpwd_check(%s)", (username) ? username : "<nil>");

	granted = auth_cache_q(username, password, userdata);
	if (granted != MOSQ_ERR_UNKNOWN) {
		_log(LOG_DEBUG, "getuser(%s) CACHEDAUTH: %d",
			username, (granted == MOSQ_ERR_SUCCESS) ? TRUE : FALSE);
		return granted;
	}

	struct backend_p *b = *ud->be_list;
	bep = ud->be_list;
	_log(LOG_DEBUG, "** checking backend %s", b->name);

	/*
	 * The ->getuser() routine can decide to authenticate by returning BACKEND_ALLOW
	 * or by setting phash to the user's PBKDF2 password hash and returning BACKEND_DEFER
	 * It can also refuse authentication by returning BACKEND_DENY.
	 */
	if (phash != NULL) {
		free(phash);
		phash = NULL;
	}
	rc = b->getuser(b->conf, username, password, &phash);
	if (rc == BACKEND_ALLOW) {
		backend_name = (*bep)->name;
		authenticated = TRUE;
		// break;
	}
	else if (rc == BACKEND_DENY) {
		authenticated = FALSE;
		backend_name = (*bep)->name;
		// break;
	}
	else if (rc == BACKEND_ERROR) {
		has_error = TRUE;
	}
	else if (phash != NULL) {
		match = pbkdf2_check((char *)password, phash);
		if (match == 1) {
			backend_name = (*bep)->name;
			authenticated = TRUE;
			/* Mark backend index in userdata so we can check
			 * authorization in this back-end only.
			 */
			 // break;
		}
	}

	_log(LOG_DEBUG, "getuser(%s) AUTHENTICATED=%d by %s",
		username, authenticated, (backend_name) ? backend_name : "none");

	if (phash != NULL) {
		free(phash);
	}

	granted = (authenticated) ? MOSQ_ERR_SUCCESS : MOSQ_DENY_AUTH;
	if (granted == MOSQ_DENY_AUTH && has_error) {
		_log(LOG_DEBUG, "getuser(%s) AUTHENTICATED=N HAS_ERROR=Y => ERR_UNKNOWN",
			username);
		granted = MOSQ_ERR_UNKNOWN;
	}
	auth_cache(username, password, granted, userdata);
	return granted;
}

int mosquitto_auth_acl_check(void *userdata, const char *clientid, const char *username, const char *topic, int access)
{
	struct userdata *ud = (struct userdata *)userdata;
	struct backend_p **bep;
	char *backend_name = NULL;
	int match = 0, authorized = FALSE, has_error = FALSE;
	int granted = MOSQ_DENY_ACL;

	if (!username || !*username) { 	// anonymous users
		username = ud->anonusername;
	}

	/* We are using pattern based acls. Check whether the username or
	 * client id contains a +, # or / and if so deny access.
	 *
	 * Without this, a malicious client may configure its username/client
	 * id to bypass ACL checks (or have a username/client id that cannot
	 * publish or receive messages to its own place in the hierarchy).
	 */
	if (username && strpbrk(username, "+#/")) {
		_log(MOSQ_LOG_NOTICE, "ACL denying access to client with dangerous username \"%s\"", username);
		return MOSQ_DENY_ACL;
	}

	if (clientid && strpbrk(clientid, "+#/")) {
		_log(MOSQ_LOG_NOTICE, "ACL denying access to client with dangerous client id \"%s\"", clientid);
		return MOSQ_DENY_ACL;
	}

	_log(LOG_DEBUG, "mosquitto_auth_acl_check(..., %s, %s, %s, %s)",
		clientid ? clientid : "NULL",
		username ? username : "NULL",
		topic ? topic : "NULL",
		access == MOSQ_ACL_READ ? "MOSQ_ACL_READ" : "MOSQ_ACL_WRITE");


	granted = acl_cache_q(clientid, username, topic, access, userdata);
	if (granted != MOSQ_ERR_UNKNOWN) {
		_log(LOG_DEBUG, "aclcheck(%s, %s, %d) CACHEDAUTH: %d",
			username, topic, access, granted);
		return (granted);
	}

	if (!username || !*username || !topic || !*topic) {
		granted = MOSQ_DENY_ACL;
		goto outout;
	}


	/* Check for usernames exempt from ACL checking, first */

	if (ud->superusers) {
		if (PathMatchSpecEx(username, ud->superusers, 0) == 0) {
			_log(LOG_DEBUG, "aclcheck(%s, %s, %d) GLOBAL SUPERUSER=Y",
				username, topic, access);
			granted = MOSQ_ERR_SUCCESS;
			goto outout;
		}
	}

	struct backend_p *b = *ud->be_list;
	bep = ud->be_list;

	match = b->superuser(b->conf, username);
	if (match == BACKEND_ALLOW) {
		_log(LOG_DEBUG, "aclcheck(%s, %s, %d) SUPERUSER=Y by %s",
			username, topic, access, b->name);
		granted = MOSQ_ERR_SUCCESS;
		goto outout;
	}
	else if (match == BACKEND_DENY) {
		_log(LOG_DEBUG, "aclcheck(%s, %s, %d) SUPERUSER=N by %s",
			username, topic, access, b->name);
		granted = MOSQ_DENY_ACL;
		goto outout;
	}
	else if (match == BACKEND_ERROR) {
		_log(LOG_DEBUG, "aclcheck(%s, %s, %d) HAS_ERROR=Y by %s",
			username, topic, access, b->name);
		has_error = TRUE;
	}


	/*
	 * Check authorization in the back-end used to authenticate the user.
	 */

	b = *ud->be_list;
	bep = ud->be_list;
	match = b->aclcheck((*bep)->conf, clientid, username, topic, access);
	if (match == BACKEND_ALLOW) {
		backend_name = b->name;
		_log(LOG_DEBUG, "aclcheck(%s, %s, %d) trying to acl with %s",
			username, topic, access, b->name);
		authorized = TRUE;
	}
	else if (match == BACKEND_DENY) {
		backend_name = b->name;
		authorized = FALSE;
	}
	else if (match == BACKEND_ERROR) {
		_log(LOG_DEBUG, "aclcheck(%s, %s, %d) HAS_ERROR=Y by %s",
			username, topic, access, b->name);
		has_error = TRUE;
	}


	_log(LOG_DEBUG, "aclcheck(%s, %s, %d) AUTHORIZED=%d by %s",
		username, topic, access, authorized, (backend_name) ? backend_name : "none");

	granted = (authorized) ? MOSQ_ERR_SUCCESS : MOSQ_DENY_ACL;

outout:	/* goto fail goto fail */

	if (granted == MOSQ_DENY_ACL && has_error) {
		_log(LOG_DEBUG, "aclcheck(%s, %s, %d) AUTHORIZED=N HAS_ERROR=Y => ERR_UNKNOWN",
			username, topic, access);
		granted = MOSQ_ERR_UNKNOWN;
	}

	acl_cache(clientid, username, topic, access, granted, userdata);
	return (granted);

}


int mosquitto_auth_psk_key_get(void *userdata, const char *hint, const char *identity, char *key, int max_key_len)
{
#if BE_PSK
	struct userdata *ud = (struct userdata *)userdata;
	struct backend_p **bep;
	char *database = p_stab("psk_database");
	char *psk_key = NULL, *username;
	int psk_found = FALSE, rc, has_error = FALSE;

	// username = malloc(strlen(hint) + strlen(identity) + 12);
	// sprintf(username, "%s-%s", hint, identity);
	username = (char *)identity;

	rc = BACKEND_DENY;
	for (bep = ud->be_list; bep && *bep; bep++) {
		struct backend_p *b = *bep;
		if (!strcmp(database, b->name)) {
			rc = b->getuser(b->conf, username, NULL, &psk_key);
			break;
		}

	}

	if (rc == BACKEND_ERROR) {
		psk_found = FALSE;
		has_error = TRUE;
	}
	else if (rc == BACKEND_DENY) {
		psk_found = FALSE;
	}
	else {
		_log(LOG_DEBUG, "psk_key_get(%s, %s) from [%s] finds PSK: %d",
			hint, identity, database,
			psk_key ? 1 : 0);

		if (psk_key != NULL) {
			strncpy(key, psk_key, max_key_len);
			psk_found = TRUE;
		}
	}

	if (psk_key != NULL) {
		free(psk_key);
	}

	// free(username);

	if (has_error) return MOSQ_ERR_UNKNOWN;
	return (psk_found) ? MOSQ_ERR_SUCCESS : MOSQ_DENY_AUTH;

#else /* !BE_PSK */
	return MOSQ_DENY_AUTH;
#endif /* BE_PSK */
}
