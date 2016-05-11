#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_HAVE_OPENSSL_MD5_H)
#include <openssl/md5.h>
#else
#include <md5.h>
#endif

#if (NGX_OPENSSL_MD5)
#define MD5Init     MD5_Init
#define MD5Update   MD5_Update
#define MD5Final    MD5_Final
#endif


#define OUTCOME_ERROR          -1 /* Some error occured in the process */
#define OUTCOME_DENY            0
#define OUTCOME_ALLOW           1
#define OUTCOME_CACHED_DENY     2 /* Cached results */
#define OUTCOME_CACHED_ALLOW    3
#define OUTCOME_UNCERTAIN       4 /* Not yet decided */


typedef struct {
    ngx_array_t *servers;
} ngx_http_gettoken_main_conf_t;

/*custom conf struct ngx_http_xxx_loc_conf_t*/
typedef struct ngx_http_gettoken_loc_conf_s
{
    ngx_flag_t      enable;
    ngx_str_t       auth_host;
    ngx_str_t       auth_url;
    ngx_str_t       token_host;
    ngx_str_t       token_url;
    ngx_array_t     *servers;
} ngx_http_gettoken_loc_conf_t;

typedef struct {
    ngx_str_t url;
    ngx_str_t alias;
    ngx_url_t  parsed_url;
    ngx_uint_t connections;
    ngx_msec_t connect_timeout;
    ngx_msec_t reconnect_timeout;
    ngx_msec_t request_timeout;
    ngx_msec_t request_im_token_timeout;

    ngx_queue_t free_connections;
    ngx_queue_t waiting_requests;
} ngx_http_gettoken_server_t;

typedef enum {
    PHASE_START,
    PHASE_CHECK_USER,
    PHASE_CHECK_OK,
    PHASE_NEXT
} ngx_http_gettoken_request_phase_t;

typedef struct {
    ngx_http_request_t *r;
    ngx_uint_t server_index;
    ngx_http_gettoken_server_t *server;
    ngx_http_gettoken_request_phase_t phase;
    unsigned int iteration;
    int outcome;

    struct ngx_http_gettoken_connection *c;
    ngx_queue_t queue;
    int replied;
    int error_code;
    ngx_str_t error_msg;

} ngx_http_gettoken_ctx_t;

typedef enum {
    STATE_DISCONNECTED,
    STATE_CONNECTING,
    STATE_ESTABLISHED,
    STATE_AUTH_GT_TOKEN,
    STATE_CONNECTING_IM,
    STATE_ESTABLISHED_IM,
    STATE_FETECH_IM_TOKEN,
    STATE_COMPLETED,
    STATE_READY
} ngx_http_gettoken_connection_state_t;

typedef struct ngx_http_gettoken_connection {
    ngx_log_t *log;
    ngx_http_gettoken_server_t *server;
    ngx_peer_connection_t conn;
    ngx_event_t reconnect_event;

    ngx_queue_t queue;
    ngx_http_gettoken_ctx_t *rctx;

    ngx_http_gettoken_connection_state_t state;
    int msgid;
} ngx_http_gettoken_connection_t;


static ngx_int_t ngx_http_gettoken_handler(ngx_http_request_t *r);

static void* ngx_http_gettoken_create_main_conf(ngx_conf_t *cf);
static void* ngx_http_gettoken_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_gettoken_merge_loc_conf(ngx_conf_t *cf, void* parent, void* child);

static ngx_int_t ngx_http_gettoken_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_gettoken_init_worker(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_gettoken_init_connections(ngx_cycle_t *cycle);

static void ngx_http_gettoken_connect(ngx_http_gettoken_connection_t *c);

static void ngx_http_gettoken_read_handler(ngx_event_t *rev);
static void ngx_http_gettoken_connect_handler(ngx_event_t *wev);

static void ngx_http_gettoken_reconnect_handler(ngx_event_t *ev);
static void ngx_http_gettoken_connection_cleanup(void *data);
static void ngx_http_gettoken_close_connection(ngx_http_gettoken_connection_t *c);
static void ngx_http_gettoken_wake_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_gettoken_authenticate(ngx_http_request_t *r, 
    ngx_http_gettoken_ctx_t *ctx, ngx_http_gettoken_loc_conf_t *conf);
static ngx_int_t ngx_http_gettoken_handler(ngx_http_request_t *r);

static char * ngx_http_gettoken_server_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char * ngx_http_gettoken_server(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);
static ngx_int_t ngx_http_gettoken_check_user(ngx_http_request_t *r, ngx_http_gettoken_ctx_t *ctx);

static ngx_command_t ngx_http_gettoken_commands[] = {
    {
        ngx_string("token_server"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1,
        ngx_http_gettoken_server_block,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL
    },
    {   ngx_string("auth"),
        NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_gettoken_loc_conf_t, enable),
        NULL },
    {   ngx_string("auth_host"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_gettoken_loc_conf_t, auth_host),
        NULL }, 
    {   ngx_string("auth_url"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_gettoken_loc_conf_t, auth_url),
        NULL },
    
    {   ngx_string("token_host"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_gettoken_loc_conf_t, token_host),
        NULL },
    

    {   ngx_string("token_url"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_gettoken_loc_conf_t, token_url),
        NULL },

    ngx_null_command
    };

static ngx_http_module_t ngx_http_gettoken_moudle_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_gettoken_init,                  /* postconfiguration */

    ngx_http_gettoken_create_main_conf,     /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_gettoken_create_loc_conf,       /* create location configuration */
    ngx_http_gettoken_merge_loc_conf         /* merge location configuration */
};


ngx_module_t ngx_http_gettoken_module = {
    NGX_MODULE_V1,
    &ngx_http_gettoken_moudle_ctx,
    ngx_http_gettoken_commands,
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_gettoken_init_worker,         /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_gettoken_check_user(ngx_http_request_t *r, ngx_http_gettoken_ctx_t *ctx)
{
    //ctx->outcome = OUTCOME_ALLOW;
    //return NGX_OK;
    ctx->outcome = OUTCOME_DENY;
    return NGX_DECLINED;

}

/*** Configuration and initialization ***/

/**
 * Reads token_server block and sets ngx_http_gettoken_server as a handler of each conf value
 */
static char *
ngx_http_gettoken_server_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                           *rv;
    ngx_str_t                      *value, name;
    ngx_conf_t                     save;
    ngx_http_gettoken_server_t    *server;
    ngx_http_gettoken_main_conf_t *cnf = conf;

    value = cf->args->elts;

    name = value[1];

    if (ngx_strlen(name.data) == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_gettoken: Missing server name in server");
        return NGX_CONF_ERROR;
    }

    if (cnf->servers == NULL) {
        cnf->servers = ngx_array_create(cf->pool, 6, sizeof(ngx_http_gettoken_server_t));
        if (cnf->servers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    server = ngx_array_push(cnf->servers);
    if (server == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(server, sizeof(*server));
    server->connect_timeout = 10000;
    server->reconnect_timeout = 10000;
    server->request_im_token_timeout = 5000;
    server->request_timeout = 10000;
    server->alias = name;

    save = *cf;
    cf->handler = ngx_http_gettoken_server;
    cf->handler_conf = conf;
    rv = ngx_conf_parse(cf, NULL);
    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    return NGX_CONF_OK;
}


/**
 * Parse URL conf parameter
 */
static char *
ngx_http_gettoken_parse_url(ngx_conf_t *cf, ngx_http_gettoken_server_t *server)
{
    ngx_str_t *value;
    u_char *p;
    value = cf->args->elts;
    ngx_url_t   *u = &server->parsed_url;
    ngx_memzero(u, sizeof(ngx_url_t));
    
    u->host = value[1];
    //u->no_resolve = 1;
    //u->no_port = 1;

    if (ngx_parse_url(cf->pool, u) != NGX_OK) { //解析uri，如果uri是IP:PORT形式则获取他们，如果是域名www.xxx.com形式，则解析域名
        if (u->err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "gettoken: %s in server hostname \"%V\"", u->err, &u->url);
        }

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/**
 * Called for every variable inside ldap_server block
      ldap_server cherry {
      url ldap://cherry/ou=People,DC=axa,DC=xx?uid?sub?(objectClass=person);
      binddn "uid=kibana,ou=Admins,dc=axa,dc=xx";
      binddn_passwd changeme;
      require valid_user;
      ldap_satisfy any;
      gettoken_cache_enabled false;
      connections       5;
    }
 */
static char *
ngx_http_gettoken_server(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    char                           *rv;
    ngx_str_t                      *value;
    ngx_http_gettoken_server_t    *server;
    ngx_http_gettoken_main_conf_t *cnf = conf;
    ngx_int_t                      i;

    /* It should be safe to just use latest server from array */
    server = ((ngx_http_gettoken_server_t *) cnf->servers->elts + (cnf->servers->nelts - 1));

    value = cf->args->elts;

    if (ngx_strcmp(value[0].data, "server") == 0) {
        return ngx_http_gettoken_parse_url(cf, server);
    } 

    /*
    else if (ngx_strcmp(value[0].data, "connections") == 0) {
        i = ngx_atoi(value[1].data, value[1].len);
        if (i == NGX_ERROR || i == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_gettoken: 'connections' value has to be a number greater than 0");
            return NGX_CONF_ERROR;
        }
        server->connections = i;
    } else if (ngx_strcmp(value[0].data, "ssl_check_cert") == 0  && ngx_strcmp(value[1].data, "on") == 0) {
    } else if (ngx_strcmp(value[0].data, "ssl_ca_dir") == 0) {
      server->ssl_ca_dir = value[1];
    } else if (ngx_strcmp(value[0].data, "ssl_ca_file") == 0) {
      server->ssl_ca_file = value[1];
    }
    */

    rv = NGX_CONF_OK;

    return rv;
}

static int
ngx_http_gettoken_get_connection(ngx_http_gettoken_ctx_t *ctx)
{
    ngx_http_gettoken_server_t *server;
    ngx_queue_t *q;
    ngx_http_gettoken_connection_t *c;

    /*
     * If we already have a connection, just say we got them one.
     */
    if (ctx->c != NULL)
        return 1;

    server = ctx->server;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->r->connection->log, 0, "http_gettoken: Wants a free connection to \"%V\"",
        &server->alias);

    if (!ngx_queue_empty(&server->free_connections)) {
        q = ngx_queue_last(&server->free_connections);
        ngx_queue_remove(q);
        c = ngx_queue_data(q, ngx_http_gettoken_connection_t, queue);
        c->rctx = ctx;
        ctx->c = c;
        ctx->replied = 0;
        return 1;
    }

    ngx_queue_insert_head(&server->waiting_requests, &ctx->queue);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->r->connection->log, 0, "http_gettoken: No connection available at the moment, waiting...");
    return 0;
}

static void
ngx_http_gettoken_return_connection(ngx_http_gettoken_connection_t *c)
{
    ngx_queue_t *q;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: Marking the connection to \"%V\" as free",
        &c->server->alias);

    if (c->rctx != NULL) {
        c->rctx->c = NULL;
        c->rctx = NULL;
        c->msgid = -1;
        c->state = STATE_READY;
    }

    ngx_queue_insert_head(&c->server->free_connections, &c->queue);
    if (!ngx_queue_empty(&c->server->waiting_requests)) {
        q = ngx_queue_last(&c->server->waiting_requests);
        ngx_queue_remove(q);
        ngx_http_gettoken_wake_request((ngx_queue_data(q, ngx_http_gettoken_ctx_t, queue))->r);
    }
}

static void
ngx_http_gettoken_reply_connection(ngx_http_gettoken_connection_t *c, int error_code, char* error_msg)
{
    ngx_http_gettoken_ctx_t *ctx = c->rctx;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: LDAP request to \"%V\" has finished",
        &c->server->alias);

    ctx->replied = 1;
    ctx->error_code = error_code;
    if (error_msg) {
        ctx->error_msg.len = ngx_strlen(error_msg);
        ctx->error_msg.data = ngx_palloc(ctx->r->pool, ctx->error_msg.len);
        ngx_memcpy(ctx->error_msg.data, error_msg, ctx->error_msg.len);
    } else {
        ctx->error_msg.len = 0;
        ctx->error_msg.data = NULL;
    }

    ngx_http_gettoken_wake_request(ctx->r);
}

static void
ngx_http_gettoken_dummy_write_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "http_gettoken: Dummy write handler");

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_gettoken_close_connection(((ngx_connection_t *) wev->data)->data);
    }
}


#if (NGX_OPENSSL)
/* Make sure the event handlers are activated. */
static ngx_int_t
ngx_http_gettoken_restore_handlers(ngx_connection_t *conn)
{
    ngx_int_t rc;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, conn->log, 0, "http_gettoken: Restoring event handlers. read=%d write=%d", conn->read->active, conn->write->active);

    if (!conn->read->active) {
        rc = ngx_add_event(conn->read, NGX_READ_EVENT, 0);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    if (!conn->write->active &&
        (conn->write->handler != ngx_http_gettoken_dummy_write_handler)) {
        rc = ngx_add_event(conn->write, NGX_WRITE_EVENT, 0);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}
#endif

static void
ngx_http_gettoken_connection_established(ngx_http_gettoken_connection_t *c)
{
    ngx_connection_t *conn;
    ngx_int_t rc;

    conn = c->conn.connection;
    ngx_del_timer(conn->read);
    conn->write->handler = ngx_http_gettoken_dummy_write_handler;


    /* Initialize OpenLDAP on the connection */
    //

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: Initializing connection using URL \"%V\"", &c->server->url);
    /*
    rc = ldap_init_fd(c->conn.connection->fd, LDAP_PROTO_EXT, (const char *) c->server->url.data, &c->ld);
    if (rc != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, c->log, errno, "http_gettoken: ldap_init_fd() failed (%d: %s)", rc, ldap_err2string(rc));
        ngx_http_gettoken_close_connection(c);
        return;
    }


    */
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: Connection initialized");


    /* Perform initial bind to the server */
    /*
    rc = ldap_sasl_bind(c->ld, (const char *) c->server->bind_dn.data, LDAP_SASL_SIMPLE, &cred, NULL, NULL, &c->msgid);
    if (rc != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_gettoken: ldap_sasl_bind() failed (%d: %s)",
            rc, ldap_err2string(rc));
        ngx_http_gettoken_close_connection(c);
        return;
    }*/
    //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: ldap_sasl_bind() -> msgid=%d", c->msgid);
    c->state = STATE_FETECH_ACCESS_TOKEN;
    ngx_add_timer(c->conn.connection->read, c->server->request_im_token_timeout);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: bind_timeout=%d", c->server->request_im_token_timeout);
}

/* ngx_http_core_run_phases会遍历所有的phase，然后调用它的checker进行处理，phase处理过程中的错误处理，校验等都是在checker中完成的，不同phase的checker的逻辑是不同，但是返回值的意义是相同的，如果checker的返回值时NGX_OK表示请求处理完毕，否则会进入下一个handler继续处理。接下来看一下phase的checker */
static void
ngx_http_gettoken_wake_request(ngx_http_request_t *r)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_gettoken: Waking authentication request \"%V\"",
        &r->request_line);
    ngx_http_core_run_phases(r);
}

static void
ngx_http_gettoken_close_connection(ngx_http_gettoken_connection_t *c)
{
    ngx_queue_t *q;


    if (c->conn.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: Closing connection (fd=%d)",
            c->conn.connection->fd);

        ngx_close_connection(c->conn.connection);
        c->conn.connection = NULL;
    }
    
    q = ngx_queue_head(&c->server->free_connections);
    while (q != ngx_queue_sentinel(&c->server->free_connections)) {
        if (q == &c->queue) {
            ngx_queue_remove(q);
            break;
        }
        q = ngx_queue_next(q);
    }
   
    c->rctx = NULL;
    if (c->state != STATE_DISCONNECTED) {
        c->state = STATE_DISCONNECTED;
        ngx_add_timer(&c->reconnect_event, c->server->reconnect_timeout);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: Connection scheduled for reconnection in %d ms", c->server->reconnect_timeout);
    }
}


static void
ngx_http_gettoken_connection_cleanup(void *data)
{
    ngx_http_gettoken_close_connection((ngx_http_gettoken_connection_t *) data);
}

static void
ngx_http_gettoken_reconnect_handler(ngx_event_t *ev)
{
    ngx_connection_t *conn = ev->data;
    ngx_http_gettoken_connection_t *c = conn->data;
    ngx_http_gettoken_connect(c);
}

static void
ngx_http_gettoken_connect_handler(ngx_event_t *wev)
{
    ngx_connection_t *conn;
    ngx_http_gettoken_connection_t *c;
    int keepalive;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "http_gettoken: Connect handler");

    conn = wev->data;
    c = conn->data;

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_gettoken_close_connection(c);
        return;
    }

    keepalive = 1;
    if (setsockopt(conn->fd, SOL_SOCKET, SO_KEEPALIVE, (const void *) &keepalive, sizeof(int)) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno, "http_gettoken: setsockopt(SO_KEEPALIVE) failed");
    }


    ngx_http_gettoken_connection_established(c);
}

static void
ngx_http_gettoken_read_handler(ngx_event_t *rev)
{
    ngx_connection_t *conn;
    ngx_http_gettoken_connection_t *c;
    ngx_int_t rc;
    struct timeval timeout = {0, 0};
    int error_code;
    char *error_msg;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http_gettoken: Read handler");

    conn = rev->data;
    c = conn->data;

//    if (c->ld == NULL) {
//        ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_gettoken: Could not connect");
//        ngx_http_gettoken_close_connection(c);
//        return;
//    }
//
    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT, "http_gettoken: Request timed out (state=%d)", c->state);
        conn->timedout = 1;
        ngx_http_gettoken_close_connection(c);
        return;
    }

    c->log->action = "reading response from LDAP";

    for (;;) {
        //rc = ldap_result(c->ld, LDAP_RES_ANY, 0, &timeout, &result);
        rc = 0;
      // if (rc < 0) {
      //      ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_gettoken: ldap_result() failed (%d: %s)",
      //          rc, ldap_err2string(rc));
      //      ngx_http_gettoken_close_connection(c);
      //      return;
      //  }
      //  if (rc == 0) {
      //      ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: ldap_result() -> rc=0");
      //      break;
      //  }
      //  ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: ldap_result() -> rc=%d, msgid=%d, msgtype=%d",
      //      rc, ldap_msgid(result), ldap_msgtype(result));

      //  if (ldap_msgid(result) != c->msgid) {
      //      ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: Message with unknown ID received, ignoring.");
      //      ldap_msgfree(result);
      //      continue;
      //  }

      //  rc = ldap_parse_result(c->ld, result, &error_code, NULL, &error_msg, NULL, NULL, 0);
      //  if (rc == LDAP_NO_RESULTS_RETURNED) {
      //      error_code = LDAP_NO_RESULTS_RETURNED;
      //      error_msg = NULL;
      //  } else if (rc != LDAP_SUCCESS) {
      //      ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_gettoken: ldap_parse_result() failed (%d: %s)",
      //          rc, ldap_err2string(rc));
      //      ldap_msgfree(result);
      //      ngx_http_gettoken_close_connection(c);
      //      return;
      //  }

        switch (c->state) {
          //  case STATE_INITIAL_BINDING:
          //      if (ldap_msgtype(result) != LDAP_RES_BIND) {
          //          break;
          //      }
          //      ngx_del_timer(conn->read);
          //      if (error_code == LDAP_SUCCESS) {
          //          ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: Initial bind successful");
          //          c->state = STATE_READY;
          //          ngx_http_gettoken_return_connection(c);
          //      } else {
          //          ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_gettoken: Initial bind failed (%d: %s [%s])",
          //              error_code, ldap_err2string(error_code), error_msg ? error_msg : "-");
          //          ldap_memfree(error_msg);
          //          ldap_msgfree(result);
          //          ngx_http_gettoken_close_connection(c);
          //          return;
          //      }
          //      break;

            //case STATE_BINDING:
            //    if (ldap_msgtype(result) != LDAP_RES_BIND) {
            //        break;
            //    }
            //    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: Received bind response (%d: %s [%s])",
            //        error_code, ldap_err2string(error_code), error_msg ? error_msg : "-");
            //    ngx_http_gettoken_reply_connection(c, error_code, error_msg);
            //      break;

            //case STATE_SEARCHING:
              //  if (ldap_msgtype(result) == LDAP_RES_SEARCH_ENTRY) {
              //      ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: Received a search entry");
              //      if (c->rctx->dn.data == NULL) {
              //          dn = ldap_get_dn(c->ld, result);
              //          if (dn != NULL) {
              //              ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: Found entry with DN \"%s\"", dn);
              //              c->rctx->dn.len = ngx_strlen(dn);
              //              c->rctx->dn.data = (u_char *) ngx_palloc(c->rctx->r->pool, c->rctx->dn.len + 1);
              //              ngx_memcpy(c->rctx->dn.data, dn, c->rctx->dn.len + 1);
              //              ldap_memfree(dn);
              //          }
              //      }
              //  } else if (ldap_msgtype(result) == LDAP_RES_SEARCH_RESULT) {
              //      ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: Received search result (%d: %s [%s])",
              //          error_code, ldap_err2string(error_code), error_msg ? error_msg : "-");
              //      ngx_http_gettoken_reply_connection(c, error_code, error_msg);
              //  }
              //  break;

            //case STATE_COMPARING:
             //   if (ldap_msgtype(result) != LDAP_RES_COMPARE) {
             //       break;
             //   }
             //   ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: Received comparison result (%d: %s [%s])",
             //       error_code, ldap_err2string(error_code), error_msg ? error_msg : "-");
             //   ngx_http_gettoken_reply_connection(c, error_code, error_msg);
             //     break;

            default:
                break;
        }

        //ldap_memfree(error_msg);
        //ldap_msgfree(result);
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_gettoken_close_connection(c);
        return;
    }
}

static ngx_int_t
ngx_http_gettoken_init_connections(ngx_cycle_t *cycle)
{
    ngx_http_gettoken_connection_t *c;
    ngx_http_gettoken_main_conf_t *halmcf;
    ngx_http_gettoken_server_t *server;
    ngx_pool_cleanup_t *cleanup;
    ngx_connection_t *dummy_conn;
    ngx_uint_t i, j;
    int option;

    halmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_gettoken_module);
    if (halmcf == NULL || halmcf->servers == NULL) {
        return NGX_OK;
    }


    for (i = 0; i < halmcf->servers->nelts; i++) {
        server = &((ngx_http_gettoken_server_t *) halmcf->servers->elts)[i];
        ngx_queue_init(&server->free_connections);
        ngx_queue_init(&server->waiting_requests);
        if (server->connections <= 1) {
            server->connections = 1;
        }

        for (j = 0; j < server->connections; j++) {
            c = ngx_pcalloc(cycle->pool, sizeof(ngx_http_gettoken_connection_t));
            cleanup = ngx_pool_cleanup_add(cycle->pool, 0);
            dummy_conn = ngx_pcalloc(cycle->pool, sizeof(ngx_connection_t));
            if (c == NULL || cleanup == NULL || dummy_conn == NULL) {
                return NGX_ERROR;
            }

            cleanup->handler = &ngx_http_gettoken_connection_cleanup;
            cleanup->data = c;

            c->log = cycle->log;
            c->server = server;
            c->state = STATE_DISCONNECTED;

            /* Various debug logging around timer management assume that the field
               'data' in ngx_event_t is a pointer to ngx_connection_t, therefore we
               have a dummy such structure around so that it does not crash etc. */
            dummy_conn->data = c;
            c->reconnect_event.log = c->log;
            c->reconnect_event.data = dummy_conn;
            c->reconnect_event.handler = ngx_http_gettoken_reconnect_handler;


            ngx_http_gettoken_connect(c);
        }
    }

    return NGX_OK;

}

static void
ngx_http_gettoken_connect(ngx_http_gettoken_connection_t *c)
{
    ngx_peer_connection_t *pconn;
    ngx_connection_t *conn;
    ngx_addr_t *addr;
    ngx_int_t rc;

    addr = &c->server->parsed_url.addrs[ngx_random() % c->server->parsed_url.naddrs];

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: Connecting to LDAP server \"%V\".",
        &addr->name);

    pconn = &c->conn;
    pconn->sockaddr = addr->sockaddr;
    pconn->socklen = addr->socklen;
    pconn->name = &addr->name;
    pconn->get = ngx_event_get_peer;
    pconn->log = c->log;
    pconn->log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(pconn);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: ngx_event_connect_peer() -> %d.", rc);
    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_gettoken: Unable to connect to LDAP server \"%V\".",
            &addr->name);
        ngx_add_timer(&c->reconnect_event, c->server->reconnect_timeout);
        return;
    }

    conn = pconn->connection;
    conn->data = c;

    conn->write->handler = ngx_http_gettoken_connect_handler;
    conn->read->handler = ngx_http_gettoken_read_handler;
    ngx_add_timer(conn->read, c->server->connect_timeout);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_gettoken: connect_timeout=%d.", c->server->connect_timeout);


    c->state = STATE_CONNECTING;
}

static ngx_int_t
ngx_http_gettoken_init_worker(ngx_cycle_t *cycle)
{
    ngx_int_t rc;
    if (ngx_process != NGX_PROCESS_SINGLE && ngx_process != NGX_PROCESS_WORKER) {
    return NGX_OK;
    }
    
    rc = ngx_http_gettoken_init_connections(cycle);
    if (rc != NGX_OK) {
        return rc;
    }

    return NGX_OK;

}

static ngx_int_t
ngx_http_gettoken_handler(ngx_http_request_t *r)
{
    ngx_http_gettoken_loc_conf_t *lcf;
    ngx_http_gettoken_ctx_t *ctx;
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_gettoken_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_gettoken_module);
    if (ctx == NULL) {

//        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_gettoken: Username is \"%V\"",
//            &r->headers_in.user);
//        if (r->headers_in.passwd.len == 0)
//        {
//            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_gettoken: Password is empty");
//            return ngx_http_gettoken_set_realm(r, &alcf->realm);
//        }
//
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_gettoken_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ctx->r = r;
        /* Other fields have been initialized to zero/NULL */
        ngx_http_set_ctx(r, ctx, ngx_http_gettoken_module);
    }

    if (! lcf->enable) {
        return NGX_OK;
    }

    if (! lcf->auth_host.len)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "auth enable, but auth_host not configured!");
        return NGX_HTTP_FORBIDDEN;
    }

    if (! lcf->auth_url.len)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "auth enable, but auth_url not configured!");
        return NGX_HTTP_FORBIDDEN;
    }
    if (! lcf->token_host.len)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "token_host not configured!");
        return NGX_HTTP_FORBIDDEN;
    }
    if (! lcf->token_url.len)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "token_url not configured!");
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_OK;
}



/**
 * Iteratively handle all phases of the authentication process, might be called many times
 */
static ngx_int_t
ngx_http_gettoken_authenticate(ngx_http_request_t *r, ngx_http_gettoken_ctx_t *ctx,
        ngx_http_gettoken_loc_conf_t *conf)
{
    ngx_int_t rc;

    if (r->connection->write->timedout) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_gettoken: Authentication timed out");
        if (ctx->c != NULL) {
            ngx_http_gettoken_return_connection(ctx->c);
        }
        return NGX_ERROR;
    }

    /*
     * If we are not starting up a request (ctx->phase != PHASE_START) and we actually already
     * sent a request (ctx->iteration > 0) and didn't receive a reply yet (!ctx->replied) we
     * ask to be called again at a later time when we hopefully have received a reply.
     *
     * It is quite possible that we reach this if while not having sent a request yet (ctx->iteration == 0) -
     * this happens when we are trying to get an LDAP connection but all of them are busy right now.
     */
    if (ctx->iteration > 0 && !ctx->replied && ctx->phase != PHASE_START) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_gettoken: The LDAP operation did not finish yet");
        return NGX_AGAIN;
    }

    for (;;) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_gettoken: Authentication loop (phase=%d, iteration=%d)",
            ctx->phase, ctx->iteration);

        switch (ctx->phase) {
            case PHASE_START:
                ctx->server = ((ngx_http_gettoken_server_t **) conf->servers->elts)[ctx->server_index];
                ctx->outcome = OUTCOME_UNCERTAIN;

                ngx_add_timer(r->connection->write, ctx->server->request_timeout);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_gettoken: request_timeout=%d",ctx->server->request_timeout);

                ctx->iteration = 0;
                ctx->phase = PHASE_CHECK_USER;
                break;

            case PHASE_CHECK_USER:
                //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_gettoken: User DN is \"%V\"", &ctx->dn);

                    rc = ngx_http_gettoken_check_user(r, ctx);
                    if (rc != NGX_OK) {
                        //ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_gettoken: Not ok", &ctx->dn);
                        /* User check failed, try next server */
                        ctx->phase = PHASE_NEXT;
                        break;
                    }

                /* User not yet fully authenticated, check group next */

                /* No groups to validate, try binding next */
                ctx->phase = PHASE_CHECK_OK;
                ctx->iteration = 0;
                break;



            case PHASE_NEXT:
                if (r->connection->write->timer_set) {
                    ngx_del_timer(r->connection->write);
                }

                if (ctx->c != NULL) {
                    ngx_http_gettoken_return_connection(ctx->c);
                }
                /*
                if (ngx_http_gettoken_cache.buckets != NULL &&
                    (ctx->outcome == OUTCOME_DENY || ctx->outcome == OUTCOME_ALLOW)) {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_gettoken: Caching outcome %d", ctx->outcome);
                    ngx_http_gettoken_update_cache(ctx, &ngx_http_gettoken_cache, ctx->outcome);
                }
                */
                if (ctx->outcome == OUTCOME_ALLOW || ctx->outcome == OUTCOME_CACHED_ALLOW) {
                    return NGX_OK;
                }

                ctx->server_index++;
                //if (ctx->server_index >= conf->servers->nelts) {
                //    return ngx_http_gettoken_set_realm(r, &conf->realm);
                //}

                ctx->phase = PHASE_START;
                break;
        }
    }
}




static void* 
ngx_http_gettoken_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_gettoken_main_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_gettoken_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    
    return conf;
}

static void*
ngx_http_gettoken_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_gettoken_loc_conf_t * conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_gettoken_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->enable = NGX_CONF_UNSET;  
    conf->servers = NGX_CONF_UNSET_PTR;
    return conf;
}

static char*
ngx_http_gettoken_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_gettoken_loc_conf_t *prev = parent;
    ngx_http_gettoken_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->auth_host, prev->auth_host, "");
    ngx_conf_merge_str_value(conf->auth_url, prev->auth_url, "");
    ngx_conf_merge_str_value(conf->token_host, prev->token_host, "");
    ngx_conf_merge_str_value(conf->token_url, prev->token_url, "");
    ngx_conf_merge_ptr_value(conf->servers, prev->servers, NULL);
    return    NGX_CONF_OK;

}

//ngx_http_module_t 模块定义在 postconfiguration后调用
static ngx_int_t
ngx_http_gettoken_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt             *h;
    ngx_http_core_main_conf_t       *cmcf;
    
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_gettoken_handler;
    return NGX_OK;

}


