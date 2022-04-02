// date: 2022.3.19
// author: chendaole
// email: 1174250185@qq.com
// desc: 中间件

#ifndef TINY_GIN_H
#define TINY_GIN_H

#include <regex.h>
#include "thirdpard/http_parser/http_parser.h"

typedef enum {
    OK = 200,
    BAD_REQUEST = 400,
    NOT_FOUND = 404,
    NOT_METHOD_ALLOWED = 405,
    INTERNAL_SERVER_ERROR = 500,
} tiny_gin_code;

typedef enum {
    TEXT_HTML = 0,
    APPLICATION_JSON = 1,
}tiny_gin_content_type;

typedef enum {
    DELETE = 0,
    GET = 1,
    HEAD = 2,
    POST = 3,
    PUT = 4,
}tiny_gin_method;

typedef struct {
    tiny_gin_content_type s_content_type;
    char *s_data;
    size_t s_data_n;
} tiny_gin_body;

typedef struct {
    char *absolute_path;
    size_t absolute_path_n;
}_tiny_gin_closure_static_dir ;

typedef struct {
    int receive_fd;
    tiny_gin_method method;
    char *url;
    size_t url_n;
    void *body;
    size_t body_n;
    void *handle_funcs;
    size_t handle_funcs_n;
    size_t handle_funcs_exec_n;
    void *s_closure;
    regmatch_t *s_url_regmatch;
    size_t s_url_regmatch_n;
} tiny_gin_context;

typedef void (*tiny_gin_handle_func)(tiny_gin_context *);


typedef struct {
    char *path;
    size_t path_n;
    tiny_gin_method method;
    tiny_gin_handle_func *handle_funcs;
    size_t handle_funcs_n;
    int root;
    void *s_engine;
    void *s_closure;
} tiny_gin_router_group;

typedef struct {
    tiny_gin_router_group *s_router_group;
    void *next;
} tiny_gin_router_node;

typedef struct {
    tiny_gin_router_group *s_router_group;
    tiny_gin_router_node *router_trees;
    tiny_gin_router_group *s_recycled_router_groups;
    size_t s_recycled_router_groups_n;
} tiny_gin_engine;


tiny_gin_engine *new_router_engine_default();

void tiny_gin_any(tiny_gin_router_group *s_router_group, tiny_gin_method s_method, const char *relative_path, \
            tiny_gin_handle_func s_handle_func, void *s_closure);

void tiny_gin_get(tiny_gin_router_group *s_router_group, const char *path, tiny_gin_handle_func s_handle_func);

void tiny_gin_post(tiny_gin_router_group *s_router_group, const char *path, tiny_gin_handle_func s_handle_func);

//int tiny_gin_static_dir(tiny_gin_router_group *s_router_group, const char *relative_path, const char *root);

void tiny_gin_run(int receive_fd, tiny_gin_engine *s_engine);

void tiny_gin_render_json(tiny_gin_context *ctx, tiny_gin_code code, const char* data, size_t data_n);

int tiny_gin_render_html(tiny_gin_context *ctx, tiny_gin_code code, const char *data, size_t data_n);

int tiny_gin_render_html_file(tiny_gin_context *ctx, tiny_gin_code code, const char *relative_path);

void tiny_gin_middleware_logger(tiny_gin_context *ctx);
#endif