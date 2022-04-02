#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <string.h>
#include <regex.h>
#include "tiny_gin.h"

#define RECEIVE_BUF_N 80 * 1024

tiny_gin_handle_func default_middlewares[] = {tiny_gin_middleware_logger};

int calculate_fs_absolute_path(const char *relative_path, size_t relative_path_n, char *absolute_path, size_t absolute_path_n) {
    char buf[2048] = {'\0'};
    if ((*relative_path) == '.' ) {
        getcwd(buf, sizeof(buf));
        sprintf(buf + strlen(buf), "%s", relative_path + 1);
    } else {
        sprintf(buf, "%s", relative_path);
    }
    if (strlen(buf) + 1 > absolute_path_n) {
        return -1;
    }

    strcpy(absolute_path, buf);
    return 1;
}

int request_message_begin(http_parser *parser) {
    return 0;
}

int request_message_complete(http_parser *parser) {
    return  0;
}

int request_url_cb(http_parser *parser, const char *buf, size_t n) {
    tiny_gin_context *ctx;
    ctx = (tiny_gin_context *)(parser->data);
    ctx->url = malloc(sizeof(char) * n + 1) ;
    memset(ctx->url, '\0', n + 1);
    memcpy(ctx->url, buf, n);
    ctx->url_n = n;
    return 0;
}

int request_header_filed_cb(http_parser *parser, const char *buf, size_t n) {
    return 0;
}

int request_header_value_cb(http_parser *parser, const char *buf, size_t n) {
    return 0;
}

int request_body_cb(http_parser *parser, const char *buf, size_t n) {
    tiny_gin_context *ctx;
    ctx = (tiny_gin_context *)(parser->data);
    ctx->url = malloc(sizeof(char) * n);
    memcpy(ctx->body, buf, n);
    return 0;
}

tiny_gin_engine *new_router_engine_default() {
    tiny_gin_router_group *s_router_group;
    s_router_group = malloc(sizeof(tiny_gin_router_group));
    s_router_group->path = 0;
    s_router_group->path_n = 0;
    s_router_group->handle_funcs = default_middlewares;
    s_router_group->handle_funcs_n = sizeof(default_middlewares) / sizeof(tiny_gin_handle_func);

    tiny_gin_engine *s_engine = malloc(sizeof(tiny_gin_engine));
    s_engine->s_router_group = s_router_group;
    s_engine->s_router_group->s_engine = s_engine;
    s_engine->router_trees = 0;
    s_engine->s_recycled_router_groups_n = 0;
    s_engine->s_recycled_router_groups = 0;
    return s_engine;
}

tiny_gin_handle_func *combine_handlers(tiny_gin_router_group *s_router_group, tiny_gin_handle_func handle_funcs) {
    tiny_gin_handle_func *new_handle_funcs;
    new_handle_funcs = malloc(sizeof(tiny_gin_handle_func) * s_router_group->handle_funcs_n);
    memcpy(new_handle_funcs, s_router_group->handle_funcs, sizeof(tiny_gin_handle_func) * s_router_group->handle_funcs_n);
    memcpy(new_handle_funcs + s_router_group->handle_funcs_n, &handle_funcs, sizeof(tiny_gin_handle_func) * 1);
    return new_handle_funcs;
}

char *calculate_url_absolute_path(char *prefix, size_t prefix_n, char *other, size_t other_n) {
    char *new_absolute_path;
    new_absolute_path = malloc((prefix_n + other_n) + 1);
    memset(new_absolute_path, '\0', (prefix_n + other_n) + 1);
    memcpy(new_absolute_path, prefix, prefix_n);
    memcpy(new_absolute_path + prefix_n, other, other_n);
    return new_absolute_path;
}

void mark_recycled_router_group(tiny_gin_router_group *s_router_group) {
    tiny_gin_router_group *new_recycled_router_group;
    tiny_gin_engine *s_engine;
    s_engine = (tiny_gin_engine *)s_router_group->s_engine;
    new_recycled_router_group = malloc(sizeof(tiny_gin_router_group) * (s_engine->s_recycled_router_groups_n + 1));
    free(s_engine->s_recycled_router_groups);
    s_engine->s_recycled_router_groups = new_recycled_router_group;
    s_engine->s_recycled_router_groups_n ++;
}

void recycled_router_group(tiny_gin_engine *s_engine) {
    if (s_engine->s_recycled_router_groups_n == 0) {
        return;
    }
    for (size_t i=0; i < s_engine->s_recycled_router_groups_n; i ++) {
        free(s_engine->s_recycled_router_groups + i);
    }
    s_engine->s_recycled_router_groups_n = 0;
}

tiny_gin_router_group *tiny_gin_group(tiny_gin_router_group *s_router_group, char *path, size_t path_n) {
    tiny_gin_router_group *new_router_group;
    new_router_group = malloc(sizeof(tiny_gin_router_group));
    new_router_group->path = calculate_url_absolute_path(s_router_group->path, s_router_group->path_n, path, path_n);
    new_router_group->path_n = s_router_group->path_n + path_n;
    new_router_group->handle_funcs_n = s_router_group->handle_funcs_n;
    new_router_group->handle_funcs = s_router_group->handle_funcs;
    new_router_group->s_engine = s_router_group->s_engine;
    new_router_group->s_closure = s_router_group->s_closure;

    // 标记待回收  tiny_gin_router_group
    mark_recycled_router_group(new_router_group);

    return new_router_group;
}

void tiny_gin_use(tiny_gin_router_group *s_router_group, tiny_gin_handle_func s_handle_func) {
    tiny_gin_handle_func *new_handle_funcs;
    new_handle_funcs =  combine_handlers(s_router_group, s_handle_func);
    free(s_router_group->handle_funcs);
    s_router_group->handle_funcs = new_handle_funcs;
    s_router_group->handle_funcs_n + 1;
}

void add_engine(tiny_gin_router_group *s_router_group) {
    // 可以使用redix 树 替换链表
    tiny_gin_router_node *new_tree_node;
    tiny_gin_engine *s_engine;

    s_engine = (tiny_gin_engine *)s_router_group->s_engine;

    // 添加到链表上
    new_tree_node = malloc(sizeof(tiny_gin_router_node));
    new_tree_node->s_router_group = s_router_group;
    new_tree_node->next = s_engine->router_trees;
    s_engine->router_trees = new_tree_node;
}

void _tiny_gin_static_handle_func (tiny_gin_context *ctx) {
    char absolute_file[2048] = {'\0'};
    _tiny_gin_closure_static_dir *closure;

    closure = (_tiny_gin_closure_static_dir *)ctx->s_closure;
    regmatch_t *s_regmatch = ctx->s_url_regmatch + (ctx->s_url_regmatch_n - 1);
    memcpy(absolute_file, closure->absolute_path, closure->absolute_path_n);
    *(absolute_file + closure->absolute_path_n) = '/';
    memcpy(absolute_file + closure->absolute_path_n + 1, ctx->url + s_regmatch->rm_so, s_regmatch->rm_eo - s_regmatch->rm_so);

    // TODO: 读取文件写入到socket中
}

int tiny_gin_static_dir(tiny_gin_router_group *s_router_group, const char *relative_path, const char *root) {
    char pattern_path[strlen(relative_path) + 22];
    char *absolute_path;
    _tiny_gin_closure_static_dir *s_closure;

    // 计算静态目录
    absolute_path = malloc(sizeof(char) * 1024);
    memset(absolute_path, '\0', 1024);
    if(calculate_fs_absolute_path(root, strlen(root), absolute_path, 1024) == -1) {
        return -1;
    }
    s_closure = malloc(sizeof(_tiny_gin_closure_static_dir));
    s_closure->absolute_path = absolute_path;
    s_closure->absolute_path_n = strlen(absolute_path);
    memset(pattern_path, '\0', strlen(relative_path) + 22);
    sprintf(pattern_path, "%s/([A-Za-z0-9_\\.]+){1}", relative_path);

    tiny_gin_any(s_router_group, GET, pattern_path, _tiny_gin_static_handle_func, s_closure);
    return 1;
}

void tiny_gin_any(tiny_gin_router_group *s_router_group, tiny_gin_method s_method, const char *relative_path, \
            tiny_gin_handle_func s_handle_func, void *s_closure) {
    tiny_gin_router_group *new_router_group;
    size_t relative_path_n;
    relative_path_n = strlen(relative_path);
    new_router_group = malloc(sizeof(tiny_gin_router_group));
    new_router_group->method = s_method;
    new_router_group->path = calculate_url_absolute_path(s_router_group->path, s_router_group->path_n,
                                                         (char *) relative_path, relative_path_n);
    new_router_group->path_n = s_router_group->path_n + relative_path_n;
    new_router_group->handle_funcs_n = s_router_group->handle_funcs_n + 1;
    new_router_group->handle_funcs = combine_handlers(s_router_group, s_handle_func);
    new_router_group->s_engine = s_router_group->s_engine;
    new_router_group->s_closure = s_closure;

    // 添加到路由树节点
    add_engine(new_router_group);
}

void tiny_gin_get(tiny_gin_router_group *s_router_group, const char *path, tiny_gin_handle_func s_handle_func) {
    tiny_gin_any(s_router_group, GET, path, s_handle_func, NULL);
}

void tiny_gin_post(tiny_gin_router_group *s_router_group, const char *path, tiny_gin_handle_func s_handle_func) {
    tiny_gin_any(s_router_group, POST, path, s_handle_func, NULL);
}

int find_router(tiny_gin_context *ctx, tiny_gin_engine *s_engine) {
    tiny_gin_router_node *router_node;
    tiny_gin_router_group *router_group;
    router_node = s_engine->router_trees;
    while (router_node != 0){
        router_group = router_node->s_router_group;
        // 请求方法匹配
        if (ctx->method != router_group->method) {
            router_node = router_node->next;
            continue;
        }

        int regex_result;
        regex_t regex;
        size_t  regmatch_n = 2;
        regmatch_t regmatch[regmatch_n];

        // 正则匹配支持
        regcomp(&regex, router_group->path, REG_EXTENDED);
        regex_result = regexec(&regex, ctx->url, regmatch_n, regmatch, 0);
        if (regex_result == 0) {
            ctx->handle_funcs = malloc(sizeof(tiny_gin_handle_func) * router_group->handle_funcs_n);
            memcpy(ctx->handle_funcs, router_group->handle_funcs, sizeof(tiny_gin_handle_func) * router_group->handle_funcs_n);
            ctx->handle_funcs_n = router_group->handle_funcs_n;
            ctx->s_closure = router_group->s_closure;
            ctx->s_url_regmatch_n = regmatch_n;
            ctx->s_url_regmatch = malloc(sizeof(regmatch_t) * regmatch_n);
            memcpy(ctx->s_url_regmatch, regmatch, sizeof(regmatch_t) * regmatch_n);
            regfree(&regex);
            return 1;
        } else {
            router_node = router_node->next;
        }
        regfree(&regex);
    }
    return -1;
}

void next(tiny_gin_context *ctx) {
    ++ctx->handle_funcs_exec_n;
    while (ctx->handle_funcs_exec_n <= ctx->handle_funcs_n) {
        (*(((tiny_gin_handle_func *) ctx->handle_funcs) + ctx->handle_funcs_exec_n - 1))(ctx);
        ++ctx->handle_funcs_exec_n;
    }
}

int write_http_code(tiny_gin_context *ctx, tiny_gin_code code) {
    char buf[1024];
    switch (code) {
        case OK:
            sprintf(buf, "HTTP/1.1 200 OK\r\n");
            break;
        case BAD_REQUEST:
            sprintf(buf, "HTTP/1.1 400 Bad Request\r\n");
            break;
        case NOT_FOUND:
            sprintf(buf, "HTTP/1.1 404 Not Found\r\n");
            break;
        case NOT_METHOD_ALLOWED:
            sprintf(buf, "HTTP/1.1 404 Method Not Allowed\r\n");
            break;
        case INTERNAL_SERVER_ERROR:
            sprintf(buf, "HTTP/1.1 500 Internal Server Error\r\n");
            break;
        default:
            return -1;
    }
    send(ctx->receive_fd, buf, strlen(buf), 0);
    return 1;
}

int write_http_header(tiny_gin_context *ctx, tiny_gin_body *body) {
    char buf[1024];
    size_t content_length;
    content_length = 0;
    if (body != NULL && body->s_data_n > 0) {
        switch (body->s_content_type) {
            case TEXT_HTML:
                sprintf(buf, "Content-Type: text/html\r\n");
                break;
            case APPLICATION_JSON:
                sprintf(buf, "Content-Type: application/json\r\n");
                break;
            default:
                return -1;
        }

        send(ctx->receive_fd, buf, strlen(buf), 0);
        content_length = body->s_data_n;
    }

    sprintf(buf, "Content-Length: %zu\r\n", content_length);
    send(ctx->receive_fd, buf, strlen(buf), 0);

    sprintf(buf, "\r\n");
    send(ctx->receive_fd, buf, strlen(buf), 0);
    return 1;
}

int render(tiny_gin_context *ctx, tiny_gin_code code, tiny_gin_body *body) {
    char buf[1024];

    // 协议头
    if(write_http_code(ctx, code) == -1) {
        printf("write http code error\n");
        return -1;
    }

    // 写入HTTP头部
    if(write_http_header(ctx, body) == -1) {
        printf("write http header error\n");
        return -1;
    }

    if(body != 0 && body->s_data_n > 0) {
        send(ctx->receive_fd, body->s_data, body->s_data_n, 0);
    }
    sprintf(buf, "\r\n");
    send(ctx->receive_fd, buf, strlen(buf), 0);
    return 1;
}

void tiny_gin_render_json(tiny_gin_context *ctx, tiny_gin_code code, const char* data, size_t data_n) {
    tiny_gin_body body = {
            .s_content_type = APPLICATION_JSON,
            .s_data = data,
            .s_data_n = data_n,
    };
    render(ctx, code, &body);
}

int tiny_gin_render_html(tiny_gin_context *ctx, tiny_gin_code code, const char *data, size_t data_n) {
    tiny_gin_body body = {
            .s_content_type = TEXT_HTML,
            .s_data = data,
            .s_data_n = data_n,
    };
    return render(ctx, code, &body);
}

int tiny_gin_render_html_file(tiny_gin_context *ctx, tiny_gin_code code, const char *relative_path) {
    FILE *html_fd;
    char absolute_path[1024];
    char *html_buf;
    size_t html_buf_n;
    int ret;

    // 获取绝对路径
    if(calculate_fs_absolute_path(relative_path, strlen(relative_path), absolute_path, 1024) == -1) {
        return -1;
    }

    html_fd = fopen(absolute_path, "r");
    if (html_fd <= 0) {
        return -1;
    }
    fseek(html_fd, 0, SEEK_END);
    html_buf_n = ftell(html_fd);
    rewind(html_fd);
    html_buf = malloc(sizeof(char) * html_buf_n);
    fread((void *)html_buf, sizeof(char), html_buf_n, html_fd);
    fclose(html_fd);
    ret = tiny_gin_render_html(ctx, code, html_buf, html_buf_n);
    free(html_buf);
    return ret;
}

void tiny_gin_run(int receive_fd, tiny_gin_engine *s_engine) {

    // 回收 s_recycled_router_group
    recycled_router_group(s_engine);

    http_parser_settings settings;
    http_parser *parser;
    char *receive_buf;
    size_t receivel_n, nparsed;
    tiny_gin_context *ctx;

    // 接收数据
    receive_buf = (char *) malloc(sizeof(char) * RECEIVE_BUF_N);
    receivel_n = 0;
    receivel_n = recv(receive_fd, receive_buf, RECEIVE_BUF_N, 0);

    // 解析 http 协议
    settings.on_message_begin = request_message_begin;
    settings.on_message_complete = request_message_complete;
    settings.on_url = request_url_cb;
    settings.on_header_field = request_header_filed_cb;
    settings.on_header_value = request_header_value_cb;
    settings.on_body = request_body_cb;

    parser = malloc(sizeof(struct http_parser));
    ctx = malloc(sizeof(tiny_gin_context));
    parser->data = ctx;

    http_parser_init(parser, HTTP_BOTH);

    if (receivel_n > 0) {
        nparsed = 0;
        nparsed = http_parser_execute(parser, &settings, receive_buf, receivel_n);
        if (nparsed != receivel_n){
            printf("parse err=%d\n", parser->http_errno);
        } else {
            if (parser->upgrade) {
                // TOOD: websocket
            } else {
                ctx->receive_fd = receive_fd;
                ctx->method = parser->method;
                ctx->handle_funcs_exec_n = 0;
                if(find_router(ctx, s_engine) == 1) {
                    next(ctx);
                } else {
                    // 处理找不到路径
                    render(ctx, NOT_FOUND, NULL);
                }
            }
        }
    }
    free(receive_buf);
    free(ctx->handle_funcs);
    free(ctx->s_url_regmatch);
    free(ctx);
    free(parser);
}

void sprint_string(char * dsc, const char *format, char *in, size_t in_n) {
    char str[in_n + 1];
    memcpy(str, in, in_n);
    str[in_n] = '\0';
    sprintf(dsc, format, str);
}

void tiny_gin_middleware_logger(tiny_gin_context *ctx) {
    char *buf;
    size_t buf_cursor;
    struct timeval use_start, use_end;

    gettimeofday(&use_start, NULL);

    next(ctx);

    gettimeofday(&use_end, NULL);

    buf = (char *) malloc(sizeof(char) * 255);
    memset(buf, '\0', 255);
    strftime(buf, 225, "%Y-%m-%d %H:%M:%S ", localtime(&use_start.tv_sec));
    buf_cursor = strlen(buf);

    sprintf(buf + buf_cursor, "%.2fms ", \
    (use_end.tv_sec - use_end.tv_sec) * 1000 + (use_end.tv_usec - use_start.tv_usec) / 1000.0);
    buf_cursor = strlen(buf);

    if (ctx->method == HTTP_GET) {
        strcpy(buf + buf_cursor, "[GET]");
    } else if (ctx->method == HTTP_POST) {
        strcpy(buf + buf_cursor, "[POST]");
    } else {
        strcpy(buf + buf_cursor, "[REQ]");
    }

    buf_cursor = strlen(buf);
    sprint_string(buf + buf_cursor, " %s\n", ctx->url, ctx->url_n);

    printf("%s", buf);
    free(buf);
}