// date: 2022.3.25
// author: chendaole
// email: 1174250185@qq.com

#include "router_myblog.h"
#include "tiny_gin.h"

void handle_myblog(tiny_gin_context *ctx) {
    tiny_gin_render_html_file(ctx, OK, "./html/index.html");
}

void init_router_myblog(tiny_gin_router_group *s_router_group) {
    tiny_gin_get(s_router_group, "/myblog", handle_myblog);
}

