cmake_minimum_required(VERSION 3.20)
project(myblog C)

set(CMAKE_C_STANDARD 99)

# 设置库文件输出路径
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

# 配置库目录
link_libraries(${PROJECT_SOURCE_DIR}/lib)

# 添加子模块
add_subdirectory(thirdpard/http_parser)

# 生成项目可执行文件
add_executable(myblog main.c router_myblog.h router_myblog.c tiny_gin.c tiny_gin.h)

# 连接动态库
target_link_libraries(myblog httpparser)
