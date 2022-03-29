cmake_minimum_required(VERSION 3.20)
project(httpparser)

add_library(httpparser http_parser.c http_parser.h)