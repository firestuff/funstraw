#!/bin/sh

exec find $(dirname $0) \
  -name '*.cc' -o -name '*.h' \
  -exec clang-format-3.8 -i --style=google '{}' ';'
