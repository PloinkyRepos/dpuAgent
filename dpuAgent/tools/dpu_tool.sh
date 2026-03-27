#!/bin/sh
if [ -n "$1" ]; then
  TOOL_NAME="$1"
  export TOOL_NAME
fi
node "$(cd "$(dirname "$0")" && pwd)/dpu_tool.mjs"
