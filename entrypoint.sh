#!/bin/sh
set -e

# 如果数据库文件不存在，则初始化
if [ ! -f "/var/lib/brick-auth/auth.db" ]; then
  echo "Database not found, running seeder to load initial data..."
  /app/seeder -data /app/data -dbpath /var/lib/brick-auth/auth.db
fi

# 启动主服务
exec /app/brick-auth 