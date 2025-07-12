# Brick Auth Service

Brick 认证服务，提供用户认证、JWT 令牌管理和权限控制功能。

## 目录结构

```
brick-auth/
├── main.go                 # 主应用程序
├── Dockerfile             # Docker 构建文件
├── go.mod                 # Go 模块文件
├── private_rsa_pkcs1.pem # RSA 私钥文件
├── scripts/               # 脚本文件
│   └── test.sh
└── README.md             # 本文档
```

## 容器化最佳实践

### 目录结构
- `/etc/brick/auth/` - 配置文件
- `/var/log/brick/auth/` - 日志文件
- `/data/brick/auth/` - 数据文件
- `/app/brick-auth/` - 应用程序文件

### 环境变量
- `CONFIG_PATH` - 配置文件路径 (默认: `/etc/brick/auth`)
- `LOG_PATH` - 日志文件路径 (默认: `/var/log/brick/auth`)
- `DATA_PATH` - 数据文件路径 (默认: `/data/brick/auth`)
- `JWT_SECRET` - JWT 密钥
- `ENVIRONMENT` - 运行环境

### 安全特性
- 非 root 用户运行 (brick:1000)
- 标准 Linux 目录结构
- 健康检查端点
- 环境变量配置
- 合并的 RUN 命令减少镜像层数

## 构建和运行

### 本地构建
```bash
docker build -t brick-auth:latest .
```

### 使用 Docker Compose
```bash
cd ../brick-deployment
docker-compose up auth
```

### 健康检查
```bash
curl http://localhost:17001/health
```

### 版本信息
```bash
curl http://localhost:17001/version
```

## API 端点

- `POST /login` - 用户登录
- `POST /validate` - 验证 JWT 令牌
- `GET /health` - 健康检查
- `GET /version` - 版本信息

## 监控和日志

日志文件位置：`/var/log/brick/auth/app.log`

健康检查端点：`http://localhost:17001/health`

## 默认用户

- **brick-admin** / brickadminpass (管理员权限)
- **brick** / brickpass (普通用户权限)

## 技术特点

- 使用 SQLite 数据库存储用户信息
- RSA 密钥对进行 JWT 签名
- bcrypt 密码哈希
- 基于角色的权限控制
- 15分钟 JWT 令牌过期时间 