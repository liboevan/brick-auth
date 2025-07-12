[English Version](README.en.md) | **简体中文**

---

# Brick Auth Service

Brick 认证服务，提供用户认证、JWT 令牌管理和权限控制功能。

## 新特性

### 🔐 改进的权限系统
- **角色基础访问控制 (RBAC)**: 支持角色和权限的精细化管理
- **资源-操作权限模型**: `resource/action` 格式的权限控制
- **动态权限分配**: 支持运行时权限分配和修改

### 🛡️ 增强的安全功能
- **密码策略**: 可配置的密码复杂度要求
- **会话管理**: 支持会话跟踪和自动清理
- **审计日志**: 完整的用户操作审计记录
- **登录限制**: 可配置的登录尝试限制

### 📊 改进的数据库设计
- **规范化结构**: 消除数据冗余，提高数据一致性
- **外键约束**: 确保数据完整性
- **可扩展性**: 易于添加新的角色和权限

### ⚙️ 灵活的配置管理
- **环境变量支持**: 全面的环境变量配置
- **配置文件**: JSON格式的配置文件支持
- **配置验证**: 启动时配置验证
- **运行时配置**: 支持运行时配置重载

## 目录结构

```
brick-auth/
├── main.go                 # 主应用程序入口
├── models.go               # 数据模型定义
├── config.go               # 配置管理
├── handlers.go             # API处理函数
├── database.go             # 数据库管理
├── Dockerfile             # Docker 构建文件
├── go.mod                 # Go 模块文件
├── private_rsa_pkcs1.pem # RSA 私钥文件
├── scripts/               # 脚本文件
│   └── test.sh
└── README.md             # 本文档
```

## 容器化最佳实践

### 目录结构
- `/etc/brick-auth/` - 配置文件
- `/var/log/brick-auth/` - 日志文件
- `/var/lib/brick-auth/` - 数据文件
- `/app/` - 应用程序文件

### 环境变量
- `BRICK_AUTH_PORT` - 服务端口 (默认: 17001)
- `BRICK_AUTH_HOST` - 服务主机 (默认: 0.0.0.0)
- `BRICK_AUTH_DB_PATH` - 数据库路径 (默认: /var/lib/brick-auth/auth.db)
- `BRICK_AUTH_PRIVATE_KEY_PATH` - 私钥路径 (默认: /app/private.pem)
- `BRICK_AUTH_TOKEN_EXPIRY` - 令牌过期时间 (默认: 15m)
- `BRICK_AUTH_PASSWORD_MIN_LENGTH` - 密码最小长度 (默认: 8)
- `BRICK_AUTH_MAX_LOGIN_ATTEMPTS` - 最大登录尝试次数 (默认: 5)
- `BRICK_AUTH_ENABLE_AUDIT_LOG` - 启用审计日志 (默认: true)
- `BRICK_AUTH_ENABLE_SESSION_TRACKING` - 启用会话跟踪 (默认: true)

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

### 认证端点
- `POST /login` - 用户登录
- `POST /validate` - 验证 JWT 令牌
- `GET /validate` - 验证 JWT 令牌 (兼容性)
- `POST /refresh` - 刷新令牌
- `GET /me` - 获取当前用户信息

### 系统端点
- `GET /health` - 健康检查
- `GET /version` - 版本信息

## 默认用户

### 超级管理员
- **用户名**: `brick-super-admin`
- **密码**: `brickpass`
- **角色**: `super-admin`
- **权限**: 所有权限，包括用户、角色、权限管理

### 管理员
- **用户名**: `brick-admin`
- **密码**: `brickpass`
- **角色**: `admin`
- **权限**: 时钟管理和用户查看权限

### 普通用户
- **用户名**: `brick`
- **密码**: `brickpass`
- **角色**: `user`
- **权限**: 基本时钟查看权限

## 权限系统

### 权限格式
权限采用 `resource/action` 格式：
- `clock/view` - 查看时钟状态
- `clock/clients` - 查看时钟客户端
- `clock/server_mode` - 管理时钟服务器模式
- `clock/servers` - 管理时钟服务器
- `user/read` - 读取用户信息
- `user/create` - 创建用户
- `user/update` - 更新用户
- `user/delete` - 删除用户
- `role/*` - 角色管理权限
- `permission/*` - 权限管理权限

### 角色权限矩阵

| 权限 | super-admin | admin | user |
|------|-------------|-------|------|
| clock/view | ✅ | ✅ | ✅ |
| clock/clients | ✅ | ✅ | ✅ |
| clock/server_mode | ✅ | ✅ | ❌ |
| clock/servers | ✅ | ✅ | ❌ |
| user/read | ✅ | ✅ | ❌ |
| user/create | ✅ | ❌ | ❌ |
| user/update | ✅ | ❌ | ❌ |
| user/delete | ✅ | ❌ | ❌ |
| role/* | ✅ | ❌ | ❌ |
| permission/* | ✅ | ❌ | ❌ |

## 监控和日志

### 日志文件
- 位置：`/var/log/brick-auth/app.log`
- 格式：JSON 格式
- 轮转：自动日志轮转

### 健康检查
- 端点：`http://localhost:17001/health`
- 响应：服务状态和版本信息

### 审计日志
- 自动记录所有认证事件
- 包含用户操作、IP地址、用户代理等信息
- 自动清理90天前的日志

## 技术特点

- 使用 SQLite 数据库存储用户信息
- RSA 密钥对进行 JWT 签名
- bcrypt 密码哈希
- 基于角色的权限控制
- 15分钟 JWT 令牌过期时间
- 支持 PKCS1 和 PKCS8 私钥格式
- 自动会话和审计日志清理
- CORS 支持
- 配置验证和错误处理

## 安全配置

### 密码策略
- 最小长度：8个字符
- 要求大写字母：是
- 要求小写字母：是
- 要求数字：是
- 要求特殊字符：否

### 登录限制
- 最大登录尝试次数：5次
- 锁定时间：15分钟

### 会话管理
- 令牌过期时间：15分钟
- 刷新令牌过期时间：7天
- 会话过期时间：24小时

## 故障排除

### 常见问题

1. **数据库连接失败**
   - 检查数据库文件权限
   - 确保目录存在且可写

2. **私钥加载失败**
   - 检查私钥文件路径
   - 验证私钥格式 (PKCS1 或 PKCS8)

3. **权限验证失败**
   - 检查用户角色和权限分配
   - 验证令牌有效性

4. **配置错误**
   - 检查环境变量设置
   - 验证配置文件格式

### 调试命令

```bash
# 检查服务状态
docker ps | grep brick-auth

# 查看服务日志
docker logs el-brick-auth

# 测试认证端点
curl -X POST http://localhost:17001/login \
  -H "Content-Type: application/json" \
  -d '{"username":"brick-admin","password":"brickpass"}'

# 测试令牌验证
curl -H "Authorization: Bearer <token>" \
  http://localhost:17001/validate
```

## 文档

详细文档请查看 `doc/` 目录：

- [API 参考](doc/API_REFERENCE.md) - 完整的API文档
- [超级管理员API](doc/ADMIN_API.md) - 管理员专用API
- [部署指南](doc/DEPLOYMENT.md) - 部署和配置说明
- [数据库设计](doc/DATABASE_REDESIGN.md) - 数据库架构说明

## 未来计划

- [x] 用户管理 API ✅
- [x] 角色管理 API ✅
- [x] 权限管理 API ✅
- [ ] 密码策略配置
- [ ] 会话管理增强
- [ ] 审计日志界面

- [ ] 密码重置功能
- [ ] 多因素认证
- [ ] API 版本控制 