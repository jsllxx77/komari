package jsonrpc

// sensitive_ops.go
// 集中声明需要"敏感操作二次验证"的 RPC 方法。名单越完整，会话 cookie 被盗后
// 攻击者能做的事情就越少：pkg/rpc/sensitive.go 的标记会在权限校验之后、
// 方法执行之前强制要求 step-up（近期通过 2FA 或本次请求携带验证码）。
//
// 注意：admin:exec 与 admin:getAgentStartupConfig 已经在其注册处标记，这里
// 重复标记是幂等的。

import "github.com/komari-monitor/komari/pkg/rpc"

func init() {
	sensitiveAdminMethods := []string{
		// 任意 SQL：可以改账号、清掉 two_factor、读出所有密钥
		"admin:dbExec",
		"admin:dbQuery",
		// 节点代码执行
		"admin:exec",
		"admin:switchAgentVersion",
		"admin:getAgentStartupConfig",
		// 节点文件写：等同于执行代码
		"admin:fileMkdir",
		"admin:fileDelete",
		"admin:fileMove",
		"admin:fileCopy",
		"admin:fileChmod",
		"admin:fileChown",
		// 服务端代码：插件 JS 在服务端运行
		"admin:setPluginEnabled",
		"admin:deletePlugin",
		"admin:setPluginConfiguration",
		// 账号与认证
		"admin:setOidcProvider",
		// 密钥与会话读取
		"admin:getClientToken",
		"admin:getSessions",
		"admin:revealSecret",
	}
	for _, method := range sensitiveAdminMethods {
		rpc.MarkSensitive(method)
	}
}
