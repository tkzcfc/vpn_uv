# vpn_uv
socks5 libuv

**配置文件: ** `config.json`

````js
{
	"client_listenIP": "0.0.0.0",
	"svr_listenIP": "0.0.0.0",
	"remoteIP": "远程服务器地址",
	"client_listenPort": 8527,
	"svr_listenPort": 1004,
	"use_kcp": false,
	"encry_method": "RC4",
	"encry_key": "key_abc",
	"username": "",
	"password": ""
}
````

参数说明:

- **client_listenIP :** 客户端监听地址
- **client_listenPort :** 客户端监听端口
- **remoteIP :** 远程服务器地址
- **svr_listenIP :** 服务端监听地址
- **svr_listenPort :** 服务器监听端口
- **use_kcp :** 传输隧道是否使用kcp
- **encry_method :** 加密方法 RC4或SNAPPY,其他值为不加密
- **encry_key :** RC4加密的key
- **username :** socks5用户名,为空则不用校验
- **password :** socks5密码