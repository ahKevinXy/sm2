# SM2 国密加密 sdk

> 招商银行 国密验签

- [x] http 请求进行验签加密解密操作

- [ ] 命令行进行验签加密解密相关操作


> 参考 [bouncycastle](https://bouncycastle.org/)

> 打包

```bash
./mvnw package
```

> 启动

```bash

 java -jar target/sm2.jar --server.port=8081 # 指定端口号
 
```


```json
{
    "sign_content":"xxx", 
    "user_id":"xxxx", 
    "private_key":"123123"
}
```