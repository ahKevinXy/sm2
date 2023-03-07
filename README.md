# SM2 国密加密 sdk

> 招商银行 国密验签

加密的 sign_content 的 json 数据 需要进行  ascii码 排序

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



http://localhost:8081/api/sign


## POST 验签

> Body 请求参数




```json
{
    "sign_content":"xxx",  
    "user_id":"xxx", 
    "private_key":"xxx"
}
```


### 请求参数

| 名称             | 位置   | 类型     | 必选  | 说明                   |
|----------------|------|--------|-----|----------------------|
| body           | body | object | 否   | none                 |
| » sign_content | body | string | 是   | 签名内容(json 需要ascii排序) |
| » user_id      | body | string | 是   | 用户ID(银行提供)           |
| » private_key  | body | string | 是   | 私钥                   |


> 返回示例

> 200 Response
```bash
    xxxxxxx 
```
### 返回结果

| 状态码 | 状态码含义 | 说明  | 数据模型   |
|-----|-------|-----|--------|
| 200 | OK    | 成功  | Inline |


go ascii码 排序 案例

对 struct 进行map  化 然后再json 处理

例子：

```go 


   
   

```