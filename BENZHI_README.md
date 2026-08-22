# CertBridge

CertBridge 是企业设备证书签发与生命周期管理服务（PKI/CA），负责 CSR 申请与审核、
证书签发、私钥归档、吊销状态机、CRL 生成与发布、证书校验和审计，运营控制台提供
证书、申请、吊销和 CRL 页面。

## 构建与运行

```bash
go build -mod=vendor ./...
go test -mod=vendor -count=1 ./...
go vet -mod=vendor ./...
```

启动服务：

```bash
go run ./cmd/certbridge -addr :8080 -data ./data
```

健康检查：`curl http://localhost:8080/healthz`

## Docker

```bash
bash build_benzhi_docker.sh certbridge linux/amd64
docker run --rm -p 8080:8080 certbridge bash -c 'go run ./cmd/certbridge -addr :8080 -data /tmp/data'
```
