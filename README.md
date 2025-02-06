A dummy reverse proxy for S3 services.  
It injects AWS authentication headers and client-side encryption (SSE-C) information transparently for clients connecting to it.

# Compilation
Compile the program by running:

```bash
go mod download
go build -o s3-gateway .
```
This will produce an executable named `s3-gateway`.  

Alternatively, build with Docker.

# Usage
`s3-ssec-proxy -endpoint=s3.fr-par.scw.cloud -access-key=your-key -secret-key=your-secret-key -ssec-key=your-b64-encoded-32-bytes-key -bucket bucket-name -region fr-par`

The server will start listening on port 80
