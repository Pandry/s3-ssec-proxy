package main

import (
	"encoding/base64"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

type config struct {
	s3Endpoint        string
	accessKey         string
	secretKey         string
	region            string
	bucket            string
	ssecKey           []byte
	outgoingPathStyle bool
	incomingPathStyle bool
}

func main() {
	cfg := loadConfig()

	proxyURL, err := url.Parse(cfg.s3Endpoint)
	if err != nil {
		log.Fatalf("Failed to parse S3 endpoint URL: %v", err)
	}

	awsConfig := &aws.Config{
		Credentials:      credentials.NewStaticCredentials(cfg.accessKey, cfg.secretKey, ""),
		Endpoint:         aws.String(cfg.s3Endpoint),
		Region:           aws.String(cfg.region),
		S3ForcePathStyle: aws.Bool(cfg.outgoingPathStyle),
	}

	awsSession, err := session.NewSession(awsConfig)
	if err != nil {
		log.Fatalf("Failed to create AWS session: %v", err)
	}

	s3Client := s3.New(awsSession)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			log.Println(req.Method, req.URL.Path)
			req.URL.Scheme = proxyURL.Scheme
			req.URL.Host = proxyURL.Host
			if !cfg.outgoingPathStyle {
				req.Host = cfg.bucket + "." + proxyURL.Host
			} else {
				req.Host = proxyURL.Host
			}

			if cfg.incomingPathStyle && !cfg.outgoingPathStyle {
				parts := strings.SplitN(req.URL.Path, "/", 3)
				if len(parts) == 3 {
					req.URL.Path = "/" + parts[2]
				} else {
					req.URL.Path = "/"
				}
			}

			resignRequest(req, cfg, s3Client)
		},
		ModifyResponse: modifyResponse,
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	log.Printf("Starting S3 gateway on :80")
	log.Fatal(http.ListenAndServe(":80", nil))
}

func resignRequest(req *http.Request, cfg config, s3Client *s3.S3) {
	var objectKey string
	if cfg.incomingPathStyle {
		parts := strings.SplitN(req.URL.Path, "/", 3)
		if len(parts) == 3 {
			objectKey = parts[2]
		}
	} else {
		objectKey = strings.TrimPrefix(req.URL.Path, "/")
	}

	var awsReq *request.Request

	if len(objectKey) > 0 {
		log.Println("Found object key `" + objectKey + "`, adding SSE-C ")

		awsReq, _ = s3Client.PutObjectRequest(&s3.PutObjectInput{
			Bucket:               aws.String(cfg.bucket),
			Key:                  &objectKey,
			SSECustomerAlgorithm: aws.String("AES256"),
			SSECustomerKey:       aws.String(string(cfg.ssecKey)), // MD5 is added automatically
		})
	} else {
		log.Println("Object key not found for request. Signing with list request")
		awsReq, _ = s3Client.ListObjectsRequest(&s3.ListObjectsInput{
			Bucket: aws.String(cfg.bucket),
		})
	}

	awsReq.HTTPRequest.Method = req.Method
	awsReq.HTTPRequest.URL = req.URL
	if cfg.outgoingPathStyle {
		awsReq.HTTPRequest.Host = awsReq.HTTPRequest.URL.Host
	} else {
		awsReq.HTTPRequest.Host = cfg.bucket + "." + awsReq.HTTPRequest.URL.Host
	}
	req.Header.Set("Host", awsReq.HTTPRequest.Host)

	err := awsReq.Sign()
	if err != nil {
		log.Printf("Error signing request: %v", err)
		return
	}

	// Copy the signed headers back to the original request
	for key, values := range awsReq.HTTPRequest.Header {
		req.Header[key] = values
	}
}

func modifyResponse(res *http.Response) error {
	if res.StatusCode >= 400 {
		log.Println("Error detected. Status code:", res.StatusCode)
		log.Println(res.StatusCode, res.Request.URL.Path)
	}
	// Hides SSE-C headers to the response
	res.Header.Del("x-amz-server-side-encryption-customer-algorithm")
	res.Header.Del("x-amz-server-side-encryption-customer-key")
	res.Header.Del("x-amz-server-side-encryption-customer-key-MD5")

	return nil
}

func loadConfig() config {
	var cfg config

	var b64SsecKey string
	cfg.incomingPathStyle = true
	flag.StringVar(&cfg.s3Endpoint, "endpoint", os.Getenv("S3_ENDPOINT"), "S3 endpoint")
	flag.StringVar(&cfg.accessKey, "access-key", os.Getenv("S3_ACCESS_KEY"), "S3 access key")
	flag.StringVar(&cfg.secretKey, "secret-key", os.Getenv("S3_SECRET_KEY"), "S3 secret key")
	flag.StringVar(&cfg.region, "region", os.Getenv("S3_REGION"), "S3 region")
	flag.StringVar(&cfg.bucket, "bucket", os.Getenv("S3_BUCKET"), "S3 bucket")
	flag.StringVar(&b64SsecKey, "ssec-key", os.Getenv("S3_SSEC_KEY"), "Base64-encoded SSE-C key")
	// flag.BoolVar(&cfg.incomingPathStyle, "incoming-path-style", os.Getenv("S3_INCOMING_PATH_STYLE") == "true", "Expect incoming requests to be path-style")
	flag.BoolVar(&cfg.outgoingPathStyle, "outgoing-path-style", os.Getenv("S3_OUTGOING_PATH_STYLE") == "true", "Conect to remote endpoint using path-style")

	flag.Parse()

	if cfg.s3Endpoint == "" || cfg.accessKey == "" || cfg.secretKey == "" {
		log.Fatal("All configuration parameters must be provided")
	}

	// TODO: Serialize the config to JSON and print it to screen, censoring the access and secret key and the SSE-C key

	if cfg.s3Endpoint[0:4] != "http" {
		log.Println(cfg.s3Endpoint[0:4])
		cfg.s3Endpoint = "https://" + cfg.s3Endpoint
	}

	var err error
	cfg.ssecKey, err = base64.StdEncoding.DecodeString(b64SsecKey)
	if err != nil {
		log.Panic("Error decoding SSE-C key: %v", err)
	}
	if len(cfg.ssecKey) != 32 {
		log.Panic("Error with SSE-C key: not 32 bytes long")
	}
	// keyMD5 := md5.Sum(ssecDecodedKey)
	// cfg.md5SsecKey = base64.StdEncoding.EncodeToString(keyMD5[:])

	return cfg
}
