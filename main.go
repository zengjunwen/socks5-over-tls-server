package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/armon/go-socks5"
	"log"
	"net"
	"os"
)

type Params struct {
	User     string
	Password string
	Port     string
	tls      bool
}

var (
	params  = Params{}
	crtFile = "server.crt"
	keyFile = "server.key"
)

func main() {
	flag.StringVar(&params.User, "u", "admin", "username")
	flag.StringVar(&params.Password, "p", "admin", "password")
	flag.StringVar(&params.Port, "port", "1080", "port")
	flag.BoolVar(&params.tls, "tls", true, "tls")
	flag.Parse()

	// Initialize socks5 config
	socks5conf := &socks5.Config{
		Logger: log.New(os.Stdout, "", log.LstdFlags),
	}
	if params.User+params.Password != "" {
		creds := socks5.StaticCredentials{
			params.User: params.Password,
		}
		cator := socks5.UserPassAuthenticator{Credentials: creds}
		socks5conf.AuthMethods = []socks5.Authenticator{cator}
	}

	server, err := socks5.New(socks5conf)
	if err != nil {
		log.Fatal(err)
	}
	err = ListenAndServe(server)
	if err != nil {
		fmt.Println("启动失败:", err)
	}
}

func ListenAndServe(server *socks5.Server) error {
	l, err := net.Listen("tcp", ":"+params.Port)

	config, err := initTLSConfig()
	if err != nil {
		return err
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Accept error:", err)
			continue
		}

		if config != nil {
			// 使用TLS配置包装连接
			conn = tls.Server(conn, config)
		}
		go server.ServeConn(conn)
	}
}

func initTLSConfig() (*tls.Config, error) {
	if !params.tls {
		return nil, nil
	}
	// 为TLS配置生成证书和密钥
	cert, err := tls.LoadX509KeyPair(crtFile, keyFile)
	if err != nil {
		fmt.Println("无法加载证书和密钥:", err)
		return nil, err
	}

	// 创建TLS配置
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	return config, nil
}
