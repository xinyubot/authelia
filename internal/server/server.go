package server

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"

	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/logging"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/utils"
)

// CreateServer Create Authelia's internal webserver with the given configuration and providers.
func CreateServer(config schema.Configuration, providers middlewares.Providers) (*fasthttp.Server, net.Listener) {
	server := &fasthttp.Server{
		ErrorHandler:          handlerError(),
		Handler:               getHandler(config, providers),
		NoDefaultServerHeader: true,
		ReadBufferSize:        config.Server.ReadBufferSize,
		WriteBufferSize:       config.Server.WriteBufferSize,
	}

	logger := logging.Logger()

	address := net.JoinHostPort(config.Server.Host, strconv.Itoa(config.Server.Port))

	var (
		listener         net.Listener
		err              error
		connectionType   string
		connectionScheme string
	)

	if config.Server.TLS.Certificate != "" && config.Server.TLS.Key != "" {
		connectionType, connectionScheme = "TLS", schemeHTTPS

		tlsConf := &tls.Config{}

		var cert tls.Certificate

		if cert, err = tls.LoadX509KeyPair(config.Server.TLS.Certificate, config.Server.TLS.Key); err != nil {
			logger.Fatalf("unable to load X509 key pair: %v", err)
		}

		tlsConf.Certificates = append(tlsConf.Certificates, cert)

		var certPool *x509.CertPool

		if certPool, err = utils.NewX509CertPoolFromFileNames(config.Server.TLS.ClientCertificates); err != nil {
			logger.Fatalf("Cannot load client TLS certificates: %v", err)
		}

		if certPool != nil {
			tlsConf.ClientCAs = certPool
			tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
		}

		if listener, err = tls.Listen("tcp", address, tlsConf); err != nil {
			logger.Fatalf("Error initializing listener: %s", err)
		}
	} else {
		connectionType, connectionScheme = "non-TLS", schemeHTTP

		if listener, err = net.Listen("tcp", address); err != nil {
			logger.Fatalf("Error initializing listener: %s", err)
		}
	}

	if err = writeHealthCheckEnv(config.Server.DisableHealthcheck, connectionScheme, config.Server.Host,
		config.Server.Path, config.Server.Port); err != nil {
		logger.Fatalf("Could not configure healthcheck: %v", err)
	}

	if config.Server.Path == "" {
		logger.Infof("Initializing server for %s connections on '%s' path '/'", connectionType, listener.Addr().String())
	} else {
		logger.Infof("Initializing server for %s connections on '%s' paths '/' and '%s'", connectionType, listener.Addr().String(), config.Server.Path)
	}

	return server, listener
}
