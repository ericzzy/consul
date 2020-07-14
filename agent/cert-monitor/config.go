package certmon

import (
	"context"
	"net"
	"time"

	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/consul/agent/token"
	"github.com/hashicorp/consul/tlsutil"
	"github.com/hashicorp/go-hclog"
)

// FallbackFunc is used when the normal cache watch based Certificate
// updating fails to update the Certificate in time and a different
// method of updating the certificate is required.
type FallbackFunc func(context.Context) (*structs.SignedResponse, error)

type configurations struct {
	logger          hclog.Logger
	tlsConfigurator *tlsutil.Configurator
	cache           Cache
	tokens          *token.Store
	fallback        FallbackFunc
	fallbackLeeway  time.Duration
	initial         *structs.SignedResponse
	dns             []string
	ips             []net.IP
	datacenter      string
	nodeName        string
}

// Config represents one point of configurability
// for the New function when creating a new CertMonitor
type Config func(*configurations)

// WithCache will cause the created CertMonitor type to use the provided Cache
func WithCache(cache Cache) Config {
	return func(cfg *configurations) {
		cfg.cache = cache
	}
}

// WithLogger will cause the created CertMonitor type to use the provided logger
func WithLogger(logger hclog.Logger) Config {
	return func(cfg *configurations) {
		cfg.logger = logger
	}
}

// WithTLSConfigurator will cause the created CertMonitor type to use the provided configurator
func WithTLSConfigurator(tlsConfigurator *tlsutil.Configurator) Config {
	return func(cfg *configurations) {
		cfg.tlsConfigurator = tlsConfigurator
	}
}

// WithTokens will cause the created CertMonitor type to use the provided token store
func WithTokens(tokens *token.Store) Config {
	return func(cfg *configurations) {
		cfg.tokens = tokens
	}
}

// WithFallback configures a fallback function to use if the normal update mechanisms
// fail to renew the certificate in time.
func WithFallback(fallback FallbackFunc) Config {
	return func(cfg *configurations) {
		cfg.fallback = fallback
	}
}

// WithInitialCerts will cause the the initial TLS Client Certificate and CA certificates
// to be setup properly within the TLS Configurator prepopulated appropriately in the Cache.
func WithInitialCerts(info *structs.SignedResponse) Config {
	return func(cfg *configurations) {
		cfg.initial = info
	}
}

// WithDNSSANs configures the CertMonitor to request these DNS SANs when requesting a new
// certificate
func WithDNSSANs(sans []string) Config {
	return func(cfg *configurations) {
		cfg.dns = sans
	}
}

// WithIPSANs configures the CertMonitor to request these IP SANs when requesting a new
// certificate
func WithIPSANs(sans []net.IP) Config {
	return func(cfg *configurations) {
		cfg.ips = sans
	}
}

// WithDatacenter configures the CertMonitor to request Certificates in this DC
func WithDatacenter(dc string) Config {
	return func(cfg *configurations) {
		cfg.datacenter = dc
	}
}

// WithNodeName configures the CertMonitor to request Certificates with this agent name
func WithNodeName(name string) Config {
	return func(cfg *configurations) {
		cfg.nodeName = name
	}
}

// WithFallbackLeeway configures how long after a certificate expires before attempting to
// generarte a new certificate using the fallback mechanism. The default is 10s.
func WithFallbackLeeway(leeway time.Duration) Config {
	return func(cfg *configurations) {
		cfg.fallbackLeeway = leeway
	}
}

func flattenConfigs(configs []Config) configurations {
	var flat configurations
	for _, cfg := range configs {
		cfg(&flat)
	}
	return flat
}
