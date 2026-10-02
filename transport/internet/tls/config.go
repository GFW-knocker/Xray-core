package tls

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/ocsp"
	"github.com/GFW-knocker/Xray-core/common/platform/filesystem"
	"github.com/GFW-knocker/Xray-core/common/protocol/tls/cert"
	"github.com/GFW-knocker/Xray-core/transport/internet"
)

var globalSessionCache = tls.NewLRUClientSessionCache(128)

// ParseCertificate converts a cert.Certificate to Certificate.
func ParseCertificate(c *cert.Certificate) *Certificate {
	if c != nil {
		certPEM, keyPEM := c.ToPEM()
		return &Certificate{
			Certificate: certPEM,
			Key:         keyPEM,
		}
	}
	return nil
}

func (c *Config) loadSelfCertPool() (*x509.CertPool, error) {
	root := x509.NewCertPool()
	for _, cert := range c.Certificate {
		if certPEM, _ := currentPEM(cert); !root.AppendCertsFromPEM(certPEM) {
			return nil, errors.New("failed to append cert").AtWarning()
		}
	}
	return root, nil
}

// certState is the live material of one Certificate entry, shared by every
// GetTLSConfig call that uses the entry.
//
// GetTLSConfig runs on every dial, so anything it started per call -- a
// reload goroutine, a parse of the key pair -- used to pile up with each
// connection. The state is created once per entry instead, and its reload
// goroutine ends when the entry (that is, its config) is garbage collected.
type certState struct {
	once sync.Once
	stop chan struct{}

	// pem is the entry's certificate and key as last loaded: the config's own,
	// then whatever the reload goroutine reads from the files.
	pem atomic.Pointer[certPEM]
	// pair is the key pair handshakes are served (ENCIPHERMENT entries only).
	// A reload or a new OCSP staple stores a new *tls.Certificate; one already
	// published is never modified, as handshakes may be reading it.
	pair atomic.Pointer[tls.Certificate]
}

type certPEM struct {
	cert, key []byte
}

// certStates maps weak.Pointer[Certificate] to *certState. The key is weak so
// the map does not keep configs alive; a cleanup on the entry removes it.
var certStates sync.Map

// stateOf returns entry's shared state, loading it and starting its reload
// goroutine on first use.
func stateOf(entry *Certificate) *certState {
	wp := weak.Make(entry)
	v, ok := certStates.Load(wp)
	if !ok {
		var loaded bool
		v, loaded = certStates.LoadOrStore(wp, &certState{stop: make(chan struct{})})
		if !loaded {
			runtime.AddCleanup(entry, func(s *certState) {
				certStates.Delete(wp)
				close(s.stop)
			}, v.(*certState))
		}
	}
	s := v.(*certState)
	s.once.Do(func() { s.load(entry) })
	return s
}

// currentPEM returns entry's certificate and key as last loaded, so readers
// see a hot-reloaded file without the entry itself being rewritten.
func currentPEM(entry *Certificate) (cert, key []byte) {
	if v, ok := certStates.Load(weak.Make(entry)); ok {
		if p := v.(*certState).pem.Load(); p != nil {
			return p.cert, p.key
		}
	}
	return entry.Certificate, entry.Key
}

func parseKeyPair(certPEMBlock, keyPEMBlock []byte) *tls.Certificate {
	keyPair, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "ignoring invalid X509 key pair")
		return nil
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "ignoring invalid certificate")
		return nil
	}
	return &keyPair
}

func (s *certState) load(entry *Certificate) {
	s.pem.Store(&certPEM{cert: entry.Certificate, key: entry.Key})

	switch entry.Usage {
	case Certificate_ENCIPHERMENT:
		pair := parseKeyPair(entry.Certificate, entry.Key)
		if pair == nil {
			// skipped, and never reloaded
			return
		}
		s.pair.Store(pair)
	case Certificate_AUTHORITY_ISSUE:
		// reloaded too: certificates are issued from the current CA
	default:
		return
	}
	if entry.OneTimeLoading {
		return
	}

	hotReloadCertInterval := uint64(3600)
	isOcspstapling := false
	if entry.OcspStapling != 0 {
		hotReloadCertInterval = entry.OcspStapling
		isOcspstapling = true
	}
	// copied out so the goroutine holds no reference to the entry
	certPath, keyPath, usage := entry.CertificatePath, entry.KeyPath, entry.Usage
	go s.hotReload(certPath, keyPath, usage, time.Duration(hotReloadCertInterval)*time.Second, isOcspstapling)
}

// hotReload re-reads the entry's files every interval and, for ENCIPHERMENT,
// refreshes the served key pair and its OCSP staple. It returns when the entry
// is garbage collected, or when a file can no longer be read.
func (s *certState) hotReload(certPath, keyPath string, usage Certificate_Usage, interval time.Duration, isOcspstapling bool) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		// the newly loaded key pair, nil when the files did not change
		var newPair *tls.Certificate
		if certPath != "" && keyPath != "" {
			newCert, err := filesystem.ReadCert(certPath)
			if err != nil {
				errors.LogErrorInner(context.Background(), err, "failed to parse certificate")
				return
			}
			newKey, err := filesystem.ReadCert(keyPath)
			if err != nil {
				errors.LogErrorInner(context.Background(), err, "failed to parse key")
				return
			}
			if cur := s.pem.Load(); string(newCert) != string(cur.cert) || string(newKey) != string(cur.key) {
				// Only a matching pair is taken: a renewal writes the two files
				// one after the other, and a read in between must not replace a
				// working pair with half of a new one. Until both match, the
				// current pair stays and the files are read again next time.
				if newPair = parseKeyPair(newCert, newKey); newPair != nil {
					s.pem.Store(&certPEM{cert: newCert, key: newKey})
				}
			}
		}
		if usage == Certificate_ENCIPHERMENT {
			s.refreshPair(newPair, isOcspstapling)
		}
		select {
		case <-t.C:
		case <-s.stop:
			return
		}
	}
}

// refreshPair publishes newPair, if any, and the current OCSP staple.
func (s *certState) refreshPair(newPair *tls.Certificate, isOcspstapling bool) {
	cur := s.pair.Load()
	next := cur
	if newPair != nil {
		next = newPair
	}
	if isOcspstapling {
		if newOCSPData, err := ocsp.GetOCSPForCert(next.Certificate); err != nil {
			errors.LogWarningInner(context.Background(), err, "ignoring invalid OCSP")
		} else if string(newOCSPData) != string(next.OCSPStaple) {
			staple := *next
			staple.OCSPStaple = newOCSPData
			next = &staple
		}
	}
	if next != cur {
		s.pair.Store(next)
	}
}

// certificateStates returns the shared states of c's usable ENCIPHERMENT
// certificates.
func (c *Config) certificateStates() []*certState {
	states := make([]*certState, 0, len(c.Certificate))
	for _, entry := range c.Certificate {
		if entry.Usage != Certificate_ENCIPHERMENT {
			continue
		}
		if s := stateOf(entry); s.pair.Load() != nil {
			states = append(states, s)
		}
	}
	return states
}

// BuildCertificates builds a list of TLS certificates from proto definition.
// The list is a snapshot; handshakes go through the live states instead.
func (c *Config) BuildCertificates() []*tls.Certificate {
	states := c.certificateStates()
	certs := make([]*tls.Certificate, 0, len(states))
	for _, s := range states {
		certs = append(certs, s.pair.Load())
	}
	return certs
}

func isCertificateExpired(c *tls.Certificate) bool {
	if c.Leaf == nil && len(c.Certificate) > 0 {
		if pc, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
			c.Leaf = pc
		}
	}

	// If leaf is not there, the certificate is probably not used yet. We trust user to provide a valid certificate.
	return c.Leaf != nil && c.Leaf.NotAfter.Before(time.Now().Add(time.Minute*2))
}

func issueCertificate(rawCA *Certificate, domain string) (*tls.Certificate, error) {
	caCert, caKey := currentPEM(rawCA)
	parent, err := cert.ParseCertificate(caCert, caKey)
	if err != nil {
		return nil, errors.New("failed to parse raw certificate").Base(err)
	}
	newCert, err := cert.Generate(parent, cert.CommonName(domain), cert.DNSNames(domain))
	if err != nil {
		return nil, errors.New("failed to generate new certificate for ", domain).Base(err)
	}
	newCertPEM, newKeyPEM := newCert.ToPEM()
	if rawCA.BuildChain {
		newCertPEM = bytes.Join([][]byte{newCertPEM, caCert}, []byte("\n"))
	}
	cert, err := tls.X509KeyPair(newCertPEM, newKeyPEM)
	return &cert, err
}

func (c *Config) getCustomCA() []*Certificate {
	certs := make([]*Certificate, 0, len(c.Certificate))
	for _, certificate := range c.Certificate {
		if certificate.Usage == Certificate_AUTHORITY_ISSUE {
			certs = append(certs, certificate)
			// starts its hot reload once, not once per call
			stateOf(certificate)
		}
	}
	return certs
}

func getGetCertificateFunc(c *tls.Config, ca []*Certificate) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var access sync.RWMutex

	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		domain := hello.ServerName
		certExpired := false

		access.RLock()
		certificate, found := c.NameToCertificate[domain]
		access.RUnlock()

		if found {
			if !isCertificateExpired(certificate) {
				return certificate, nil
			}
			certExpired = true
		}

		if certExpired {
			newCerts := make([]tls.Certificate, 0, len(c.Certificates))

			access.Lock()
			for _, certificate := range c.Certificates {
				if !isCertificateExpired(&certificate) {
					newCerts = append(newCerts, certificate)
				} else if certificate.Leaf != nil {
					expTime := certificate.Leaf.NotAfter.Format(time.RFC3339)
					errors.LogInfo(context.Background(), "old certificate for ", domain, " (expire on ", expTime, ") discarded")
				}
			}

			c.Certificates = newCerts
			access.Unlock()
		}

		var issuedCertificate *tls.Certificate

		// Create a new certificate from existing CA if possible
		for _, rawCert := range ca {
			if rawCert.Usage == Certificate_AUTHORITY_ISSUE {
				newCert, err := issueCertificate(rawCert, domain)
				if err != nil {
					errors.LogInfoInner(context.Background(), err, "failed to issue new certificate for ", domain)
					continue
				}
				parsed, err := x509.ParseCertificate(newCert.Certificate[0])
				if err == nil {
					newCert.Leaf = parsed
					expTime := parsed.NotAfter.Format(time.RFC3339)
					errors.LogInfo(context.Background(), "new certificate for ", domain, " (expire on ", expTime, ") issued")
				} else {
					errors.LogInfoInner(context.Background(), err, "failed to parse new certificate for ", domain)
				}

				access.Lock()
				c.Certificates = append(c.Certificates, *newCert)
				issuedCertificate = &c.Certificates[len(c.Certificates)-1]
				access.Unlock()
				break
			}
		}

		if issuedCertificate == nil {
			return nil, errors.New("failed to create a new certificate for ", domain)
		}

		access.Lock()
		c.BuildNameToCertificate()
		access.Unlock()

		return issuedCertificate, nil
	}
}

func getNewGetCertificateFunc(states []*certState, rejectUnknownSNI bool) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if len(states) == 0 {
			return nil, errNoCertificates
		}
		sni := strings.ToLower(hello.ServerName)
		if !rejectUnknownSNI && (len(states) == 1 || sni == "") {
			return states[0].pair.Load(), nil
		}
		gsni := "*"
		if index := strings.IndexByte(sni, '.'); index != -1 {
			gsni += sni[index:]
		}
		for _, s := range states {
			keyPair := s.pair.Load()
			if keyPair.Leaf.Subject.CommonName == sni || keyPair.Leaf.Subject.CommonName == gsni {
				return keyPair, nil
			}
			for _, name := range keyPair.Leaf.DNSNames {
				if name == sni || name == gsni {
					return keyPair, nil
				}
			}
		}
		if rejectUnknownSNI {
			return nil, errNoCertificates
		}
		return states[0].pair.Load(), nil
	}
}

func (c *Config) parseServerName() string {
	if IsFromMitm(c.ServerName) {
		return ""
	}
	return c.ServerName
}

func (r *RandCarrier) verifyPeerCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) (err error) {
	// extract x509 certificates from rawCerts (verifiedChains will be nil if InsecureSkipVerify is true)
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, asn1Data := range rawCerts {
		certs[i], _ = x509.ParseCertificate(asn1Data)
	}
	if len(certs) == 0 {
		return errors.New("unexpected certs")
	}

	// directly return success if pinned cert is leaf
	// or replace RootCAs if pinned cert is CA (and can be used in VerifyPeerCertByName)
	CAs := r.RootCAs
	var verifyResult verifyResult
	var verifiedCert *x509.Certificate
	if r.PinnedPeerCertSha256 != nil {
		verifyResult, verifiedCert = verifyChain(certs, r.PinnedPeerCertSha256)
		switch verifyResult {
		case certNotFound:
			return errors.New("peer cert is unrecognized (against pinnedPeerCertSha256)")
		case foundLeaf:
			return nil
		case foundCA:
			CAs = x509.NewCertPool()
			CAs.AddCert(verifiedCert)
		default:
			panic("impossible pinnedPeerCertSha256 verify result")
		}
	}

	if r.VerifyPeerCertByName != nil { // RAW's Dial() may make it empty but not nil
		opts := x509.VerifyOptions{
			Roots:         CAs,
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		for _, opts.DNSName = range r.VerifyPeerCertByName {
			if _, err := certs[0].Verify(opts); err == nil {
				return nil
			}
		}
		if verifyResult == foundCA {
			errors.New("peer cert is invalid (against pinned CA and verifyPeerCertByName)")
		}
		return errors.New("peer cert is invalid (against root CAs and verifyPeerCertByName)")
	}

	if verifyResult == foundCA { // if found CA, we need to verify here
		if len(r.Config.ServerName) == 0 {
			return errors.New("Pinning CA needs a valid ServerName")
		}
		opts := x509.VerifyOptions{
			Roots:         CAs,
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
			DNSName:       r.Config.ServerName,
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		if _, err := certs[0].Verify(opts); err == nil {
			return nil
		}
		return errors.New("peer cert is invalid (against pinned CA and serverName)")
	}

	return nil // r.PinnedPeerCertSha256==nil && r.verifyPeerCertByName==nil
}

type RandCarrier struct {
	Config               *tls.Config
	RootCAs              *x509.CertPool
	VerifyPeerCertByName []string
	PinnedPeerCertSha256 [][]byte
	// ECHCacheKey identifies the GlobalECHConfigCache entry the ECH config on
	// this tls.Config came from, so RefineECHError can drop it when the server
	// tells us it is stale. Empty for a pinned base64 config, which has no
	// cache entry and nothing to refresh.
	ECHCacheKey string
}

func (r *RandCarrier) Read(p []byte) (n int, err error) {
	return rand.Read(p)
}

// GetTLSConfig converts this Config into tls.Config.
func (c *Config) GetTLSConfig(opts ...Option) *tls.Config {
	root, err := c.getCertPool()
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "failed to load system root certificate")
	}

	if c == nil {
		return &tls.Config{
			ClientSessionCache:     globalSessionCache,
			RootCAs:                root,
			SessionTicketsDisabled: true,
		}
	}

	randCarrier := &RandCarrier{
		RootCAs:              root,
		VerifyPeerCertByName: slices.Clone(c.VerifyPeerCertByName),
		PinnedPeerCertSha256: c.PinnedPeerCertSha256,
	}
	config := &tls.Config{
		InsecureSkipVerify:     c.AllowInsecure, // GFW-knocker: restored
		Rand:                   randCarrier,
		ClientSessionCache:     globalSessionCache,
		RootCAs:                root,
		NextProtos:             slices.Clone(c.NextProtocol),
		SessionTicketsDisabled: !c.EnableSessionResumption,
		VerifyPeerCertificate:  randCarrier.verifyPeerCert,
	}
	randCarrier.Config = config
	if len(c.VerifyPeerCertByName) > 0 {
		config.InsecureSkipVerify = true
	} else {
		randCarrier.VerifyPeerCertByName = nil
	}
	if len(c.PinnedPeerCertSha256) > 0 {
		config.InsecureSkipVerify = true
	} else {
		randCarrier.PinnedPeerCertSha256 = nil
	}

	for _, opt := range opts {
		opt(config)
	}

	caCerts := c.getCustomCA()
	if len(caCerts) > 0 {
		config.GetCertificate = getGetCertificateFunc(config, caCerts)
	} else {
		config.GetCertificate = getNewGetCertificateFunc(c.certificateStates(), c.RejectUnknownSni)
	}

	if sn := c.parseServerName(); len(sn) > 0 {
		config.ServerName = sn
	}

	if len(c.CurvePreferences) > 0 {
		config.CurvePreferences = ParseCurveName(c.CurvePreferences)
	}

	if len(config.NextProtos) == 0 {
		config.NextProtos = []string{"h2", "http/1.1"}
	}

	switch c.MinVersion {
	case "1.0":
		config.MinVersion = tls.VersionTLS10
	case "1.1":
		config.MinVersion = tls.VersionTLS11
	case "1.2":
		config.MinVersion = tls.VersionTLS12
	case "1.3":
		config.MinVersion = tls.VersionTLS13
	}

	switch c.MaxVersion {
	case "1.0":
		config.MaxVersion = tls.VersionTLS10
	case "1.1":
		config.MaxVersion = tls.VersionTLS11
	case "1.2":
		config.MaxVersion = tls.VersionTLS12
	case "1.3":
		config.MaxVersion = tls.VersionTLS13
	}

	if len(c.CipherSuites) > 0 {
		id := make(map[string]uint16)
		for _, s := range tls.CipherSuites() {
			id[s.Name] = s.ID
		}
		for _, s := range tls.InsecureCipherSuites() {
			id[s.Name] = s.ID
		}
		for n := range strings.SplitSeq(c.CipherSuites, ":") {
			n = strings.TrimSpace(n)
			if v, ok := id[n]; ok {
				config.CipherSuites = append(config.CipherSuites, v)
			}
		}
	}

	if len(c.MasterKeyLog) > 0 && c.MasterKeyLog != "none" {
		writer, err := os.OpenFile(c.MasterKeyLog, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to open ", c.MasterKeyLog, " as master key log")
		} else {
			config.KeyLogWriter = writer
		}
	}
	if len(c.EchConfigList) > 0 || len(c.EchServerKeys) > 0 {
		err := ApplyECH(c, config)
		if err != nil {
			errors.LogError(context.Background(), err)
		}
	}

	return config
}

// Option for building TLS config.
type Option func(*tls.Config)

// WithDestination sets the server name in TLS config.
// Due to the incorrect structure of GetTLSConfig(), the config.ServerName will always be empty.
// So the real logic for SNI is:
// set it to dest -> overwrite it with servername(if it's len>0).
func WithDestination(dest net.Destination) Option {
	return func(config *tls.Config) {
		if config.ServerName == "" {
			config.ServerName = dest.Address.String()
		}
	}
}

func WithOverrideName(serverName string) Option {
	return func(config *tls.Config) {
		config.ServerName = serverName
	}
}

// WithNextProto sets the ALPN values in TLS config.
func WithNextProto(protocol ...string) Option {
	return func(config *tls.Config) {
		if len(config.NextProtos) == 0 {
			config.NextProtos = protocol
		}
	}
}

// ConfigFromStreamSettings fetches Config from stream settings. Nil if not found.
func ConfigFromStreamSettings(settings *internet.MemoryStreamConfig) *Config {
	if settings == nil {
		return nil
	}
	config, ok := settings.SecuritySettings.(*Config)
	if !ok {
		return nil
	}
	return config
}

func ParseCurveName(curveNames []string) []tls.CurveID {
	curveMap := map[string]tls.CurveID{
		"curvep256":          tls.CurveP256,
		"curvep384":          tls.CurveP384,
		"curvep521":          tls.CurveP521,
		"x25519":             tls.X25519,
		"x25519mlkem768":     tls.X25519MLKEM768,
		"secp256r1mlkem768":  tls.SecP256r1MLKEM768,
		"secp384r1mlkem1024": tls.SecP384r1MLKEM1024,
	}

	var curveIDs []tls.CurveID
	for _, name := range curveNames {
		if curveID, ok := curveMap[strings.ToLower(name)]; ok {
			curveIDs = append(curveIDs, curveID)
		} else {
			errors.LogWarning(context.Background(), "unsupported curve name: "+name)
		}
	}
	return curveIDs
}

func IsFromMitm(str string) bool {
	return strings.ToLower(str) == "frommitm"
}

type verifyResult int

const (
	certNotFound verifyResult = iota
	foundLeaf
	foundCA
)

func verifyChain(certs []*x509.Certificate, pinnedPeerCertSha256 [][]byte) (verifyResult, *x509.Certificate) {
	leafHash := GenerateCertHash(certs[0])
	for _, c := range pinnedPeerCertSha256 {
		if hmac.Equal(leafHash, c) {
			return foundLeaf, nil
		}
	}
	certs = certs[1:] // skip leaf
	for _, cert := range certs {
		certHash := GenerateCertHash(cert)
		for _, c := range pinnedPeerCertSha256 {
			if hmac.Equal(certHash, c) {
				if cert.IsCA {
					return foundCA, cert
				}
			}
		}
	}
	return certNotFound, nil
}
