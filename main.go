package main

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/klog/v2"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	controller "github.com/zoomoid/tbctrl/controllers"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	Build   = ""
	Version = "v0.0.0-dev.0"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	viper.BindEnv("v", "log_level")
	viper.BindEnv("metrics_bind_addr")
	viper.BindEnv("health_probe_bind_addr")
	viper.BindEnv("enable_leader_election")
	viper.BindEnv("enable_http2")
	viper.BindEnv("k8s_service_host")
	viper.BindEnv("k8s_service_port")

	// replace all underscores with minus to map to the flag names
	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)

	flag.Int("v", 0, "klog level ranges from -5 (Fatal) to 10 (Verbose)")
	flag.String("metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.String("health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.Bool("enable-leader-election", false, "Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.")
	flag.Bool("enable-http2", false, "Enable http/2 for the connection to the API server. http/2 should be disabled due to its vulnerabilities.")
	flag.Bool("metrics-secure", true, "If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.String("k8s-service-host", "localhost", "Hostname to use to connect to the API server to. This is required, because otherwise the controller needs the CNI to be setup (which, it turns out, we cannot ensure.)")
	flag.String("k8s-service-port", "6443", "Port to use to connect to the API server to. This is required, because otherwise the controller needs the CNI to be setup (which, it turns out, we cannot ensure.)")
}

func main() {
	flag.Parse()
	viper.BindPFlags(flag.CommandLine)

	l := klog.NewKlogr().V(viper.GetInt("v"))
	ctrl.SetLogger(l)

	// create a custom client config for connecting to the API server from the host network namespace
	cfg := ctrl.GetConfigOrDie()
	cfg.Host = net.JoinHostPort(viper.GetString("k8s-service-host"), viper.GetString("k8s-service-port"))

	var tlsOpts []func(*tls.Config)

	// Create watchers for metrics and webhooks certificates
	var metricsCertWatcher *certwatcher.CertWatcher

	metricsServerOptions := metricsserver.Options{
		BindAddress:    viper.GetString("metrics-bind-address"),
		SecureServing:  viper.GetBool("metrics-secure"),
		TLSOpts:        tlsOpts,
		FilterProvider: filters.WithAuthenticationAndAuthorization,
	}

	if metricsCertPath := viper.GetString("metrics-cert-path"); len(metricsCertPath) > 0 {
		metricsCertName := viper.GetString("metrics-cert-name")
		metricsCertKey := viper.GetString("metrics-cert-key")
		l.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		var err error
		metricsCertWatcher, err = certwatcher.New(
			filepath.Join(metricsCertPath, metricsCertName),
			filepath.Join(metricsCertPath, metricsCertKey),
		)
		if err != nil {
			l.Error(err, "to initialize metrics certificate watcher", "error", err)
			os.Exit(1)
		}

		metricsServerOptions.TLSOpts = append(metricsServerOptions.TLSOpts, func(config *tls.Config) {
			config.GetCertificate = metricsCertWatcher.GetCertificate
		})
	}

	if viper.GetBool("metrics-secure") {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	disableHTTP2 := func(c *tls.Config) {
		l.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !viper.GetBool("enable-http2") {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	l.V(0).Info("Starting controller", "version", Version, "build", Build)
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		HealthProbeBindAddress: viper.GetString("health-probe-bind-address"),
		LeaderElection:         viper.GetBool("enable-leader-election"),
		LeaderElectionID:       "tbctrl",
		Logger:                 l,
	})
	if err != nil {
		l.Error(err, "unable to start manager")
		os.Exit(1)
	}
	if err = (&controller.CertificateSigningRequestReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Config:    mgr.GetConfig(),
		ClientSet: kubernetes.NewForConfigOrDie(mgr.GetConfig()),
	}).SetupWithManager(mgr); err != nil {
		l.Error(err, "unable to create controller", "controller", "CertificateSigningRequestManager")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		l.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		l.Error(err, "unable to set up ready check")
		os.Exit(1)
	}
	l.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		l.Error(err, "problem running manager")
		os.Exit(1)
	}
}
