package main

import (
	"net"
	"os"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/klog/v2"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	controller "github.com/zoomoid/tbctrl/controllers"
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

	viper.BindEnv("k8s_service_host")
	viper.BindEnv("k8s_service_port")

	// replace all underscores with minus to map to the flag names
	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)

	flag.Int("v", 0, "klog level ranges from -5 (Fatal) to 10 (Verbose)")
	flag.String("metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.String("health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.Bool("enable-leader-election", false, "Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.")

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

	l.V(0).Info("Starting controller", "version", Version, "build", Build)
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
		// MetricsBindAddress:     metricsAddr,
		// Port:                   9443,
		Metrics: server.Options{
			BindAddress: viper.GetString("metrics-bind-address"),
		},

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
