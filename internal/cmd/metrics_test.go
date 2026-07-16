package cmd

import "testing"

func TestMetricsInsightsCommandIsNotRegistered(t *testing.T) {
	for _, command := range metricsCmd.Commands() {
		if command.Name() == "insights" {
			t.Fatal("unsupported metrics insights command is registered")
		}
	}

	if err := metricsCmd.Args(metricsCmd, []string{"insights"}); err == nil {
		t.Fatal("unsupported metrics insights argument is accepted")
	}
	if metricsCmd.RunE == nil {
		t.Fatal("metrics command skips argument validation without a runner")
	}
}
