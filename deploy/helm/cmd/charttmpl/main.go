package main

import (
	"flag"
	"log"
	"os"
	"text/template"

	"gopkg.in/yaml.v3"
)

type annotations struct {
	Name       string `yaml:"name"`
	Provider   string `yaml:"provider"`
	SupportURL string `yaml:"supportURL"`
}

type image struct {
	Image string `yaml:"image"`
	Tag   string `yaml:"tag"`
}

// templateContext is the data model available to templates. It includes
// chart metadata as well as arbitrary image overrides under .Images.
type templateContext struct {
	ChartVersion string
	AppVersion   string
	Name         string           `yaml:"name"`
	Description  string           `yaml:"description"`
	Home         string           `yaml:"home"`
	Icon         string           `yaml:"icon"`
	Annotations  annotations      `yaml:"annotations"`
	Images       map[string]image `yaml:"images"`
}

func main() {
	// Optional override: still allow -key to select profile; paths are fixed in code
	key := flag.String("key", "", "profile key to use (default: env RHEM=redhat, else community)")
	flag.Parse()

	// Fixed paths relative to deploy/helm
	const chartTmplPath = "flightctl/Chart.yaml.gotmpl"
	const chartOutPath = "flightctl/Chart.yaml"
	const valuesTmplPath = "flightctl/values.yaml.gotmpl"
	const valuesOutPath = "flightctl/values.yaml"
	const optsPath = "helm-chart-opts.yaml"

	chartVersion := getenvDefault("CHART_VERSION", "0.1.0")
	appVersion := getenvDefault("CHART_APP_VERSION", "latest")

	var data templateContext
	// Resolve profile key defaulting to env when not provided
	profileKey := *key
	if profileKey == "" {
		if os.Getenv("RHEM") != "" {
			profileKey = "redhat"
		} else {
			profileKey = "community"
		}
	}

	// Multi-profile opts file
	optsBytes, err := os.ReadFile(optsPath)
	if err != nil {
		log.Fatalf("reading opts %s: %v", optsPath, err)
	}
	var profiles map[string]templateContext
	if err := yaml.Unmarshal(optsBytes, &profiles); err != nil {
		log.Fatalf("parsing opts %s: %v", optsPath, err)
	}
	profile, ok := profiles[profileKey]
	if !ok {
		log.Fatalf("profile key %q not found in %s", profileKey, optsPath)
	}
	data = profile

	data.ChartVersion = chartVersion
	data.AppVersion = appVersion

	// Render Chart.yaml
	tplBytes, err := os.ReadFile(chartTmplPath)
	if err != nil {
		log.Fatalf("reading template %s: %v", chartTmplPath, err)
	}

	tpl, err := template.New("chart").Option("missingkey=error").Parse(string(tplBytes))
	if err != nil {
		log.Fatalf("parsing template %s: %v", chartTmplPath, err)
	}

	outFile, err := os.Create(chartOutPath)
	if err != nil {
		log.Fatalf("creating output %s: %v", chartOutPath, err)
	}
	defer outFile.Close()

	if err := tpl.Execute(outFile, data); err != nil {
		log.Fatalf("executing template %s: %v", chartOutPath, err)
	}

	// Render values.yaml if a template exists
	if _, err := os.Stat(valuesTmplPath); err == nil {
		valBytes, err := os.ReadFile(valuesTmplPath)
		if err != nil {
			log.Fatalf("reading template %s: %v", valuesTmplPath, err)
		}
		valTpl, err := template.New("values").Option("missingkey=error").Parse(string(valBytes))
		if err != nil {
			log.Fatalf("parsing template %s: %v", valuesTmplPath, err)
		}
		valOut, err := os.Create(valuesOutPath)
		if err != nil {
			log.Fatalf("creating output %s: %v", valuesOutPath, err)
		}
		defer valOut.Close()
		if err := valTpl.Execute(valOut, data); err != nil {
			log.Fatalf("executing template %s: %v", valuesOutPath, err)
		}
	}
}

func getenvDefault(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}
