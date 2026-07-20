package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Hostname, Listen, DataDir        string
	AdminPassword, AdminEmail        string
	SystemFrom, EgressIP             string
	SMTPPort, FailureRateMinVolume   int
	FailureRateThreshold             float64
}

func Load() (*Config, error) {
	c := &Config{
		Hostname:      os.Getenv("DOEVOE_HOSTNAME"),
		Listen:        getdef("DOEVOE_LISTEN", ":8080"),
		DataDir:       getdef("DOEVOE_DATA_DIR", "/data"),
		AdminPassword: os.Getenv("DOEVOE_ADMIN_PASSWORD"),
		AdminEmail:    os.Getenv("DOEVOE_ADMIN_EMAIL"),
		SystemFrom:    os.Getenv("DOEVOE_SYSTEM_FROM"),
		EgressIP:      os.Getenv("DOEVOE_EGRESS_IP"),
	}
	for name, v := range map[string]string{
		"DOEVOE_HOSTNAME": c.Hostname, "DOEVOE_ADMIN_PASSWORD": c.AdminPassword,
		"DOEVOE_ADMIN_EMAIL": c.AdminEmail, "DOEVOE_SYSTEM_FROM": c.SystemFrom,
		"DOEVOE_EGRESS_IP": c.EgressIP,
	} {
		if v == "" {
			return nil, fmt.Errorf("%s is required", name)
		}
	}
	var err error
	if c.SMTPPort, err = intdef("DOEVOE_SMTP_PORT", 25); err != nil {
		return nil, err
	}
	if c.FailureRateMinVolume, err = intdef("DOEVOE_FAILURE_RATE_MIN_VOLUME", 10); err != nil {
		return nil, err
	}
	c.FailureRateThreshold = 0.2
	if s := os.Getenv("DOEVOE_FAILURE_RATE_THRESHOLD"); s != "" {
		if c.FailureRateThreshold, err = strconv.ParseFloat(s, 64); err != nil {
			return nil, fmt.Errorf("DOEVOE_FAILURE_RATE_THRESHOLD: %w", err)
		}
	}
	return c, nil
}

func getdef(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func intdef(k string, d int) (int, error) {
	s := os.Getenv(k)
	if s == "" {
		return d, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", k, err)
	}
	return n, nil
}
