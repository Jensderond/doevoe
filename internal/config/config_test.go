package config

import "testing"

func setRequired(t *testing.T) {
	t.Setenv("DOEVOE_HOSTNAME", "mail.example.com")
	t.Setenv("DOEVOE_ADMIN_PASSWORD", "s3cret")
	t.Setenv("DOEVOE_ADMIN_EMAIL", "ops@example.com")
	t.Setenv("DOEVOE_SYSTEM_FROM", "noreply@mail.example.com")
	t.Setenv("DOEVOE_EGRESS_IP", "203.0.113.7")
}

func TestLoadDefaults(t *testing.T) {
	setRequired(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8080" || c.DataDir != "/data" || c.SMTPPort != 25 {
		t.Errorf("bad defaults: %+v", c)
	}
	if c.FailureRateThreshold != 0.2 || c.FailureRateMinVolume != 10 {
		t.Errorf("bad alert defaults: %+v", c)
	}
	if c.InboundListen != ":25" {
		t.Errorf("want default InboundListen :25, got %q", c.InboundListen)
	}
}

func TestLoadInboundListen(t *testing.T) {
	setRequired(t)

	t.Setenv("DOEVOE_INBOUND_LISTEN", ":2525")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.InboundListen != ":2525" {
		t.Errorf("want :2525, got %q", c.InboundListen)
	}

	t.Setenv("DOEVOE_INBOUND_LISTEN", "")
	c, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.InboundListen != "" {
		t.Errorf("want empty InboundListen (disabled) when explicitly set to empty, got %q", c.InboundListen)
	}
}

func TestLoadMissingRequired(t *testing.T) {
	setRequired(t)
	t.Setenv("DOEVOE_HOSTNAME", "")
	if _, err := Load(); err == nil {
		t.Fatal("want error for missing DOEVOE_HOSTNAME")
	}
}

func TestLoadPublicURL(t *testing.T) {
	setRequired(t)
	if c, err := Load(); err != nil {
		t.Fatal(err)
	} else if c.PublicURL != "" {
		t.Errorf("want empty PublicURL by default, got %q", c.PublicURL)
	}

	t.Setenv("DOEVOE_PUBLIC_URL", "https://mail.example.com/")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicURL != "https://mail.example.com" {
		t.Errorf("want trailing slash stripped, got %q", c.PublicURL)
	}
}
