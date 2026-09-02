package native

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
)

func PrepareXRay(source, destination, tunName string, allowed []netip.Prefix) error {
	content, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read XRay configuration: %w", err)
	}
	var config map[string]any
	if err := json.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("parse XRay configuration: %w", err)
	}
	if _, ok := config["outbounds"].([]any); !ok {
		return fmt.Errorf("XRay configuration requires an outbounds array")
	}
	routeValues := make([]string, len(allowed))
	for i, prefix := range allowed {
		routeValues[i] = prefix.String()
	}
	managedTag := "amn-tun"
	inbounds, _ := config["inbounds"].([]any)
	for _, inbound := range inbounds {
		object, ok := inbound.(map[string]any)
		if !ok || object["protocol"] != "tun" {
			continue
		}
		if tag, ok := object["tag"].(string); ok && tag != "" {
			managedTag = tag
			break
		}
	}
	tun := map[string]any{
		"tag":      managedTag,
		"port":     0,
		"protocol": "tun",
		"settings": map[string]any{
			"name":                   tunName,
			"mtu":                    1500,
			"gateway":                []string{"10.255.255.1/30", "fd00:616d:6e::1/126"},
			"autoSystemRoutingTable": routeValues,
			"autoOutboundsInterface": "auto",
		},
	}
	managed := make([]any, 0, len(inbounds)+1)
	managed = append(managed, tun)
	for _, inbound := range inbounds {
		object, ok := inbound.(map[string]any)
		if ok && (object["tag"] == "amn-tun" || object["protocol"] == "tun") {
			continue
		}
		managed = append(managed, inbound)
	}
	config["inbounds"] = managed

	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("encode managed XRay configuration: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(destination, encoded, 0o600); err != nil {
		return fmt.Errorf("write managed XRay configuration: %w", err)
	}
	return nil
}
