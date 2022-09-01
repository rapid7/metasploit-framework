/*
 * Module metadata definition
 */

package module

type (
	Reference struct {
		Type string `json:"type"`
		Ref  string `json:"ref"`
	}

	Target struct {
		Platform string `json:"platform"`
		Arch     string `json:"arch"`
	}

	Option struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		Required    bool   `json:"required"`
		Default     string `json:"default"`
	}

	Metadata struct {
		Name         string              `json:"name"`
		Description  string              `json:"description"`
		Authors      []string            `json:"authors"`
		Date         string              `json:"date"`
		References   []Reference         `json:"references"`
		Type         string              `json:"type"`
		Rank         string              `json:"rank"`
		WFSDelay     int                 `json:"wfsdelay"`
		Privileged   bool                `json:"privileged"`
		Targets      []Target            `json:"targets,omitempty"`
		Capabilities []string            `json:"capabilities"`
		Payload      map[string]string   `json:"payload,omitempty"`
		Options      map[string]Option   `json:"options,omitempty"`
		Notes        map[string][]string `json:"notes,omitempty"`
	}
)
