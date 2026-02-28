package client

import (
	"context"
	"fmt"
	"net/http"
)

type BaseActions struct{ c *Client }

func (c *Client) Base() *BaseActions { return &BaseActions{c: c} }

func (b *BaseActions) Info(ctx context.Context) (any, error) {
	if err := b.c.requireUser(ctx); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/users/%s/base", b.c.UserID)
	var res any
	err := b.c.doApp(ctx, http.MethodGet, path, nil, nil, &res)
	return res, err
}

func (b *BaseActions) SetAngle(ctx context.Context, head, foot int) error {
	if err := b.c.requireUser(ctx); err != nil {
		return err
	}
	path := fmt.Sprintf("/users/%s/base/angle", b.c.UserID)
	body := map[string]any{"torsoAngle": head, "legAngle": foot}
	return b.c.doApp(ctx, http.MethodPost, path, nil, body, nil)
}

func (b *BaseActions) Presets(ctx context.Context) (any, error) {
	if err := b.c.requireUser(ctx); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/users/%s/base/presets", b.c.UserID)
	var res any
	err := b.c.doApp(ctx, http.MethodGet, path, nil, nil, &res)
	return res, err
}

// RunPreset looks up the preset angles from the API and calls SetAngle to
// physically move the base. Priority order:
//  1. name+"-custom" — user's saved custom variant (e.g. "relaxing-custom")
//  2. Exact name with non-zero angles (e.g. "reading-default", "anti-snore-low")
//  3. First sub-preset with metaOf==name that has non-zero angles
//  4. Exact name even if angles are zero (e.g. "flat" legitimately goes to 0,0)
func (b *BaseActions) RunPreset(ctx context.Context, name string) error {
	if err := b.c.requireUser(ctx); err != nil {
		return err
	}

	// Fetch all presets from API.
	presetsRes, err := b.Presets(ctx)
	if err != nil {
		return fmt.Errorf("fetching presets: %w", err)
	}

	presetsMap, ok := presetsRes.(map[string]any)
	if !ok {
		return fmt.Errorf("unexpected presets response type")
	}
	rawPresets, ok := presetsMap["presets"]
	if !ok {
		return fmt.Errorf("no 'presets' field in response")
	}
	presetsList, ok := rawPresets.([]any)
	if !ok {
		return fmt.Errorf("unexpected presets list type")
	}

	type presetEntry struct {
		torsoAngle float64
		legAngle   float64
		metaOf     string
	}

	byName := make(map[string]presetEntry)
	for _, p := range presetsList {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		n, _ := pm["name"].(string)
		e := presetEntry{}
		if v, ok := pm["torsoAngle"].(float64); ok {
			e.torsoAngle = v
		}
		if v, ok := pm["legAngle"].(float64); ok {
			e.legAngle = v
		}
		if v, ok := pm["metaOf"].(string); ok {
			e.metaOf = v
		}
		byName[n] = e
	}

	// Priority 1: user's custom variant (e.g. "relaxing-custom").
	if custom, found := byName[name+"-custom"]; found && (custom.torsoAngle != 0 || custom.legAngle != 0) {
		return b.SetAngle(ctx, int(custom.torsoAngle), int(custom.legAngle))
	}

	// Priority 2: exact match with non-zero angles.
	if exact, found := byName[name]; found && (exact.torsoAngle != 0 || exact.legAngle != 0) {
		return b.SetAngle(ctx, int(exact.torsoAngle), int(exact.legAngle))
	}

	// Priority 3: first sub-preset (metaOf==name) with non-zero angles.
	// Iterate the original ordered list to prefer defaults that appear first.
	for _, p := range presetsList {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		metaOf, _ := pm["metaOf"].(string)
		if metaOf != name {
			continue
		}
		torso, _ := pm["torsoAngle"].(float64)
		leg, _ := pm["legAngle"].(float64)
		if torso != 0 || leg != 0 {
			return b.SetAngle(ctx, int(torso), int(leg))
		}
	}

	// Priority 4: exact match even with 0/0 angles (e.g. "flat").
	if exact, found := byName[name]; found {
		return b.SetAngle(ctx, int(exact.torsoAngle), int(exact.legAngle))
	}

	return fmt.Errorf("preset %q not found", name)
}

func (b *BaseActions) VibrationTest(ctx context.Context) error {
	deviceID, err := b.c.EnsureDeviceID(ctx)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/devices/%s/vibration-test", deviceID)
	return b.c.doApp(ctx, http.MethodPost, path, nil, map[string]any{}, nil)
}
