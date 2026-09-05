package client

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// HouseholdUserTarget describes a user that can be targeted for side-aware actions.
type HouseholdUserTarget struct {
	UserID    string
	Side      string
	FirstName string
	LastName  string
	Email     string
}

func (t HouseholdUserTarget) DisplayName() string {
	name := strings.TrimSpace(strings.TrimSpace(t.FirstName + " " + t.LastName))
	if name != "" {
		return name
	}
	if t.Email != "" {
		return t.Email
	}
	return t.UserID
}

func (t HouseholdUserTarget) SideLabel() string {
	side := strings.TrimSpace(strings.ToLower(t.Side))
	if side == "" {
		return "unknown"
	}
	return side
}

// HouseholdUserTargets returns the household users that can be targeted for side-aware commands.
func (c *Client) HouseholdUserTargets(ctx context.Context) ([]HouseholdUserTarget, error) {
	deviceID, err := c.EnsureDeviceID(ctx)
	if err != nil {
		return nil, err
	}
	var deviceRes struct {
		Result struct {
			LeftUserID  string            `json:"leftUserId"`
			RightUserID string            `json:"rightUserId"`
			AwaySides   map[string]string `json:"awaySides"`
		} `json:"result"`
	}
	path := fmt.Sprintf("/devices/%s", deviceID)
	query := mapToValues(map[string]string{
		"filter": "leftUserId,rightUserId,awaySides",
	})
	if err := c.do(ctx, http.MethodGet, path, query, nil, &deviceRes); err != nil {
		return nil, err
	}

	sideByUser := sideAssignmentsFromDevice(deviceRes.Result.LeftUserID, deviceRes.Result.RightUserID, deviceRes.Result.AwaySides)

	userIDs := orderedUniqueStrings(
		deviceRes.Result.LeftUserID,
		deviceRes.Result.RightUserID,
	)
	for _, awayUserID := range deviceRes.Result.AwaySides {
		userIDs = appendUniqueString(userIDs, awayUserID)
	}
	targets := make([]HouseholdUserTarget, 0, len(userIDs))
	for _, userID := range userIDs {
		var userRes struct {
			User struct {
				UserID        string `json:"userId"`
				FirstName     string `json:"firstName"`
				LastName      string `json:"lastName"`
				Email         string `json:"email"`
				CurrentDevice struct {
					Side string `json:"side"`
				} `json:"currentDevice"`
			} `json:"user"`
		}
		if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/users/%s", userID), nil, nil, &userRes); err != nil {
			return nil, err
		}
		targets = append(targets, HouseholdUserTarget{
			UserID:    userRes.User.UserID,
			Side:      resolveTargetSide(sideByUser[userRes.User.UserID], userRes.User.CurrentDevice.Side),
			FirstName: userRes.User.FirstName,
			LastName:  userRes.User.LastName,
			Email:     userRes.User.Email,
		})
	}
	if len(targets) == 1 && strings.TrimSpace(targets[0].Side) == "" {
		targets[0].Side = "solo"
	}
	return targets, nil
}

// sideAssignmentsFromDevice builds a userID -> side map from the /devices payload.
// Away mode can collapse both top-level IDs onto the present user or omit them.
// Distinct awaySides IDs retain the true left/right mapping.
func sideAssignmentsFromDevice(leftUserID, rightUserID string, awaySides map[string]string) map[string]string {
	awayLeft := awaySides["leftUserId"]
	awayRight := awaySides["rightUserId"]

	if awayLeft != "" && awayRight != "" && awayLeft != awayRight {
		leftUserID, rightUserID = awayLeft, awayRight
	} else {
		if leftUserID == "" {
			leftUserID = awayLeft
		}
		if rightUserID == "" {
			rightUserID = awayRight
		}
	}
	out := map[string]string{}
	switch {
	case leftUserID != "" && rightUserID != "" && leftUserID == rightUserID:
		out[leftUserID] = "solo"
	case leftUserID != "" && rightUserID != "":
		out[leftUserID] = "left"
		out[rightUserID] = "right"
	case leftUserID != "" && rightUserID == "":
		out[leftUserID] = "solo"
	case leftUserID == "" && rightUserID != "":
		out[rightUserID] = "solo"
	}
	return out
}

// resolveTargetSide prefers the device-level assignment and ignores
// user.currentDevice.side when it is the Away-mode sentinel.
func resolveTargetSide(deviceAssigned, userReported string) string {
	if deviceAssigned != "" {
		return deviceAssigned
	}
	candidate := strings.ToLower(strings.TrimSpace(userReported))
	switch candidate {
	case "left", "right", "solo":
		return candidate
	}
	return ""
}

// ResolveHouseholdSide resolves a single user target for left/right/solo side-aware commands.
func ResolveHouseholdSide(targets []HouseholdUserTarget, side string) (*HouseholdUserTarget, error) {
	side = strings.ToLower(strings.TrimSpace(side))
	switch side {
	case "left", "right", "solo":
	default:
		return nil, fmt.Errorf("invalid side %q; expected left, right, or solo", side)
	}

	matches := []HouseholdUserTarget{}
	available := []string{}
	for _, target := range targets {
		switch target.Side {
		case "left", "right", "solo":
			available = appendUniqueString(available, target.Side)
		}
		if target.Side == side {
			matches = append(matches, target)
		}
	}

	if len(matches) == 1 {
		match := matches[0]
		return &match, nil
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("side %q maps to multiple household users; use --target-user-id", side)
	}
	if len(available) == 0 {
		return nil, fmt.Errorf("could not resolve household side mapping; use --target-user-id")
	}
	return nil, fmt.Errorf("side %q is not available for this household; available sides: %s", side, strings.Join(available, ", "))
}
