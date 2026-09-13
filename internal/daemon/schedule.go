package daemon

import (
	"fmt"
	"time"
)

type timedAction struct {
	ScheduleItem
	hour, minute int
	level        int
}

func prepareSchedule(items []ScheduleItem) ([]timedAction, error) {
	prepared := make([]timedAction, 0, len(items))
	for _, item := range items {
		at, err := time.Parse("15:04", item.Time)
		if err != nil {
			return nil, fmt.Errorf("parse time %s: %w", item.Time, err)
		}
		action := timedAction{ScheduleItem: item, hour: at.Hour(), minute: at.Minute()}
		switch item.Action {
		case "on", "off":
		case "temp":
			action.level, err = ParseTemp(item.Temperature)
			if err != nil {
				return nil, fmt.Errorf("schedule %s: %w", item.Time, err)
			}
		default:
			return nil, fmt.Errorf("unknown action %s", item.Action)
		}
		prepared = append(prepared, action)
	}
	return prepared, nil
}
