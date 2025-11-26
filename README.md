# K1 Speed Fastlap Chart

## Lap time cutoffs
These track-specific cutoffs are applied when parsing lap data and can also be re-applied to historical sessions:

- Burbank: 22.0 seconds
- Culver City Track 1: 27.0 seconds
- Thousand Oaks: 26.5 seconds
- Torrance Track 1: 26.5 seconds

## Reapplying lap cutoffs to existing sessions
Use the built-in Flask CLI command to enforce updated cutoffs without reimporting emails:

1. Activate the same environment this app runs in and ensure it can reach the database (defaults to `sqlite:////data/data.db`).
2. Run the command:
   ```bash
   flask --app app reapply_cutoffs
   ```
3. The command reloads each session's `lap_data`, filters laps using the track display name, recalculates totals/averages, and commits changes. Sessions that already match the current cutoffs are skipped.
4. Review the printed summary of how many sessions were updated.

This is a safe, idempotent operation you can rerun anytime lap cutoffs change.
