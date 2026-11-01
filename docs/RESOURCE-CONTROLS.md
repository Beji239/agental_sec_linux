# Startup loading and process observation

## Optional packages

Startup checks whether optional packages are present without loading their
implementations. A feature still needs to load its own dependencies when it
is used. An installed package may be broken or incompatible, so its presence
alone is not a successful feature check.

Required dashboard dependencies are still imported and checked at startup.
Optional package checks do not disable credential handling, access checks or
approval controls.

## Process observation

Open Settings, Choose what runs. Process observation is the first collector
with live controls.

Start now and Stop now affect ongoing collection in this session. They do
not change the next-start preference. An existing pass may finish after a
stop request, and the card shows Stopping until the worker exits. Starting a
second worker is refused while that happens.

Start automatically next time saves a separate preference. Saving it does
not start or stop collection now. It is stored as the JSON boolean
`feature_startup.process_monitor` in the local configuration.

When that preference is absent, `sensors.process_monitor.enabled` keeps its
existing startup meaning. A saved feature preference overrides the legacy
setting at the next launch. Existing installations retain their startup
behavior until the preference is explicitly saved.

The card shows current state, the last successful pass and any last error.
Stored findings are retained after stopping. The coverage history records
the paused interval, and an intentional stop is shown as off rather than as
a collector failure.

This switch controls the process-monitor passes on this computer. Kernel,
audit and other sources remain independent. Starting or stopping this
collector does not enable or disable every source of process information.

Stop ends the collector worker when its current pass finishes. Already
imported Python libraries remain in the main process. This is not a claim
that stopping the collector unloads all of its memory.

The read-only integration key can read `/api/features`. Only a dashboard
session can use the authenticated POST routes for current execution and
startup preferences. Opening the feature card does not start collection.

Configuration writes preserve other fields and keep the resulting file
readable and writable only by its owner.

## Measurement limits

Offline backend measurements exclude native capture, helper services,
network serving, the browser and representative production data. They must
not be presented as the full application's live memory requirement. Test
each enabled feature and the complete process group before setting a
production resource target.
