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

Set `sensors.process_monitor.enabled` to `false` in the local configuration
and restart the application to prevent ongoing process collection. The value
must be a JSON boolean. A missing value keeps the existing enabled default.
Values such as the string `"false"` do not enable collection.

The collector reports whether it is running, stopping, stopped or off. When
stopped, the previous observation remains available and is not a new reading.
Stored database evidence is retained. This setting controls ongoing process
observation, not every local inspection performed by other features.

Stopping wakes a collector waiting for its next pass. If a pass is already
running, stopping waits up to three seconds by default and returns whether
the worker has finished. A caller can supply another wait duration. A new
worker cannot start while the previous worker is still finishing.

The current settings panel does not provide a general live feature switch.
Editing this configuration remains a restart operation. The interactive
design preview illustrates a proposed interface and is not a live control.

## Measurement limits

Offline backend measurements exclude native capture, helper services,
network serving, the browser and representative production data. They must
not be presented as the full application's live memory requirement. Test
each enabled feature and the complete process group before setting a
production resource target.
