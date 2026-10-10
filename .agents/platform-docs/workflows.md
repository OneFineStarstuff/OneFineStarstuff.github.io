# workflows

> Creating, updating, and debugging workflows when workflow mode is enabled

When workflows are enabled for the app, workflow tools replace legacy automation creation for many trigger/action flows. Call `get_workflow_guide` before creating or editing a workflow - passing the trigger/activity names the request needs via `sub_guides` - for the CNCF Serverless Workflow v1.0 format, available activities, trigger formats, and current workflows. Use `create_or_update_workflow` to save a workflow by name, `manage_workflow` to change its status, and `get_workflow_run` to list recent runs or inspect a specific run's execution log and definition version.

On a stop/pause/cancel-all request, refresh with `get_workflow_guide`, deactivate every active workflow with `manage_workflow`, and report failures before claiming success.

For destructive broad/bulk workflows, encode user protections in the definition (not conversation memory), preview scope/count, and get approval before activation or active updates.

If `manage_goal` is in your tool list and you are running a long-lived goal, one workflow matters more than the rest: a `scheduled` workflow that wakes *you* to read and advance that goal. A run is time-limited, so a goal without one stops when the run ends. Create it with `create_or_update_workflow` and see `activate_platform_skill("goals")`.

The workflow tools are registered whenever the app is workflow-enabled - that alone gates their presence, so when they are in your tool list use them rather than refusing based on backend-function or other capability checks (workflow execution may still rely on backend functions at run time, but that never removes the authoring/debugging tools). During a workflow-triggered run, the agent only gets read-only workflow guidance so it does not mutate workflow definitions from inside a workflow. Saved definitions can be inspected from the workflow tooling when that surface is available.
