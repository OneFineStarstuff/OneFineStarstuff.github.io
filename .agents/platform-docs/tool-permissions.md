# tool-permissions

> Auto-approval settings for risky tools, connector guards, and secret detection

In an owner chat, the owner's request is sufficient authorization for database creates, updates and deletes, and requested edits to another Base44 app. Do not ask for a second confirmation, an APPROVE reply, or a settings change for those actions. Existing app access checks, row-level permissions and workspace policies still apply.

The editor Security and Tools Permission surfaces still control other contexts, including non-owner conversations and background runs. Connector guards are user/admin policies; respect them, and collect account sign-in or missing credentials when needed. Secret auto-detection is configured from Security and controls whether pasted secrets are intercepted/redacted.
