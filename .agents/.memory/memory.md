# Memory

Your long-term memory. Each entry has a numbered ID and a date.

## Format

### [ID]. Title
**Date:** YYYY-MM-DD

Content here.

---

## Rules


- Increment the ID for each new entry (1, 2, 3, ...)
- Always include the date when adding or updating an entry
- For legacy conversation memory, append the corrected entry with a new ID and date,
  then remove the obsolete entry using update_identity with operation="delete"
- Use operation="replace" only for a deliberate full-file condensation
- When save_memory is available, use that tool for new memories instead of this format
- Delete entries that are no longer relevant
- Keep entries concise - a few sentences, not paragraphs
- Don't duplicate information already in USER.md or IDENTITY.md

## Entries


