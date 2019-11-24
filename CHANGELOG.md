# Changelog: 

### 1.0.2
**Feature enhancements:**

- Added basic web port (80/443) inspection for enumerated hosts with a chat status update.
- Added basic POST callback `!post` to run through the startup commands for debugging purposes. 

**Bugfixes:**

- Updated help menu.
- Added error handling for hastebin uploads. 
- Added checks to validate override parameters for host inspections.
- Fixed error with host inspection not properly handling integer return codes.
- Added more verbosity to errors provided by host inspection. 
- Migrated hastebin.com data upload to ghostbin.co due to 403 errors returned.

### 1.0.1
- Modified wfuzz calls to follow redirects to end, which removes the necessity for a percentage based result filter. (initial commit)
- Hardcoded `!hi` to have a strength of 1 by default, for easier usage. Added override to allow more detailed wordfilters, updated console debugging. (initial commit)

### 1.0.0 
Initial release. (initial commit)
