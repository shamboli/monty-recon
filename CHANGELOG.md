# Changelog: 

### 1.0.3
**Feature enhancements:**

- Added support for GitHub Gists. Previously used data uploading sites (pastebin, hastebin, ghostbin,etc) were insufficient for the amount of data that could be accumulated via host or subdomain inspections. Create an API with gist permission, and add your API token in `config.py`. Due to some character limitations in Gist creation, URLs are SHA1 hashed, and the resultant hash is used as the Gist title. 
- Added a percentage based status indicator for subdomain inspection. Monty will send an update at approximately 25, 50 and 75 percent complete (not rounded because it looks cool)

**Bugfixes:**

- Added logic to fix an infinite redirect for sites which redirect invalid paths to a homepage or other landing page. 
- Added and removed support for Sprunge.us as a data uploader. 
- Added user whitelisting for the basic POST callback, `!post`.
- Added basic URL input sanitization for subdomain inspection. Subdomain inspection now supports `https://google.com/` as input, or `google.com` (`https://google.com///////////' turns into `https://google.com/`)
- General text cleanup/formatting.

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
