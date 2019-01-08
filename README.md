Dradis-Issue-JanitorBot (https://govanguard.io)
==
[![Build Status](https://travis-ci.com/GoVanguard/dradis-issue-janitorbot.svg?branch=master)](https://travis-ci.com/GoVanguard/dradis-issue-janitorbot)
[![Known Vulnerabilities](https://snyk.io/test/github/GoVanguard/dradis-issue-janitorbot/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/GoVanguard/dradis-issue-janitorbot?targetFile=requirements.txt)
[![Maintainability](https://api.codeclimate.com/v1/badges/c13411c956ec363b3f89/maintainability)](https://codeclimate.com/github/GoVanguard/dradis-issue-janitorbot/maintainability)

# About dradis-issue-janitorbot
Script for removing bad characters from Dradis issues and evidence that might break report generation. Two scripts are provided: one for issues, one for evidence.

## Installation
```git clone https://github.com/GoVanguard/dradis-issue-janitorbot.git```

## Recommended Python Version
Python 3.5+

## Dependencies
PyDradis3: https://github.com/GoVanguard/pydradis3 (also in PyPi)

## Usage
```python dradisIssueJanitor.py <dradis_URL> <project_ID> <API_token>```

```python dradisEvidenceJanitor.py <dradis_URL> <project_ID> <API_token>```

## License
GNU Affero General Public License v3.0
