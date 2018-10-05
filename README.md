# dradis-issue-janitorbot
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
