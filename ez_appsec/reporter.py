"""Integration with reporting formats"""

import json
from pathlib import Path
from typing import Dict, List, Any


VIRTUAL_LOCATION_PREFIXES = ("dependency:", "image:")


def _coerce_sarif_uri(value: Any) -> str:
    """Coerce scanner file/location values into a SARIF artifact URI string."""
    if isinstance(value, Path):
        return value.as_posix().replace("\\", "/")
    if isinstance(value, dict):
        for key in ("uri", "file", "path", "name"):
            nested = value.get(key)
            if nested:
                return _coerce_sarif_uri(nested)
        return "unknown"
    if isinstance(value, (list, tuple)):
        for item in value:
            if item:
                return _coerce_sarif_uri(item)
        return "unknown"
    if value is None:
        return "unknown"
    text = str(value).strip()
    return text.replace("\\", "/") if text else "unknown"


def _is_virtual_location(value: Any) -> bool:
    """Return true for scanner labels that are not repository file URIs."""
    if not isinstance(value, str):
        return False
    normalized = value.strip().lower()
    return normalized.startswith(VIRTUAL_LOCATION_PREFIXES)


class Reporter:
    """Generate reports in various formats"""
    
    @staticmethod
    def to_json(results: Dict[str, Any], file_path: str) -> None:
        """Export results to JSON"""
        with open(file_path, "w") as f:
            json.dump(results, f, indent=2)
    
    @staticmethod
    def to_sarif(results: Dict[str, Any]) -> Dict[str, Any]:
        """Convert to SARIF format (GitHub/GitLab compatible)"""
        runs = []
        
        for issue in results.get("issues", []):
            result = {
                "ruleId": issue.get("type", "UNKNOWN"),
                "message": {
                    "text": issue.get("title", "")
                },
                "level": issue.get("severity", "note").lower()
            }
            location = issue.get("file")
            if _is_virtual_location(location):
                # Values such as "dependency: requests" are labels, not URIs.
                # Emitting them as artifactLocation.uri makes GitHub reject the
                # entire upload because their URI scheme differs from checkout.
                result["properties"] = {"virtualLocation": str(location)}
            else:
                result["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": _coerce_sarif_uri(location)
                            },
                            "region": {
                                "startLine": issue.get("line", 1)
                            }
                        }
                    }
                ]
            runs.append(result)
        
        return {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ez-appsec",
                            "version": "0.1.0"
                        }
                    },
                    "results": runs
                }
            ]
        }
