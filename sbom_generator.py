import json
import uuid
from datetime import datetime
import re

class SBOMGenerator:
    @staticmethod
    def generate_cyclonedx(requirements_content, project_name="scanned-project"):
        components = []
        for line in requirements_content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            match = re.match(r'^([a-zA-Z0-9_\-]+)\s*==\s*([0-9a-zA-Z\.\-]+)', line)
            if match:
                pkg_name = match.group(1).lower()
                pkg_version = match.group(2)
                components.append({
                    "type": "library",
                    "name": pkg_name,
                    "version": pkg_version,
                    "purl": f"pkg:pypi/{pkg_name}@{pkg_version}"
                })
            else:
                match_pkg = re.match(r'^([a-zA-Z0-9_\-]+)', line)
                if match_pkg:
                    pkg_name = match_pkg.group(1).lower()
                    components.append({
                        "type": "library",
                        "name": pkg_name
                    })

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [{"vendor": "AI-SecScan", "name": "AI-SecScan", "version": "1.0.0"}],
                "component": {"type": "application", "name": project_name}
            },
            "components": components
        }
        return json.dumps(sbom, indent=4)