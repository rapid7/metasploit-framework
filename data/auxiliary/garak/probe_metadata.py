# Read metadata through garak's plugin API. Do not instantiate or run plugins.
# API: https://github.com/NVIDIA/garak/blob/main/garak/_plugins.py
import json
import sys

import garak
from garak import _plugins


def metadata(name):
    info = _plugins.plugin_info(name)
    if not isinstance(info, dict):
        return {"inputs": None, "active": None}
    modality = info.get("modality")
    return {
        "inputs": modality.get("in") if isinstance(modality, dict) else None,
        "active": info.get("active"),
    }


result = {
    "garak_version": getattr(garak, "__version__", None),
    "probes": {name: metadata(name) for name, _ in _plugins.enumerate_plugins("probes")},
    "generators": {name: metadata("generators." + name) for name in sys.argv[2:]},
}
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump(result, output, cls=_plugins.PluginEncoder)
