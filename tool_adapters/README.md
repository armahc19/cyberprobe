# CyberProbe tool adapters

Adapters expose tool capabilities without exposing arbitrary shell commands to
agents. A future adapter should provide a manifest, a validated command
builder, and an output parser that returns the common `ToolResult` shape.

Example:

```python
from tool_adapters import default_registry

registry = default_registry()
result = registry.run("nmap", "service_detection", {"target": "192.0.2.10"})
```

Agents should select a capability (`service_detection`), not construct flags.

`ToolEngine` sits above the registry and selects the first available preferred
adapter, with fallback support:

```python
from tool_adapters import ToolEngine

engine = ToolEngine()
result = engine.run("port_scanning", {"target": "192.0.2.10"})
```
