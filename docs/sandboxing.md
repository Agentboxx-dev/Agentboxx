# Zero-Trust Sandboxing & Hardware Isolation in Agentboxx

Autonomous agents executing untrusted code or arbitrary shell commands require runtime containment.
Agentboxx provides a multi-tiered sandboxing model ranging from lightweight containerization to zero-trust user-space kernel virtualization.

## Sandbox Isolation Tiers

| Sandbox Tier | Class | Isolation Boundary | Kernel Model | Primary Use Case |
|---|---|---|---|---|
| **Standard Docker** | `DockerSandbox` | cgroups, namespaces, capabilities | Shared host Linux kernel | Local development, trusted scripts, CI |
| **gVisor Zero-Trust** | `GVisorSandbox` | User-space Sentry kernel (`runsc`) | Dedicated user-space kernel | Multi-tenant SaaS, untrusted agent code, SOC 2 / HIPAA compliance |
| **MicroVM Hypervisor**| `MicroVMSandbox` | Hypervisor / KVM hardware virtualization | Virtualized guest kernel | High-security enterprise environments |

## How gVisor (`runsc`) Works

Standard Docker containers share the host operating system kernel. A kernel vulnerability allows code inside the container to compromise the entire host.
Under `GVisorSandbox`, every system call made by the agent is intercepted by **gVisor Sentry** in user-space, so the container never directly talks to the host Linux kernel.

## Python API Usage

```python
from agentbox import GVisorSandbox, Recorder

# Initialize with gVisor user-space kernel isolation
sandbox = GVisorSandbox(
    workspace='./workspace',
    memory='512m',
    cpus='1',
    require_gvisor=True,
)

rec = Recorder('session-1', workspace='./workspace', sandbox=sandbox)
rec.run('echo hello')
rec.close()
```

