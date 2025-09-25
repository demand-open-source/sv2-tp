# Internal c++ interfaces

The SV2 fork keeps only the interfaces needed by the template provider runtime:

* [`Init`](init.h) — used by multiprocess code to obtain the Mining interface during startup. Added in [#19160](https://github.com/bitcoin/bitcoin/pull/19160).

* [`Ipc`](ipc.h) — used by multiprocess code to access `Init` across processes. Added in [#19160](https://github.com/bitcoin/bitcoin/pull/19160).

* [`Mining`](mining.h) — exposes block template creation primitives consumed by the template provider.

Legacy `Chain`, `ChainClient`, and `Node` interfaces were removed along with their IPC bindings because they are not required for the SV2 workflow.
