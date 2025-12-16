# Iris: Expressive Traffic Analysis for the Modern Internet

Iris is an open-source framework for executing traffic analysis research.

Iris provides high-level abstractions, like [Zeek](https://zeek.org), alongside low-level, performant access to connection data. Iris absorbs the common, tedious tasks associated with traffic analysis, leaving researchers to focus on what is relevant to their use-cases. In experiments on the Stanford University network, we find that Iris can execute hundreds of concurrent, complex analsysis tasks at 100Gbps+ on a single commodity server.

## Note for Artifact Evaluation

Meaningfully replicating the experiments in the Iris paper requires access to live traffic.
However, Iris supports offline development and evaluation using packet captures.

Full Rust crate documentation for using and developing against Iris will be improved and released in the coming weeks. This is an initial version.

## Iris Programming Framework

An Iris application consists of *one or more* traffic *subscriptions*, each of which consists of filters, data types, and callbacks over tracked connections.

* **Subscription Programming Model.** Iris supports analyzing packets, reassembled streams, and parsed application sessions within a bidirectional, "five-tuple"-defined connection. Each subscription includes a filter (what data is of interest?), a set of data types (what format should the data be delivered in?), and callback (what to do with the data?).

* **User-Defined Filters, Data Types, and Callbacks.** Iris provides complete programmable control over filter predicates, data transformation and construction, and callback (analysis) code.

* **Connection Scope.** Iris scopes subscriptions to inferred connections, i.e., bidirectional packet streams associated with the same five-tuple until a FIN/ACK sequence, RST, or user-configurable inactivity timeout. Connections may not fully establish (i.e., an unanswered SYN is treated as a ``connection'' by \system).
Applications that analyze data across connections can be built on top of \system, much like Iris is built on top of DPDK.

* **State Machines.** To expose both common abstractions and low-level access to connection data, Iris presents connections to user code as a set of protocol-specific state machines that user-defined functions can hook into.
Iris currently supports the states and state transitions described in [DataLevel](core/src/conntrack/conn/conn_state.rs#L29).
Iris processes packets in a connection as they arrive, advancing the connection through its state machines. Note that some events carry data (e.g., observed packet, parsed application headers).

## Writing an Iris Application

See the [examples](./examples/) directory for example applications.

### Data Types

Iris defines three primitive data types: raw packets, reassembled streams, and parsed fields available within any state transition (["DataLevel"](./core/src/conntrack/conn/conn_state.rs#L29)).
User-defined Iris data types are defined in Rust and can access any of these primitive data types to create higher-level abstractions, which are then made available to filters and callbacks.

A variety of default data types are provided in the [datatypes](./datatypes) crate.

For example, to request TLS handshakes, a data type defined in [datatypes](./datatypes/src/tls_handshake.rs), a user could write a callback:

```rust
// Filter for TLS;
#[callback("tls")]
fn callback(tls: &TlsHandshake) {}
```

A callback can request multiple data types, e.g.:

```rust
#[callback("tls")]
fn callback(tls: &TlsHandshake, conn: &ConnRecord) {}
```

Users can also define their own data types, using the #[datatype] macro for the parent struct and the #[dataype_fn] for included methods.

For example, the [openvpn](./examples/open_vpn) example defines multiple custom data types.

```rust
#[datatype]
pub struct OpenVPNOpcode {
    // ... fields
}

impl OpenVPNOpcode {
    /// The "new" function must take in a PDU
    pub fn new(_pdu: &L4Pdu) -> Self {
        // ...
    }

    /// Methods can take in any Iris data types.
    /// They must specify the name of the data type
    /// for compiler interpretation, as well as the DataLevel
    /// (i.e., streaming state or state transition at which
    /// this function should be invoked).
    #[datatype_group("OpenVPNOpcode,level=L4InPayload")]
    pub fn new_packet(&mut self, pdu: &L4Pdu) {
        // ...
    }
}
```

### Filters

Iris supports the Wireshark-like filter syntax introduced by [Retina](https://stanford-esrg.github.io/retina/retina_filtergen/index.html) for filtering on protocols and protocol fields.

Iris also supports defining custom (stateful or stateless) filters, similar to data types. Custom filter functions must return a `FilterResult` (Accept, Drop, or Continue). Stateful filters (i.e., those associated with a struct) must implement the [StatefulFilter](./core/src/subscription/filter.rs) trait.

For example, the [basic](./examples/basic) filters for "short" connections:

```rust
// Tag with a filter
#[filter]
struct ShortConnLen {
    len: usize,
}

// Every stateful filter must implement StreamingFilter
impl StreamingFilter for ShortConnLen {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self { len: 0 }
    }
    fn clear(&mut self) {}
}

impl ShortConnLen {
    // As with data types, filter functions must specify
    // when they should be invoked.
    #[filter_group("ShortConnLen,level=L4InPayload")]
    fn update(&mut self, _: &L4Pdu) -> FilterResult {
        self.len += 1;
        if self.len > 10 {
            // Dropping connections early helps Iris
            // quickly discard out-of-scope traffic.
            return FilterResult::Drop;
        }
        FilterResult::Continue
    }

    #[filter_group("ShortConnLen,level=L4Terminated")]
    fn terminated(&self) -> FilterResult {
        if self.len <= 10 {
            FilterResult::Accept
        } else {
            FilterResult::Drop
        }
    }
}
```

### Callbacks

Callbacks execute arbitrary Rust code with access to one or more Iris datatypes for traffic that meets filter conditions. Callbacks that stream data within a state (e.g., to analyze video segments every ten seconds) are called repeatedly within a connection until they unsubscribe.

Callbacks can stream data over the course of a connection, optionally returning `false` to unsubscribe (i.e., stop receiving data).
For example, the [video](./examples/ml_qos/) example streams likely video traffic to perform inference:

```rust
/// Callbacks can specify a filter
#[callback("tls")]
#[derive(Debug, Serialize)]
struct Predictor {
    // ...
}

/// Streaming callbacks must implement this trait
impl StreamingCallback for Predictor {
    fn new(_first_pkt: &L4Pdu) -> Predictor { /* ... */ }
    fn clear(&mut self) { /* ... */ }
}

/// Defining callback functions is similar to filter and data type functions
impl Predictor {
    #[callback_group("Predictor,level=L4InPayload")]
    fn update(&mut self, tracked: &FeatureChunk, start: &StartTime) -> bool {
        // ...
    }
}
```

## Installing

Follow the instructions in [INSTALL.md](INSTALL.md) to set up Iris. Note that, because Iris uses DPDK, it must be run as root.

Use `configs/offline.toml` to run Iris in ``offline'' mode (i.e., on a packet capture).