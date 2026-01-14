/* This is roughly what the code looks like with macros expanded. */

impl ConnVolume {
    pub fn new(_pdu: &L4Pdu) -> Self {
        ConnVolume { count: 0 }
    }
    pub fn new_packet(&mut self, _pdu: &L4Pdu) {
        self.count += 1;
    }
}

pub fn record_data(conn: &ConnVolume) {
    {
        ::std::io::_print(format_args!("Invoked: {0}\n", conn.count));
    };
}

use iris_core::subscription::{Trackable, Subscribable};
use iris_core::conntrack::{TrackedActions, ConnInfo};
use iris_core::protocols::stream::ParserRegistry;
use iris_core::StateTransition;
use iris_core::subscription::*;
use iris_datatypes::*;

pub struct SubscribedWrapper;
impl Subscribable for SubscribedWrapper {
    type Tracked = TrackedWrapper;
}

pub struct TrackedWrapper {
    packets: Vec<iris_core::Mbuf>,
    core_id: iris_core::CoreId,
    connvolume: ConnVolume,
}

impl Trackable for TrackedWrapper {
    type Subscribed = SubscribedWrapper;
    fn new(first_pkt: &iris_core::L4Pdu, core_id: iris_core::CoreId) -> Self {
        Self {
            packets: Vec::new(),
            core_id,
            connvolume: ConnVolume::new(first_pkt),
        }
    }
    fn packets(&self) -> &Vec<iris_core::Mbuf> {
        &self.packets
    }
    fn core_id(&self) -> &iris_core::CoreId {
        &self.core_id
    }
    fn parsers() -> ParserRegistry {
        ParserRegistry::from_strings(Vec::from([]))
    }
    fn clear(&mut self) {
        self.packets.clear();
    }
}

pub fn filter() -> iris_core::filter::FilterFactory<TrackedWrapper> {
    fn packet_filter(mbuf: &iris_core::Mbuf, core_id: &iris_core::CoreId) -> bool {
        if let Ok(ethernet) = &iris_core::protocols::packet::Packet::parse_to::<
            iris_core::protocols::packet::ethernet::Ethernet,
        >(mbuf) {
            if let Ok(ipv4) = &iris_core::protocols::packet::Packet::parse_to::<
                iris_core::protocols::packet::ipv4::Ipv4,
            >(ethernet) {
                if let Ok(tcp) = &iris_core::protocols::packet::Packet::parse_to::<
                    iris_core::protocols::packet::tcp::Tcp,
                >(ipv4) {
                    return true;
                } else if let Ok(udp) = &iris_core::protocols::packet::Packet::parse_to::<
                    iris_core::protocols::packet::udp::Udp,
                >(ipv4) {
                    return true;
                }
            } else if let Ok(ipv6) = &iris_core::protocols::packet::Packet::parse_to::<
                iris_core::protocols::packet::ipv6::Ipv6,
            >(ethernet) {
                if let Ok(tcp) = &iris_core::protocols::packet::Packet::parse_to::<
                    iris_core::protocols::packet::tcp::Tcp,
                >(ipv6) {
                    return true;
                } else if let Ok(udp) = &iris_core::protocols::packet::Packet::parse_to::<
                    iris_core::protocols::packet::udp::Udp,
                >(ipv6) {
                    return true;
                }
            }
            return false;
        }
        false
    }

    fn state_tx(conn: &mut ConnInfo<TrackedWrapper>, tx: &iris_core::StateTransition) {
        match tx {
            StateTransition::L4FirstPacket => tx_l4firstpacket(conn, &tx),
            StateTransition::L4Terminated => tx_l4terminated(conn, &tx),
            _ => {}
        }
    }

    fn tx_l4firstpacket(conn: &mut ConnInfo<TrackedWrapper>, tx: &StateTransition) {
        let mut ret = false;
        let tx = iris_core::StateTxData::from_tx(tx, &conn.layers[0]);
        let mut transport_actions = iris_core::conntrack::TrackedActions::new();
        let mut layer0_actions = iris_core::conntrack::TrackedActions::new();
        if let Ok(ipv4) = &iris_core::protocols::stream::ConnData::parse_to::<
            iris_core::protocols::stream::conn::Ipv4CData,
        >(&conn.cdata) {
            if let Ok(tcp) = &iris_core::protocols::stream::ConnData::parse_to::<
                iris_core::protocols::stream::conn::TcpCData,
            >(&conn.cdata) {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(9),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(9),
                            ],
                        },
                    );
            } else if let Ok(udp) = &iris_core::protocols::stream::ConnData::parse_to::<
                iris_core::protocols::stream::conn::UdpCData,
            >(&conn.cdata) {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(9),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(9),
                            ],
                        },
                    );
            }
        } else if let Ok(ipv6) = &iris_core::protocols::stream::ConnData::parse_to::<
            iris_core::protocols::stream::conn::Ipv6CData,
        >(&conn.cdata) {
            if let Ok(tcp) = &iris_core::protocols::stream::ConnData::parse_to::<
                iris_core::protocols::stream::conn::TcpCData,
            >(&conn.cdata) {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(9),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(9),
                            ],
                        },
                    );
            } else if let Ok(udp) = &iris_core::protocols::stream::ConnData::parse_to::<
                iris_core::protocols::stream::conn::UdpCData,
            >(&conn.cdata) {
                transport_actions
                    .extend(
                        &TrackedActions {
                            active: iris_core::conntrack::Actions::from(9),
                            refresh_at: [
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(0),
                                iris_core::conntrack::Actions::from(9),
                            ],
                        },
                    );
            }
        }
        conn.linfo.actions.extend(&transport_actions);
        conn.layers[0].extend_actions(&layer0_actions);
    }

    fn tx_l4terminated(conn: &mut ConnInfo<TrackedWrapper>, tx: &StateTransition) {
        let mut ret = false;
        let tx = iris_core::StateTxData::from_tx(tx, &conn.layers[0]);
        let mut transport_actions = iris_core::conntrack::TrackedActions::new();
        let mut layer0_actions = iris_core::conntrack::TrackedActions::new();
        record_data(&conn.tracked.connvolume);
        conn.linfo.actions.extend(&transport_actions);
        conn.layers[0].extend_actions(&layer0_actions);
    }

    fn update(
        conn: &mut ConnInfo<TrackedWrapper>,
        pdu: &iris_core::L4Pdu,
        state: iris_core::StateTransition,
    ) -> bool {
        let mut ret = false;
        match state {
            StateTransition::L4InPayload(_) => {
                conn.tracked.connvolume.new_packet(pdu);
            }
            _ => {}
        }
        ret
    }

    iris_core::filter::FilterFactory::new(
        "((ipv4) and (tcp)) or ((ipv4) and (udp)) or ((ipv6) and (tcp)) or ((ipv6) and (udp))",
        packet_filter,
        state_tx,
        update,
    )
}

fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}