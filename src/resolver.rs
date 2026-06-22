use std::{
    collections::BTreeSet,
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use crate::{
    OwnedPacket, Packet,
    dns::{
        DnsError, Message,
        client::{DnsClient, UdpDnsClient},
        flags::ResponseCode,
        name::Name,
        question::Question,
        record::Data,
    },
};

const MAX_REFERRAL_HOPS: usize = 16;
const MAX_LOOKUP_DEPTH: usize = 16;
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const ROOT_PORT: u16 = 53;
const DEFAULT_CLASS_IN: u16 = 1;

const ROOT_SERVER_IPS: [Ipv4Addr; 13] = [
    Ipv4Addr::new(198, 41, 0, 4),
    Ipv4Addr::new(199, 9, 14, 201),
    Ipv4Addr::new(192, 33, 4, 12),
    Ipv4Addr::new(199, 7, 91, 13),
    Ipv4Addr::new(192, 203, 230, 10),
    Ipv4Addr::new(192, 5, 5, 241),
    Ipv4Addr::new(192, 112, 36, 4),
    Ipv4Addr::new(198, 97, 190, 53),
    Ipv4Addr::new(192, 36, 148, 17),
    Ipv4Addr::new(192, 58, 128, 30),
    Ipv4Addr::new(193, 0, 14, 129),
    Ipv4Addr::new(199, 7, 83, 42),
    Ipv4Addr::new(202, 12, 27, 33),
];

pub fn resolve(packet: Packet) -> Result<OwnedPacket, ResolveError> {
    let query = Message::try_from(packet)?;
    let resolver = Resolver::new(UdpDnsClient::new(QUERY_TIMEOUT));
    resolver
        .resolve(query)
        .try_into()
        .map_err(ResolveError::from)
}

struct Resolver<C> {
    client: C,
    roots: Vec<SocketAddr>,
    max_referral_hops: usize,
    max_lookup_depth: usize,
}

enum ResolutionStep {
    Complete(Message),
    ContinueWith(Vec<SocketAddr>),
}

enum ReferralOutcome {
    NoReferral,
    Servers(Vec<SocketAddr>),
}

impl<C> Resolver<C> {
    fn new(client: C) -> Self {
        Self::with_config(client, root_servers(), MAX_REFERRAL_HOPS, MAX_LOOKUP_DEPTH)
    }

    fn with_config(
        client: C,
        roots: Vec<SocketAddr>,
        max_referral_hops: usize,
        max_lookup_depth: usize,
    ) -> Self {
        Self {
            client,
            roots,
            max_referral_hops,
            max_lookup_depth,
        }
    }
}

impl<C: DnsClient> Resolver<C> {
    fn resolve(&self, query: Message) -> Message {
        let response = query.clone().into_response().with_recursion_available();

        // the server only handles the simple one-question case for now
        if query.questions().len() != 1 {
            return response.with_response_code(ResponseCode::FormatError);
        }

        match self.resolve_from_roots(&query, 0) {
            Ok(response) => response,
            Err(_) => response.with_response_code(ResponseCode::ServerFailure),
        }
    }

    fn resolve_from_roots(
        &self,
        query: &Message,
        lookup_depth: usize,
    ) -> Result<Message, ResolveError> {
        if lookup_depth > self.max_lookup_depth {
            return Err(ResolveError::ResolutionFailed);
        }

        let mut current_servers = self.roots.clone();

        for _ in 0..self.max_referral_hops {
            match self.query_servers(&current_servers, query, lookup_depth)? {
                ResolutionStep::Complete(response) => return Ok(response),
                ResolutionStep::ContinueWith(next_servers) => current_servers = next_servers,
            }
        }

        Err(ResolveError::ResolutionFailed)
    }

    fn query_servers(
        &self,
        servers: &[SocketAddr],
        query: &Message,
        lookup_depth: usize,
    ) -> Result<ResolutionStep, ResolveError> {
        let mut next_servers = BTreeSet::new();
        let mut terminal_response = None;

        for server in servers.iter().copied() {
            let response = match self.client.exchange(server, query) {
                Ok(response) => response,
                Err(_) => continue,
            };

            if !response.answers().is_empty()
                || response.flags().response_code() != ResponseCode::NoError
            {
                return Ok(ResolutionStep::Complete(response));
            }

            match self.referral_servers(&response, lookup_depth) {
                ReferralOutcome::Servers(referrals) => next_servers.extend(referrals),
                ReferralOutcome::NoReferral => terminal_response = Some(response),
            }
        }

        if next_servers.is_empty() {
            terminal_response
                .map(ResolutionStep::Complete)
                .ok_or(ResolveError::ResolutionFailed)
        } else {
            Ok(ResolutionStep::ContinueWith(
                next_servers.into_iter().collect(),
            ))
        }
    }

    fn referral_servers(&self, response: &Message, lookup_depth: usize) -> ReferralOutcome {
        let mut referrals = response.referrals().peekable();
        if referrals.peek().is_none() {
            return ReferralOutcome::NoReferral;
        }

        let servers = referrals
            .flat_map(|referral| {
                if referral.has_glue() {
                    referral.into_addrs()
                } else {
                    self.resolve_nameserver_ips(referral.ns_name(), lookup_depth)
                }
            })
            .collect();

        ReferralOutcome::Servers(servers)
    }

    fn resolve_nameserver_ips(&self, name: &Name, lookup_depth: usize) -> Vec<SocketAddr> {
        let mut servers = BTreeSet::new();

        for record_type in [1_u16, 28_u16] {
            let query = Message::new_query(
                0,
                Question {
                    name: name.clone(),
                    record_type,
                    class: DEFAULT_CLASS_IN,
                },
            );
            let response = match self.resolve_from_roots(&query, lookup_depth + 1) {
                Ok(response) => response,
                Err(_) => continue,
            };

            for answer in response.answers() {
                if answer.name() != name {
                    continue;
                }

                match answer.data() {
                    Data::A(ip) => {
                        servers.insert(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*ip)), ROOT_PORT));
                    }
                    Data::Aaaa(ip) => {
                        servers.insert(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*ip)), ROOT_PORT));
                    }
                    _ => {}
                }
            }
        }

        servers.into_iter().collect()
    }
}

fn root_servers() -> Vec<SocketAddr> {
    ROOT_SERVER_IPS
        .iter()
        .map(|ip| SocketAddr::new(IpAddr::V4(*ip), ROOT_PORT))
        .collect()
}

#[derive(Debug)]
pub enum ResolveError {
    Io(std::io::Error),
    Dns(DnsError),
    ResolutionFailed,
}
impl Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::Dns(e) => write!(f, "ResolveError: {e}"),
            ResolveError::Io(e) => write!(f, "IoError: {e}"),
            ResolveError::ResolutionFailed => write!(f, "ResolveError: resolution failed"),
        }
    }
}
impl From<DnsError> for ResolveError {
    fn from(value: DnsError) -> Self {
        Self::Dns(value)
    }
}
impl From<std::io::Error> for ResolveError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        OwnedPacket,
        dns::{
            Message,
            flags::{Flags, QueryOrResponse, ResponseCode},
            header::Header,
            name::Name,
            question::Question,
            record::{Data, Record},
        },
    };
    use pretty_assertions::assert_eq;
    use std::{
        cell::RefCell,
        net::{IpAddr, SocketAddr},
        rc::Rc,
    };

    #[test]
    fn resolve_returns_format_error_for_multiple_questions_without_using_client() {
        let client = Rc::new(ScriptedClient::new());
        let resolver = Resolver::with_config(
            client.clone(),
            vec![SocketAddr::new(IpAddr::V4(ROOT_SERVER_IPS[0]), ROOT_PORT)],
            4,
            4,
        );

        let query = Message::new(
            Header::new(0x1234, Flags::from(0x0100)),
            vec![
                Question {
                    name: Name::from_labels(&["example", "com"]),
                    record_type: 1,
                    class: 1,
                },
                Question {
                    name: Name::from_labels(&["www", "example", "com"]),
                    record_type: 1,
                    class: 1,
                },
            ],
            vec![],
            vec![],
            vec![],
        );

        let response = resolver.resolve(query);

        assert_eq!(response.flags().response_code(), ResponseCode::FormatError);
        assert!(client.calls().is_empty());
    }

    #[test]
    fn resolver_chases_referrals_via_the_client() {
        let client = Rc::new(ScriptedClient::new());
        let resolver = Resolver::with_config(
            client.clone(),
            vec![SocketAddr::new(IpAddr::V4(ROOT_SERVER_IPS[0]), ROOT_PORT)],
            8,
            8,
        );

        let query = query_message(0x1234, "example", "com", 1);
        let response = resolver.resolve(query.clone());

        assert_eq!(
            response.flags().query_or_response(),
            QueryOrResponse::Response
        );
        assert_eq!(response.flags().response_code(), ResponseCode::NoError);
        assert_eq!(response.id(), query.id());
        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].data(), &Data::A([93, 184, 216, 34]));

        let calls = client.calls();
        assert_eq!(calls.len(), 4);
        assert_eq!(
            calls[0],
            (
                SocketAddr::new(IpAddr::V4(ROOT_SERVER_IPS[0]), ROOT_PORT),
                "example.com".to_string(),
                1,
            )
        );
        assert_eq!(
            calls[1],
            (
                SocketAddr::new(IpAddr::V4(ROOT_SERVER_IPS[0]), ROOT_PORT),
                "ns1.example.com".to_string(),
                1,
            )
        );
        assert_eq!(
            calls[2],
            (
                SocketAddr::new(IpAddr::V4(ROOT_SERVER_IPS[0]), ROOT_PORT),
                "ns1.example.com".to_string(),
                28,
            )
        );
        assert_eq!(calls[3].1, "example.com");
        assert_eq!(calls[3].2, 1);
        assert_ne!(
            calls[3].0,
            SocketAddr::new(IpAddr::V4(ROOT_SERVER_IPS[0]), ROOT_PORT)
        );
    }

    #[test]
    fn resolver_stops_after_referral_hop_limit() {
        let client = Rc::new(ScriptedClient::new());
        let resolver = Resolver::with_config(
            client.clone(),
            vec![SocketAddr::new(IpAddr::V4(ROOT_SERVER_IPS[0]), ROOT_PORT)],
            1,
            8,
        );

        let query = query_message(0x1234, "example", "com", 1);
        let response = resolver.resolve(query);

        assert_eq!(
            response.flags().response_code(),
            ResponseCode::ServerFailure
        );
        assert_eq!(client.calls().len(), 3);
    }

    #[test]
    fn resolver_does_not_exceed_nested_lookup_limit() {
        let client = Rc::new(ScriptedClient::new());
        let resolver = Resolver::with_config(
            client.clone(),
            vec![SocketAddr::new(IpAddr::V4(ROOT_SERVER_IPS[0]), ROOT_PORT)],
            8,
            0,
        );

        let query = query_message(0x1234, "example", "com", 1);
        let response = resolver.resolve(query);

        assert_eq!(
            response.flags().response_code(),
            ResponseCode::ServerFailure
        );
        assert_eq!(client.calls().len(), 1);
    }

    #[test]
    fn resolver_preserves_terminal_error_response_code() {
        let client = Rc::new(ScriptedClient::new());
        let resolver = Resolver::with_config(
            client,
            vec![SocketAddr::new(IpAddr::V4(ROOT_SERVER_IPS[0]), ROOT_PORT)],
            4,
            4,
        );

        let query = query_message(0x1234, "missing", "example", 1);
        let response = resolver.resolve(query);

        assert_eq!(response.flags().response_code(), ResponseCode::NameError);
    }

    #[test]
    fn resolver_tries_another_server_after_exchange_failure() {
        let first_server = SocketAddr::new(IpAddr::V4(ROOT_SERVER_IPS[0]), ROOT_PORT);
        let second_server = SocketAddr::new(IpAddr::V4(ROOT_SERVER_IPS[1]), ROOT_PORT);
        let client = Rc::new(FailoverClient::new(Some(second_server)));
        let resolver =
            Resolver::with_config(client.clone(), vec![first_server, second_server], 4, 4);

        let query = query_message(0x1234, "example", "com", 1);
        let response = resolver.resolve(query);

        assert_eq!(response.flags().response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
        assert_eq!(client.calls(), vec![first_server, second_server]);
    }

    #[test]
    fn resolver_returns_server_failure_when_all_exchanges_fail() {
        let first_server = SocketAddr::new(IpAddr::V4(ROOT_SERVER_IPS[0]), ROOT_PORT);
        let second_server = SocketAddr::new(IpAddr::V4(ROOT_SERVER_IPS[1]), ROOT_PORT);
        let client = Rc::new(FailoverClient::new(None));
        let resolver =
            Resolver::with_config(client.clone(), vec![first_server, second_server], 4, 4);

        let query = query_message(0x1234, "example", "com", 1);
        let response = resolver.resolve(query);

        assert_eq!(
            response.flags().response_code(),
            ResponseCode::ServerFailure
        );
        assert_eq!(client.calls(), vec![first_server, second_server]);
    }

    #[test]
    fn resolve_packet_round_trip_for_malformed_input() {
        let packet: OwnedPacket = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 7, b'e', b'x',
            b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01, 3, b'w',
            b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00,
            0x01, 0x00, 0x01,
        ];

        let response = resolve(packet.as_slice()).unwrap();
        let message = Message::try_from(response.as_slice()).unwrap();

        assert_eq!(message.questions().len(), 2);
        assert_eq!(message.flags().response_code(), ResponseCode::FormatError);
    }

    fn query_message(id: u16, label1: &str, label2: &str, record_type: u16) -> Message {
        Message::new_query(
            id,
            Question {
                name: Name::from_labels(&[label1, label2]),
                record_type,
                class: 1,
            },
        )
    }

    fn response_from(request: &Message, answers: Vec<Record>, authorities: Vec<Record>) -> Message {
        Message::new(
            Header::new(request.id(), Flags::from(0x8180)),
            request.questions().to_vec(),
            answers,
            authorities,
            vec![],
        )
    }

    fn referral_response(request: &Message) -> Message {
        response_from(
            request,
            vec![],
            vec![Record::new(
                Name::from_labels(&["example", "com"]),
                1,
                300,
                Data::Ns(Name::from_labels(&["ns1", "example", "com"])),
            )],
        )
    }

    fn nameserver_a_response(request: &Message) -> Message {
        response_from(
            request,
            vec![Record::new(
                Name::from_labels(&["ns1", "example", "com"]),
                1,
                300,
                Data::A([192, 0, 2, 1]),
            )],
            vec![],
        )
    }

    fn nameserver_aaaa_response(request: &Message) -> Message {
        response_from(
            request,
            vec![Record::new(
                Name::from_labels(&["ns1", "example", "com"]),
                1,
                300,
                Data::Aaaa([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            )],
            vec![],
        )
    }

    fn final_answer_response(request: &Message) -> Message {
        response_from(
            request,
            vec![Record::new(
                Name::from_labels(&["example", "com"]),
                1,
                300,
                Data::A([93, 184, 216, 34]),
            )],
            vec![],
        )
    }

    fn name_error_response(request: &Message) -> Message {
        response_from(request, vec![], vec![]).with_response_code(ResponseCode::NameError)
    }

    struct ScriptedClient {
        calls: RefCell<Vec<(SocketAddr, String, u16)>>,
    }

    struct FailoverClient {
        calls: RefCell<Vec<SocketAddr>>,
        successful_server: Option<SocketAddr>,
    }

    #[derive(Debug)]
    enum ScriptedClientError {
        MissingQuestion,
        UnexpectedRequest,
    }

    impl ScriptedClient {
        fn new() -> Self {
            Self {
                calls: RefCell::new(vec![]),
            }
        }

        fn calls(&self) -> Vec<(SocketAddr, String, u16)> {
            self.calls.borrow().clone()
        }
    }

    impl FailoverClient {
        fn new(successful_server: Option<SocketAddr>) -> Self {
            Self {
                calls: RefCell::new(vec![]),
                successful_server,
            }
        }

        fn calls(&self) -> Vec<SocketAddr> {
            self.calls.borrow().clone()
        }
    }

    impl DnsClient for Rc<ScriptedClient> {
        type Error = ScriptedClientError;

        fn exchange(&self, server: SocketAddr, request: &Message) -> Result<Message, Self::Error> {
            let question = request
                .questions()
                .first()
                .ok_or(ScriptedClientError::MissingQuestion)?;
            let name = question.name.to_string();
            self.calls
                .borrow_mut()
                .push((server, name.clone(), question.record_type));

            match (server.ip(), name.as_str(), question.record_type) {
                (IpAddr::V4(ip), "example.com", 1) if ip == ROOT_SERVER_IPS[0] => {
                    Ok(referral_response(request))
                }
                (IpAddr::V4(ip), "missing.example", 1) if ip == ROOT_SERVER_IPS[0] => {
                    Ok(name_error_response(request))
                }
                (IpAddr::V4(ip), "ns1.example.com", 1) if ip == ROOT_SERVER_IPS[0] => {
                    Ok(nameserver_a_response(request))
                }
                (IpAddr::V4(ip), "ns1.example.com", 28) if ip == ROOT_SERVER_IPS[0] => {
                    Ok(nameserver_aaaa_response(request))
                }
                (IpAddr::V4(ip), "example.com", 1) if ip != ROOT_SERVER_IPS[0] => {
                    Ok(final_answer_response(request))
                }
                (IpAddr::V6(_), "example.com", 1) => Ok(final_answer_response(request)),
                _ => Err(ScriptedClientError::UnexpectedRequest),
            }
        }
    }

    impl DnsClient for Rc<FailoverClient> {
        type Error = ScriptedClientError;

        fn exchange(&self, server: SocketAddr, request: &Message) -> Result<Message, Self::Error> {
            self.calls.borrow_mut().push(server);

            if self.successful_server == Some(server) {
                Ok(final_answer_response(request))
            } else {
                Err(ScriptedClientError::UnexpectedRequest)
            }
        }
    }
}
