use std::net::Ipv4Addr;

pub const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
pub const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
pub const IF_TYPE_IEEE80211: u32 = 71;
pub const IF_TYPE_TUNNEL: u32 = 131;

const VIRTUAL_NIC_KEYWORDS: &[&str] = &[
    "vethernet",
    "hyper-v",
    "wsl",
    "virtualbox",
    "vmware",
    "virtual",
    "tailscale",
    "wireguard",
    "zerotier",
    "hamachi",
    "tap-windows",
    "wintun",
    "vpn",
    "bluetooth",
    "npcap",
    "docker",
    "teredo",
    "isatap",
    "loopback",
    "pseudo",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicCandidate {
    pub if_index: u32,
    pub friendly_name: String,
    pub description: String,
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub broadcast: Ipv4Addr,
    pub if_type: u32,
    pub has_ipv4_gateway: bool,
    pub is_virtual: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicInfo {
    pub friendly_name: String,
    pub description: String,
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub broadcast: Ipv4Addr,
    pub is_virtual: bool,
}

impl NicCandidate {
    pub fn to_info(&self) -> NicInfo {
        NicInfo {
            friendly_name: self.friendly_name.clone(),
            description: self.description.clone(),
            ip: self.ip,
            prefix_len: self.prefix_len,
            broadcast: self.broadcast,
            is_virtual: self.is_virtual,
        }
    }
}

pub fn compute_directed_broadcast(ip: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 || prefix_len >= 32 {
        return Ipv4Addr::BROADCAST;
    }
    let mask = !0u32 << (32 - u32::from(prefix_len));
    Ipv4Addr::from(u32::from(ip) | !mask)
}

fn is_cgnat_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

pub fn is_virtual_nic_candidate(
    friendly_name: &str,
    description: &str,
    if_type: u32,
    ip: Ipv4Addr,
) -> bool {
    if if_type == IF_TYPE_TUNNEL || is_cgnat_ipv4(ip) {
        return true;
    }
    let friendly_lower = friendly_name.to_ascii_lowercase();
    let desc_lower = description.to_ascii_lowercase();
    VIRTUAL_NIC_KEYWORDS
        .iter()
        .any(|kw| friendly_lower.contains(kw) || desc_lower.contains(kw))
}

fn is_usable_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() && !ip.is_multicast()
}

fn is_physical_lan_if_type(if_type: u32) -> bool {
    matches!(if_type, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211)
}

pub fn select_best_nic(
    candidates: &[NicCandidate],
    preferred_ip: Option<Ipv4Addr>,
    best_if_index: Option<u32>,
) -> Option<NicInfo> {
    let usable: Vec<&NicCandidate> = candidates
        .iter()
        .filter(|c| is_usable_ipv4(c.ip) && c.if_type != IF_TYPE_SOFTWARE_LOOPBACK)
        .collect();

    if let Some(pref) = preferred_ip
        && let Some(matched) = usable.iter().find(|c| c.ip == pref)
    {
        return Some(matched.to_info());
    }

    usable
        .into_iter()
        .max_by(|a, b| {
            let key_a = (
                !a.is_virtual,
                best_if_index == Some(a.if_index),
                a.has_ipv4_gateway,
                is_physical_lan_if_type(a.if_type),
                a.ip.is_private(),
            );
            let key_b = (
                !b.is_virtual,
                best_if_index == Some(b.if_index),
                b.has_ipv4_gateway,
                is_physical_lan_if_type(b.if_type),
                b.ip.is_private(),
            );
            key_a
                .cmp(&key_b)
                .then_with(|| b.friendly_name.cmp(&a.friendly_name))
                .then_with(|| b.ip.cmp(&a.ip))
        })
        .map(NicCandidate::to_info)
}

#[cfg(windows)]
mod win_impl {
    use std::mem::size_of;
    use std::net::Ipv4Addr;
    use std::ptr;

    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_GATEWAYS, GetAdaptersAddresses, GetBestInterface, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN, SOCKET_ADDRESS};

    use super::{
        IF_TYPE_SOFTWARE_LOOPBACK, NicCandidate, compute_directed_broadcast,
        is_virtual_nic_candidate,
    };

    const MAX_PWSTR_LEN: usize = 1024;

    unsafe fn pwstr_to_string(ptr_w: *const u16) -> String {
        if ptr_w.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while len < MAX_PWSTR_LEN {
            let ch = unsafe { *ptr_w.add(len) };
            if ch == 0 {
                break;
            }
            len += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(ptr_w, len) };
        String::from_utf16_lossy(slice)
    }

    unsafe fn extract_ipv4_from_socket_address(sa: &SOCKET_ADDRESS) -> Option<Ipv4Addr> {
        if sa.lpSockaddr.is_null() || sa.iSockaddrLength < size_of::<SOCKADDR_IN>() as i32 {
            return None;
        }
        let family = unsafe { (*sa.lpSockaddr).sa_family };
        if family != AF_INET {
            return None;
        }
        let sin = unsafe { *(sa.lpSockaddr as *const SOCKADDR_IN) };
        let raw_addr = unsafe { sin.sin_addr.S_un.S_addr };
        Some(Ipv4Addr::from(raw_addr.to_ne_bytes()))
    }

    fn fetch_adapter_buffer() -> Result<Vec<u64>, u32> {
        let mut buf_size: u32 = 16_384;
        let mut buffer: Vec<u64> = vec![0; (buf_size as usize).div_ceil(8)];
        let mut last_err = NO_ERROR;

        for _ in 0..3 {
            let ret = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_INET),
                    GAA_FLAG_INCLUDE_GATEWAYS,
                    ptr::null_mut(),
                    buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                    &mut buf_size,
                )
            };
            if ret == NO_ERROR {
                return Ok(buffer);
            }
            last_err = ret;
            if ret != ERROR_BUFFER_OVERFLOW {
                break;
            }
            buffer.resize((buf_size as usize).div_ceil(8), 0);
        }
        Err(last_err)
    }

    pub fn get_best_ipv4_interface_index() -> Option<u32> {
        let probe_dest = u32::from_ne_bytes([8, 8, 8, 8]);
        let mut best_index: u32 = 0;
        let ret = unsafe { GetBestInterface(probe_dest, &mut best_index) };
        (ret == NO_ERROR).then_some(best_index)
    }

    pub fn discover_ipv4_nics() -> Vec<NicCandidate> {
        let Ok(buffer) = fetch_adapter_buffer() else {
            return Vec::new();
        };

        let mut candidates = Vec::new();
        let mut current = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

        while !current.is_null() {
            let adapter = unsafe { &*current };
            if adapter.OperStatus == IfOperStatusUp && adapter.IfType != IF_TYPE_SOFTWARE_LOOPBACK {
                let if_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
                let friendly_name = unsafe { pwstr_to_string(adapter.FriendlyName) };
                let description = unsafe { pwstr_to_string(adapter.Description) };

                let mut has_ipv4_gateway = false;
                let mut gw_ptr = adapter.FirstGatewayAddress;
                while !gw_ptr.is_null() {
                    let gw = unsafe { &*gw_ptr };
                    if let Some(ip) = unsafe { extract_ipv4_from_socket_address(&gw.Address) }
                        && !ip.is_unspecified()
                    {
                        has_ipv4_gateway = true;
                        break;
                    }
                    gw_ptr = gw.Next;
                }

                let mut uni_ptr = adapter.FirstUnicastAddress;
                while !uni_ptr.is_null() {
                    let uni = unsafe { &*uni_ptr };
                    if let Some(ip) = unsafe { extract_ipv4_from_socket_address(&uni.Address) }
                        && super::is_usable_ipv4(ip)
                    {
                        let prefix_len = uni.OnLinkPrefixLength;
                        let broadcast = compute_directed_broadcast(ip, prefix_len);
                        let is_virtual = is_virtual_nic_candidate(
                            &friendly_name,
                            &description,
                            adapter.IfType,
                            ip,
                        );
                        candidates.push(NicCandidate {
                            if_index,
                            friendly_name: friendly_name.clone(),
                            description: description.clone(),
                            ip,
                            prefix_len,
                            broadcast,
                            if_type: adapter.IfType,
                            has_ipv4_gateway,
                            is_virtual,
                        });
                    }
                    uni_ptr = uni.Next;
                }
            }
            current = adapter.Next;
        }

        candidates
    }
}

#[cfg(windows)]
pub fn discover_ipv4_nics() -> Vec<NicCandidate> {
    win_impl::discover_ipv4_nics()
}

#[cfg(windows)]
pub fn get_best_ipv4_interface_index() -> Option<u32> {
    win_impl::get_best_ipv4_interface_index()
}

#[cfg(not(windows))]
pub fn discover_ipv4_nics() -> Vec<NicCandidate> {
    Vec::new()
}

#[cfg(not(windows))]
pub fn get_best_ipv4_interface_index() -> Option<u32> {
    None
}

pub fn resolve_active_nic(preferred_ip: Option<Ipv4Addr>) -> Option<NicInfo> {
    let candidates = discover_ipv4_nics();
    let best_idx = get_best_ipv4_interface_index();
    select_best_nic(&candidates, preferred_ip, best_idx)
}

pub fn resolve_active_nic_from_str(preferred_nic_ip: Option<&str>) -> Option<NicInfo> {
    let parsed = preferred_nic_ip.and_then(|s| s.trim().parse::<Ipv4Addr>().ok());
    resolve_active_nic(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_directed_broadcast_correctly() {
        assert_eq!(
            compute_directed_broadcast(Ipv4Addr::new(192, 168, 10, 6), 24),
            Ipv4Addr::new(192, 168, 10, 255)
        );
        assert_eq!(
            compute_directed_broadcast(Ipv4Addr::new(172, 16, 4, 12), 16),
            Ipv4Addr::new(172, 16, 255, 255)
        );
        assert_eq!(
            compute_directed_broadcast(Ipv4Addr::new(192, 168, 1, 130), 25),
            Ipv4Addr::new(192, 168, 1, 255)
        );
        assert_eq!(
            compute_directed_broadcast(Ipv4Addr::new(10, 0, 0, 1), 32),
            Ipv4Addr::BROADCAST
        );
        assert_eq!(
            compute_directed_broadcast(Ipv4Addr::new(10, 0, 0, 1), 0),
            Ipv4Addr::BROADCAST
        );
    }

    #[test]
    fn filters_virtual_nics_and_prefers_physical_adapter() {
        let candidates = vec![
            NicCandidate {
                if_index: 20,
                friendly_name: "vEthernet (WSL (Hyper-V firewall))".to_string(),
                description: "Hyper-V Virtual Ethernet Adapter".to_string(),
                ip: Ipv4Addr::new(172, 25, 160, 1),
                prefix_len: 20,
                broadcast: compute_directed_broadcast(Ipv4Addr::new(172, 25, 160, 1), 20),
                if_type: IF_TYPE_ETHERNET_CSMACD,
                has_ipv4_gateway: false,
                is_virtual: is_virtual_nic_candidate(
                    "vEthernet (WSL (Hyper-V firewall))",
                    "Hyper-V Virtual Ethernet Adapter",
                    IF_TYPE_ETHERNET_CSMACD,
                    Ipv4Addr::new(172, 25, 160, 1),
                ),
            },
            NicCandidate {
                if_index: 21,
                friendly_name: "Tailscale".to_string(),
                description: "Tailscale Tunnel".to_string(),
                ip: Ipv4Addr::new(100, 101, 102, 103),
                prefix_len: 32,
                broadcast: Ipv4Addr::BROADCAST,
                if_type: IF_TYPE_TUNNEL,
                has_ipv4_gateway: false,
                is_virtual: is_virtual_nic_candidate(
                    "Tailscale",
                    "Tailscale Tunnel",
                    IF_TYPE_TUNNEL,
                    Ipv4Addr::new(100, 101, 102, 103),
                ),
            },
            NicCandidate {
                if_index: 11,
                friendly_name: "イーサネット".to_string(),
                description: "Intel(R) Ethernet Connection".to_string(),
                ip: Ipv4Addr::new(192, 168, 10, 6),
                prefix_len: 24,
                broadcast: compute_directed_broadcast(Ipv4Addr::new(192, 168, 10, 6), 24),
                if_type: IF_TYPE_ETHERNET_CSMACD,
                has_ipv4_gateway: true,
                is_virtual: is_virtual_nic_candidate(
                    "イーサネット",
                    "Intel(R) Ethernet Connection",
                    IF_TYPE_ETHERNET_CSMACD,
                    Ipv4Addr::new(192, 168, 10, 6),
                ),
            },
        ];

        assert!(candidates[0].is_virtual);
        assert!(candidates[1].is_virtual);
        assert!(!candidates[2].is_virtual);

        let selected = select_best_nic(&candidates, None, Some(11)).unwrap();
        assert_eq!(selected.ip, Ipv4Addr::new(192, 168, 10, 6));
        assert_eq!(selected.broadcast, Ipv4Addr::new(192, 168, 10, 255));
        assert!(!selected.is_virtual);

        // 明示指定時は指定 IP が優先される
        let preferred =
            select_best_nic(&candidates, Some(Ipv4Addr::new(172, 25, 160, 1)), Some(11)).unwrap();
        assert_eq!(preferred.ip, Ipv4Addr::new(172, 25, 160, 1));
    }

    #[test]
    fn real_machine_nic_discovery_selects_physical_nic_and_broadcast() {
        let all = discover_ipv4_nics();
        println!("detected_nic_count={}", all.len());
        for nic in &all {
            println!(
                "candidate: idx={} name={} desc={} prefix={} virtual={} gw={} bcast={}",
                nic.if_index,
                nic.friendly_name,
                nic.description,
                nic.prefix_len,
                nic.is_virtual,
                nic.has_ipv4_gateway,
                nic.broadcast
            );
        }

        let active = resolve_active_nic(None);
        if !all.is_empty() {
            let info = active.expect("active NIC should be selected when candidates exist");
            assert!(is_usable_ipv4(info.ip));
            assert_ne!(info.broadcast, Ipv4Addr::UNSPECIFIED);
            if all.iter().any(|c| !c.is_virtual) {
                assert!(!info.is_virtual);
            }
            println!(
                "selected_active_nic: name={} desc={} prefix={} virtual={}",
                info.friendly_name, info.description, info.prefix_len, info.is_virtual
            );
        }
    }
}
