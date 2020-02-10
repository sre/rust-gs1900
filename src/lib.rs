// © 2020 Sebastian Reichel
// SPDX-License-Identifier: ISC

#![crate_type = "lib"]
#![crate_name = "gs1900"]

//! The `gs1900` crate provides access to Zyxel's GS1900
//! switch series from rust.

#[macro_use] extern crate lazy_static;
extern crate ssh2;
extern crate regex;

#[cfg(feature = "web")]
extern crate reqwest;
#[cfg(feature = "web")]
extern crate random_integer;

#[macro_use]
extern crate bitflags;

use std::io::prelude::*;
use std::net::{TcpStream};
use ssh2::Session;
use regex::Regex;
use std::time::SystemTime;

/// MAC Address
pub struct MacAddress {
    pub bytes: [u8; 6],
}

impl Default for MacAddress {
    fn default () -> MacAddress {
        MacAddress
        {
            bytes: [0; 6],
        }
    }
}

impl std::str::FromStr for MacAddress {
    type Err = std::io::Error;

    fn from_str (s: &str) -> Result<MacAddress, std::io::Error> {
        let split: std::vec::Vec<&str> = s.split(":").collect();
        let mut bytes: [u8; 6] = [0; 6];
        let mut pos: usize = 0;
        if split.len() != 6 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Received invalid data"))
        }
        for strbyte in split {
            if strbyte.len() != 2 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Received invalid data"))
            }
            bytes[pos] = match u8::from_str_radix(strbyte, 16) {
                Ok(x) => x,
                Err(_e) => { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Received invalid data")) },
            };
            pos+=1;
        }
        Ok(MacAddress { bytes: bytes })
    }
}

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3], self.bytes[4], self.bytes[5])
    }
}

impl std::fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MacAddress(\"{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\")", self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3], self.bytes[4], self.bytes[5])
    }
}

/// IPv4 address
pub struct IPv4Address {
    pub bytes: [u8; 4],
}

impl Default for IPv4Address {
    fn default () -> IPv4Address {
        IPv4Address
        {
            bytes: [0; 4],
        }
    }
}

impl std::str::FromStr for IPv4Address {
    type Err = std::io::Error;

    fn from_str (s: &str) -> Result<IPv4Address, std::io::Error> {
        let split: std::vec::Vec<&str> = s.split(".").collect();
        let mut bytes: [u8; 4] = [0; 4];
        let mut pos: usize = 0;
        if split.len() != 4 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Received invalid data"))
        }
        for strbyte in split {
            if strbyte.len() == 0 || strbyte.len() > 3 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Received invalid data"))
            }
            bytes[pos] = match u8::from_str(strbyte) {
                Ok(x) => x,
                Err(_e) => { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Received invalid data")) },
            };
            pos+=1;
        }
        Ok(IPv4Address { bytes: bytes })
    }
}

impl std::fmt::Display for IPv4Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3])
    }
}

impl std::fmt::Debug for IPv4Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IPv4Address(\"{}.{}.{}.{}\")", self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3])
    }
}

/// Access to GS1900 switch
pub struct GS1900 {
    address: String,
    username: String,
    password: String,
    session: ssh2::Session,
    channel: ssh2::Channel,
    prompt: String,
}

#[derive(Debug)]
/// Basic Switch Information
pub struct BasicInfo {
    /// Configured System Name
    pub system_name: String,
    /// Configured System Location
    pub system_location: String,
    /// Configured System Contact
    pub system_contact: String,
    /// System MAC address
    pub mac_address: MacAddress,
    /// System IPv4 address
    pub ip_address: IPv4Address,
    /// System Subnet mask
    pub subnet_mask: IPv4Address,
    /// Boot version
    pub boot_version: String,
    /// Firmware version
    pub firmware_version: String,
    /// System object ID
    pub system_object_id: String,
    /// System uptime (in seconds)
    pub system_uptime: u64,
}

impl Default for BasicInfo {
    fn default () -> BasicInfo {
        BasicInfo
        {
            system_name: "".to_string(),
            system_location: "".to_string(),
            system_contact: "".to_string(),
            mac_address: MacAddress::default(),
            ip_address: IPv4Address::default(),
            subnet_mask: IPv4Address::default(),
            boot_version: "".to_string(),
            firmware_version: "".to_string(),
            system_object_id: "".to_string(),
            system_uptime: 0,
        }
    }
}

bitflags! {
    /// LLDP capability
    pub struct LLDPCap: u8 {
        const STATION   = 0b00001;
        const BRIDGE    = 0b00010;
        const WLAN      = 0b00100;
        const ROUTER    = 0b01000;
        const TELEPHONE = 0b10000;
    }
}

#[derive(Debug)]
/// LLDP neighbor information
pub struct LLDPNeighbor {
    /// Switch interface number
    pub port: u8,
    /// Remote device ID
    pub device_id: String,
    /// Remote port ID
    pub port_id: String,
    /// Remote system name
    pub system_name: String,
    /// Remote system capabilities
    pub caps: LLDPCap,
    /// TTL for the LLDP informations (in seconds)
    pub ttl: u32,
}

#[derive(Debug)]
/// Type of Entry in MAC address table
pub enum MacEntryType {
    Management,
    Dynamic,
    Static,
}

impl std::str::FromStr for MacEntryType {
    type Err = std::io::Error;

    fn from_str (s: &str) -> Result<MacEntryType, std::io::Error> {
        match s {
            "Management" => Ok(MacEntryType::Management),
            "Dynamic" => Ok(MacEntryType::Dynamic),
            "Static" => Ok(MacEntryType::Static),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Failed to parse '{}'", s))),
        }
    }
}

#[derive(Debug)]
/// MAC address table entry
pub struct MacEntry {
    /// VLAN ID
    pub vlan_id: u8,
    /// MAC address
    pub mac_address: MacAddress,
    /// Type of entry (dynamic or static)
    pub entry_type: MacEntryType,
    /// Interfaces with the MAC address
    pub ports: String,
}

#[derive(Debug)]
/// Status for SFP information
pub enum SFPStatus {
    NotAvailable,
    OK,
    Warning,
    Error,
}

impl std::str::FromStr for SFPStatus {
    type Err = std::io::Error;

    fn from_str (s: &str) -> Result<SFPStatus, std::io::Error> {
        match s {
            "N/A" => Ok(SFPStatus::NotAvailable),
            "OK" => Ok(SFPStatus::OK),
            "W" => Ok(SFPStatus::Warning),
            "E" => Ok(SFPStatus::Error),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Failed to parse '{}'", s))),
        }
    }
}

#[derive(Debug)]
/// SFP diagnostic data
pub struct FiberInfo {
    /// Port Number
    pub port: u8,
    /// Temperature (in milli Celsius)
    pub temperature: i32,
    /// Temperature status
    pub temperature_status: SFPStatus,
    /// Voltage (in mV)
    pub voltage: i32,
    /// Voltage status
    pub voltage_status: SFPStatus,
    /// Current (in uA)
    pub current: i32,
    /// Current status
    pub current_status: SFPStatus,
    /// Output Power (in uW)
    pub output_power: i32,
    /// Output Power status
    pub output_power_status: SFPStatus,
    /// Input Power (in uW)
    pub input_power: i32,
    /// Input Power status
    pub input_power_status: SFPStatus,
    /// SFP module is present
    pub present: bool,
    /// Link detected?
    pub link: bool,
}

/// PoE classification (0-4)
#[derive(Debug)]
pub enum PoEClass {
    /// 0.44 - 12.94 Watts
    Class0,
    /// 0.44 - 3.84 Watts
    Class1,
    /// 3.84 - 6.49 Watts
    Class2,
    /// 6.49 - 12.95 Watts
    Class3,
    /// 12.95 - 25.50 Watts (802.3at)
    Class4,
}

impl std::str::FromStr for PoEClass {
    type Err = std::io::Error;

    fn from_str (s: &str) -> Result<PoEClass, std::io::Error> {
        match s {
            "class0" => Ok(PoEClass::Class0),
            "class1" => Ok(PoEClass::Class1),
            "class2" => Ok(PoEClass::Class2),
            "class3" => Ok(PoEClass::Class3),
            "class4" => Ok(PoEClass::Class4),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Could not parse {}", s))),
        }
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
/// PoE power mode (802.3af, 802.3at, ...)
pub enum PoEPowerMode {
    IEEE_802_3af,
    Legacy,
    Pre_802_3at,
    IEEE_802_3at,
}

#[derive(Debug)]
/// PoE port priority (Low-Critical)
pub enum PoEPriority {
    Low,
    Medium,
    High,
    Critical,
}

impl std::str::FromStr for PoEPriority {
    type Err = std::io::Error;

    fn from_str (s: &str) -> Result<PoEPriority, std::io::Error> {
        match s {
            "low" => Ok(PoEPriority::Low),
            "medium" => Ok(PoEPriority::Medium),
            "high" => Ok(PoEPriority::High),
            "critical" => Ok(PoEPriority::Critical),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Could not parse {}", s))),
        }
    }
}

#[derive(Debug)]
/// PoE power limitation mode
pub enum PoELimitMode {
    /// Limit power based on device classification
    Classification,
    /// Limit power based on manual configuration
    User,
}

#[derive(Debug)]
/// PoE port status (On, Off, Searching)
pub enum PoEStatus {
    Off,
    Searching,
    On,
}

impl std::str::FromStr for PoEStatus {
    type Err = std::io::Error;

    fn from_str (s: &str) -> Result<PoEStatus, std::io::Error> {
        match s {
            "off" => Ok(PoEStatus::Off),
            "searching" => Ok(PoEStatus::Searching),
            "on" => Ok(PoEStatus::On),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Could not parse {}", s))),
        }
    }
}

#[derive(Debug)]
/// PoE debug information
pub struct PoEDebug {
    /// Interface number
    pub port: u8,
    /// PoE status
    pub status: PoEStatus,
    /// PoE port priority
    pub priority: PoEPriority,
    /// PoE classification
    pub class: PoEClass,
    /// PoE status reason
    pub reason: String,
}

#[derive(Debug)]
/// PoE power allocation mode
pub enum PoEMode {
    /// Allocate power based on device classification
    Classification,
    /// Allocate power based on device consumption
    Consumption,
}

impl std::str::FromStr for PoEMode {
    type Err = std::io::Error;

    fn from_str (s: &str) -> Result<PoEMode, std::io::Error> {
        match s {
            "Class limit mode" => Ok(PoEMode::Classification),
            "Port limit mode" => Ok(PoEMode::Consumption),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Could not parse {}", s))),
        }
    }
}

#[derive(Debug)]
/// PoE power-up sequence
pub enum PoEPowerUpSequence {
    /// Enable PoE ports one after each other
    Staggered,
    /// Enable all PoE ports simultaneously
    Simultaneous,
}

impl std::str::FromStr for PoEPowerUpSequence {
    type Err = std::io::Error;

    fn from_str (s: &str) -> Result<PoEPowerUpSequence, std::io::Error> {
        match s {
            "Staggered" => Ok(PoEPowerUpSequence::Staggered),
            "Simultaneous" => Ok(PoEPowerUpSequence::Simultaneous),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Could not parse {}", s))),
        }
    }
}

#[derive(Debug)]
/// PoE configuration
pub struct PoEConfig {
    /// PoE Management Mode (classification vs consumption)
    pub management_mode: PoEMode,
    /// Pre-Allocation enabled?
    pub pre_allocation: bool,
    /// Power-Up sequence (staggered vs simultaneously)
    pub power_up_sequence: PoEPowerUpSequence,
}

impl Default for PoEConfig {
    fn default () -> PoEConfig {
        PoEConfig
        {
            management_mode: PoEMode::Classification,
            pre_allocation: true,
            power_up_sequence: PoEPowerUpSequence::Staggered,
        }
    }
}

#[derive(Debug)]
/// PoE power-supply information
pub struct PoESupply {
    /// Power Supply unit (usually 0)
    pub unit: u8,
    /// Power Supply status
    pub power: String,
    /// Power Supply status
    pub status: String,
    /// Nominal Power of the power-supply in Watts
    pub nominal_power: u32,
    /// Allocated Power of the power-supply in Watts
    pub allocated_power: u32,
    /// Consumed Power of the power-supply in Watts
    pub consumed_power: u32,
    /// Available Power of the power-supply in Watts
    pub available_power: u32,
}

#[derive(Debug)]
/// PoE port information
pub struct PoEPort {
    /// port number
    pub port: u8,
    /// max. power limit (mW)
    pub power_limit: i32,
    /// admin power limit (mW)
    pub admin_power_limit: i32,
    /// power (mW)
    pub power: i32,
    /// voltage (mV)
    pub voltage: i32,
    /// current (mA)
    pub current: i32,
}

#[derive(Debug, Copy, Clone)]
/// Cable pair status
pub enum CablePairState {
    /// Connected to a running device
    Normal,
    /// Not connected to anything
    Open,
    /// Connected to a power-off device
    LineDriver,
    /// Cable has bad quality (impedance is not 70-130 Ohm)
    ImpedanceMis,
}

impl std::str::FromStr for CablePairState {
    type Err = std::io::Error;

    fn from_str (s: &str) -> Result<CablePairState, std::io::Error> {
        match s {
            "Normal" => Ok(CablePairState::Normal),
            "Open" => Ok(CablePairState::Open),
            "LineDriver" => Ok(CablePairState::LineDriver),
            "ImpedanceMis" => Ok(CablePairState::ImpedanceMis),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Could not parse {}", s))),
        }
    }
}

#[derive(Debug, Copy, Clone)]
/// Cable diagnostic information for one pair
pub struct CablePairStatus {
    /// pair (A,B,C,D)
    pub pair: char,
    /// length in cm
    pub length: u32,
    /// pair status
    pub status: CablePairState,
}

#[derive(Debug, Copy, Clone)]
/// Port speed information
pub struct PortSpeed {
    /// Port speed is auto-negotiated
    pub auto: bool,
    /// negotiated speed in MBit/s
    pub speed: u32,
}

#[derive(Debug, Copy, Clone)]
/// Port duplex information
pub enum PortDuplex {
    Auto,
    Full,
    Half,
}

impl std::str::FromStr for PortDuplex {
    type Err = std::io::Error;

    fn from_str (s: &str) -> Result<PortDuplex, std::io::Error> {
        match s {
            "Auto" => Ok(PortDuplex::Auto),
            "auto" => Ok(PortDuplex::Auto),
            "Full" => Ok(PortDuplex::Full),
            "full" => Ok(PortDuplex::Full),
            "a-full" => Ok(PortDuplex::Full),
            "Half" => Ok(PortDuplex::Half),
            "half" => Ok(PortDuplex::Half),
            "a-half" => Ok(PortDuplex::Half),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Could not parse {}", s))),
        }
    }
}

impl std::str::FromStr for PortSpeed {
    type Err = std::io::Error;

    fn from_str (s: &str) -> Result<PortSpeed, std::io::Error> {
        match s {
            "auto" => Ok(PortSpeed { auto: true, speed: 0 }),
            "Auto" => Ok(PortSpeed { auto: true, speed: 0 }),
            "a-1000M" => Ok(PortSpeed { auto: true, speed: 1000 }),
            "1000M" => Ok(PortSpeed { auto: false, speed: 1000 }),
            "1000Mb" => Ok(PortSpeed { auto: false, speed: 1000 }),
            "1000Mb/s" => Ok(PortSpeed { auto: false, speed: 1000 }),
            "a-100M" => Ok(PortSpeed { auto: true, speed: 100 }),
            "100M" => Ok(PortSpeed { auto: false, speed: 100 }),
            "100Mb" => Ok(PortSpeed { auto: false, speed: 100 }),
            "100Mb/s" => Ok(PortSpeed { auto: false, speed: 100 }),
            "a-10M" => Ok(PortSpeed { auto: true, speed: 10 }),
            "10M" => Ok(PortSpeed { auto: false, speed: 10 }),
            "10Mb" => Ok(PortSpeed { auto: false, speed: 10 }),
            "10Mb/s" => Ok(PortSpeed { auto: false, speed: 10 }),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Could not parse {}", s))),
        }
    }
}

#[derive(Debug, Copy, Clone)]
/// Cable diagnostic information
pub struct CableDiagnosis {
    /// port number
    pub port: u8,
    /// port speed
    pub speed: PortSpeed,
    /// information about cable pairs
    pub pair_info: [CablePairStatus; 4],
}

impl Default for CableDiagnosis {
    fn default () -> CableDiagnosis {
        CableDiagnosis
        {
            port: 0,
            speed: PortSpeed { auto: false, speed: 0 },
            pair_info: [
                CablePairStatus {pair: 'A', length: 0, status: CablePairState::Normal},
                CablePairStatus {pair: 'B', length: 0, status: CablePairState::Normal},
                CablePairStatus {pair: 'C', length: 0, status: CablePairState::Normal},
                CablePairStatus {pair: 'D', length: 0, status: CablePairState::Normal},
            ],
        }
    }
}

#[derive(Debug, Copy, Clone)]
/// Media Type (Copper, Fiber)
pub enum MediaType {
    /// RJ45 port (copper)
    Copper,
    /// SFP port (fiber)
    Fiber,
}

impl std::str::FromStr for MediaType {
    type Err = std::io::Error;

    fn from_str (s: &str) -> Result<MediaType, std::io::Error> {
        match s {
            "Copper" => Ok(MediaType::Copper),
            "Fiber" => Ok(MediaType::Fiber),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Could not parse {}", s))),
        }
    }
}

#[derive(Debug)]
/// Port status
pub struct InterfaceStatus {
    /// port number
    pub port: u8,
    /// port name
    pub name: String,
    /// link is up
    pub connected: bool,
    /// default VLAN ID
    pub vlan: u32,
    /// duplex configuration
    pub duplex: PortDuplex,
    /// speed configuration
    pub speed: PortSpeed,
    /// media type (copper, fiber)
    pub mediatype: MediaType,
}

#[derive(Debug, Copy, Clone)]
/// Port traffic statistics
pub struct InterfaceTrafficStatus {
    /// port number
    pub port: u8,
    /// interface is up?
    pub up: bool,
    /// duplex configuration
    pub duplex: PortDuplex,
    /// speed configuration
    pub speed: PortSpeed,
    /// media type (Fiber or Copper)
    pub media_type: MediaType,
    /// flow control
    pub flow_control: bool,
    /// received packets
    pub input_packets: u32,
    /// received bytes
    pub input_bytes: u32,
    /// received throttles
    pub input_throttles: u32,
    /// received broadcasts
    pub input_broadcasts: u32,
    /// received multicasts
    pub input_multicasts: u32,
    /// runts
    pub input_runts: u32,
    /// giants
    pub input_giants: u32,
    /// input errors
    pub input_errors: u32,
    /// input errors (CRC)
    pub input_crc: u32,
    /// input errors (frame)
    pub input_frame: u32,
    /// input errors (overrun)
    pub input_overrun: u32,
    /// input errors (ignored)
    pub input_ignored: u32,
    /// pause input
    pub input_pause: u32,
    /// input packets with dribble condition detected
    pub input_dribble: u32,
    /// output packets
    pub output_packets: u32,
    /// output bytes
    pub output_bytes: u32,
    /// output underrun
    pub output_underrun: u32,
    /// output errors
    pub output_errors: u32,
    /// output collisions
    pub output_collisions: u32,
    /// output interface resets
    pub output_interface_resets: u32,
    /// babbles
    pub output_babbles: u32,
    /// late collisions
    pub output_late_collisions: u32,
    /// deferred
    pub output_deferred: u32,
    /// paused
    pub output_paused: u32,
}

impl Default for InterfaceTrafficStatus {
    fn default () -> InterfaceTrafficStatus {
        InterfaceTrafficStatus
        {
            port: 0,
            up: false,
            duplex: PortDuplex::Auto,
            speed: PortSpeed { auto: false, speed: 0 },
            media_type: MediaType::Copper,
            flow_control: false,
            input_packets: 0,
            input_bytes: 0,
            input_throttles: 0,
            input_broadcasts: 0,
            input_multicasts: 0,
            input_runts: 0,
            input_giants: 0,
            input_errors: 0,
            input_crc: 0,
            input_frame: 0,
            input_overrun: 0,
            input_ignored: 0,
            input_pause: 0,
            input_dribble: 0,
            output_packets: 0,
            output_bytes: 0,
            output_underrun: 0,
            output_errors: 0,
            output_collisions: 0,
            output_interface_resets: 0,
            output_babbles: 0,
            output_late_collisions: 0,
            output_deferred: 0,
            output_paused: 0,
        }
    }
}

#[derive(Debug)]
/// VLAN type (static, dynamic)
pub enum VLANType {
    Default,
    Static,
    Dynamic,
}

#[derive(Debug)]
/// VLAN Information
pub struct VLANInfo {
    /// VLAN ID
    pub id: u32,
    /// VLAN name
    pub name: String,
    /// List of untagged ports in VLAN
    pub ports_untagged: String,
    /// List of tagged ports in VLAN
    pub ports_tagged: String,
    /// VLAN type
    pub vlan_type: VLANType,
}

impl std::str::FromStr for VLANType {
    type Err = std::io::Error;

    fn from_str (s: &str) -> Result<VLANType, std::io::Error> {
        match s {
            "Default" => Ok(VLANType::Default),
            "Static" => Ok(VLANType::Static),
            "Dynamic" => Ok(VLANType::Dynamic),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Could not parse {}", s))),
        }
    }
}

impl GS1900 {
    /// Access the device
    pub fn new(address: String, username: String, password: String) -> std::io::Result<GS1900> {
        let addr = format!("{}:22", address);
        let tcp = TcpStream::connect(addr)?;

        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;
        sess.userauth_password(username.as_str(), password.as_str())?;

        let mut chan = sess.channel_session()?;
        chan.shell()?;

        let mut clearbuffer = [0; 7];
        chan.read(&mut clearbuffer)?;

        if clearbuffer != [27, 91, 72, 27, 91, 74, 0] {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Received invalid data"));
        }

        let mut prompt = [0; 32];
        let len = chan.read(&mut prompt)?;

        Ok(GS1900 {address: address, username: username, password: password, session: sess, channel: chan, prompt: String::from_utf8_lossy(&prompt[0..len]).to_string()})
    }

    fn fetch_data(&mut self) -> std::io::Result<String> {
        self.session.set_timeout(1000);

        let mut data = String::new();
        loop {
            let mut buffer = [0; 100];
            let len = match self.channel.read(&mut buffer) {
                Ok(x) => x,
                Err(_e) => {
                    let lines: Vec<&str> = data.split("\n").collect();
                    let last = lines[lines.len()-1].trim();
                    if last == self.prompt.trim() {
                        return Ok(data);
                    } else if last == "--More--" {
                        self.channel.write(b" ")?;
                        continue;
                    } else {
                        eprintln!("data: {:?}", data.as_bytes());
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Received invalid data"));
                    }
                },
            };

            let append = String::from_utf8_lossy(&buffer[0..len]).to_string();

            data += &append;
        }
    }

    fn clean_data(&self, data: String) -> String {
        let tmp1 = data.replace(self.prompt.as_str(), "");
        let tmp2 = tmp1.replace("--More--\n", "");
        let tmp3 = tmp2.replace("--More--\x08\n", "");
        let tmp4 = tmp3.replace("\x1b[A\x1b[2K", "");
        return tmp4;
    }

    pub fn basic_info(&mut self) -> std::io::Result<BasicInfo> {
        self.channel.write(b"show info\n")?;
        let mut result: BasicInfo = BasicInfo::default();

        lazy_static! {
            static ref RE1: Regex = Regex::new(r"(\d+) days, (\d+) hours, (\d+) mins, (\d+) secs").unwrap();
        }

        let raw = self.fetch_data()?;
        let data = self.clean_data(raw);

        for line in data.split("\n") {
            if line.trim() == self.prompt.trim() {
                break;
            }

            let kv: Vec<&str> = line.split(" : ").collect();
            if kv.len() < 2 {
                continue;
            }

            let key = kv[0].trim();
            let val = kv[1].trim();

            match key {
                "System Name" => result.system_name = val.to_string(),
                "System Location" => result.system_location = val.to_string(),
                "System Contact" => result.system_contact = val.to_string(),
                "MAC Address" => result.mac_address = val.to_string().parse::<MacAddress>()?,
                "IP Address" => result.ip_address = val.to_string().parse::<IPv4Address>()?,
                "Subnet Mask" => result.subnet_mask = val.to_string().parse::<IPv4Address>()?,
                "Boot Version" => result.boot_version = val.to_string(),
                "Firmware Version" => result.firmware_version = val.to_string(),
                "System Object ID" => result.system_object_id = val.to_string(),
                "System Up Time" => {
                    for cap in RE1.captures_iter(line) {
                        /* use unwrap, since regex caps are guaranteed to be numbers only */
                        let days: u64 = cap[1].parse().unwrap();
                        let hours: u64 = cap[2].parse().unwrap();
                        let minutes: u64 = cap[3].parse().unwrap();
                        let secs: u64 = cap[4].parse().unwrap();
                        let timestamp: u64 = secs + minutes*60 + hours*3600 + days*86400;
                        result.system_uptime = timestamp;
                    }
                },
                _ => { return Err(std::io::Error::new(std::io::ErrorKind::Other, "Received invalid data")); },
            }
        }

        return Ok(result);
    }

    pub fn lldp_info(&mut self) -> std::io::Result<std::vec::Vec::<LLDPNeighbor>> {
        self.channel.write(b"show lldp neighbor\n")?;

        let mut result = std::vec::Vec::<LLDPNeighbor>::new();

        let raw = self.fetch_data()?;
        let data = self.clean_data(raw);

        for line in data.split("\n") {
            if line.trim() == self.prompt.trim() {
                break;
            }
            if line.trim() == "" {
                continue;
            }

            let kv: Vec<&str> = line.split("|").collect();
            if kv.len() < 6 {
                continue;
            }

            if kv[0].trim() == "Port" {
                continue;
            }

            let mut caps: LLDPCap = LLDPCap { bits: 0 };
            let capsstr = kv[4].trim().to_string();
            for cap in capsstr.split(", ") {
                match cap {
                    "Station Only" => caps.insert(LLDPCap::STATION),
                    "Bridge" => caps.insert(LLDPCap::BRIDGE),
                    "WLAN" => caps.insert(LLDPCap::WLAN),
                    "Router" => caps.insert(LLDPCap::ROUTER),
                    "Telephone" => caps.insert(LLDPCap::TELEPHONE),
                    _ => {return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Received invalid LLDP capability: {}", cap)))},
                }
            }

            let neighbor = LLDPNeighbor {
                port: kv[0].trim().parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?,
                device_id: kv[1].trim().to_string(),
                port_id: kv[2].trim().to_string(),
                system_name: kv[3].trim().to_string(),
                caps: caps,
                ttl: kv[5].trim().parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?,
            };

            result.push(neighbor);
        }

        return Ok(result);
    }

    fn parse_fiber_entry(&self, entry: String) -> std::io::Result<(i32, String)> {
        let splt: Vec<&str> = entry.split("  ").collect();
        let result_int: i32;
        let result_str: String;
        if splt.len() >= 2 {
            result_int = match splt[0].replace(".", "").parse() {
                Ok(x) => x,
                Err(_fail) => {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "Received invalid data"));
                },
            };
            result_str = splt[1].replace("(", "").replace(")", "");
        } else {
            result_int = 0;
            result_str = entry;
        }
        Ok((result_int*10, result_str))
    }

    pub fn fiber_info(&mut self) -> std::io::Result<()> {
        self.channel.write(b"show fiber-transceiver interfaces all\n")?;

        let raw = self.fetch_data()?;
        let data = self.clean_data(raw);

        for line in data.split("\n") {
            let e: Vec<&str> = line.split("|").collect();
            if e.len() < 8 {
                continue;
            }
            if e[0].trim() == "Port" || e[0].trim() == "" {
                continue;
            }

            let (temperature, temperature_status) = self.parse_fiber_entry(e[1].trim().to_string())?;
            let (voltage, voltage_status) = self.parse_fiber_entry(e[2].trim().to_string())?;
            let (current, current_status) = self.parse_fiber_entry(e[3].trim().to_string())?;
            let (out_pwr, out_pwr_status) = self.parse_fiber_entry(e[4].trim().to_string())?;
            let (in_pwr, in_pwr_status) = self.parse_fiber_entry(e[5].trim().to_string())?;

            let fi = FiberInfo {
                port: match e[0].trim().parse() {
                    Ok(x) => x,
                    Err(_fail) => {
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Received invalid data"));
                    },
                },
                temperature: temperature,
                temperature_status: temperature_status.parse()?,
                voltage: voltage,
                voltage_status: voltage_status.parse()?,
                current: current,
                current_status: current_status.parse()?,
                output_power: out_pwr,
                output_power_status: out_pwr_status.parse()?,
                input_power: in_pwr,
                input_power_status: in_pwr_status.parse()?,
                present: e[6].trim().to_string() == "Insert",
                link: e[7].trim().to_string() == "Normal",
            };
            println!("{:?}", fi);
        }

        return Ok(());
    }

    pub fn mac_table(&mut self) -> std::io::Result<std::vec::Vec::<MacEntry>> {
        self.channel.write(b"show mac address-table\n")?;
        let mut result = std::vec::Vec::<MacEntry>::new();

        let raw = self.fetch_data()?;
        let data = self.clean_data(raw);
        let lines: Vec<&str> = data.split("\n").collect();

        for line in lines {
            let e: Vec<&str> = line.split("|").collect();
            if e.len() < 4 {
                continue;
            }
            if e[0].trim() == "VID" {
                continue;
            }

            let mac = MacEntry {
                vlan_id: match e[0].trim().parse() {
                    Ok(x) => x,
                    Err(_fail) => {
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Received invalid data"));
                    },
                },
                mac_address: e[1].trim().to_string().parse()?,
                entry_type: e[2].trim().to_string().parse()?,
                ports: e[3].trim().to_string(),
            };

            result.push(mac);
        }

        return Ok(result);
    }

    pub fn mac_table_port(&mut self, port: u8) -> std::io::Result<std::vec::Vec::<MacEntry>> {
        self.channel.write(b"show mac address-table interfaces ")?;
        self.channel.write(format!("{}", port).as_bytes())?;
        self.channel.write(b"\n")?;
        let mut result = std::vec::Vec::<MacEntry>::new();

        let raw = self.fetch_data()?;
        let data = self.clean_data(raw);
        let lines: Vec<&str> = data.split("\n").collect();

        for line in lines {
            let e: Vec<&str> = line.split("|").collect();
            if e.len() < 4 {
                continue;
            }
            if e[0].trim() == "VID" {
                continue;
            }

            let mac = MacEntry {
                vlan_id: match e[0].trim().parse() {
                    Ok(x) => x,
                    Err(_fail) => {
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Received invalid data"));
                    },
                },
                mac_address: e[1].trim().to_string().parse()?,
                entry_type: e[2].trim().to_string().parse()?,
                ports: e[3].trim().to_string(),
            };

            result.push(mac);
        }

        return Ok(result);
    }


    pub fn lookup_mac_address(&mut self, address: MacAddress) -> std::io::Result<std::option::Option<MacEntry>> {
        self.channel.write(b"show mac address-table ")?;
        self.channel.write(format!("{}", address).as_bytes())?;
        self.channel.write(b"\n")?;

        let raw = self.fetch_data()?;
        let data = self.clean_data(raw);
        let lines: Vec<&str> = data.split("\n").collect();

        for line in lines {
            let e: Vec<&str> = line.split("|").collect();
            if e.len() < 4 {
                continue;
            }
            if e[0].trim() == "VID" {
                continue;
            }

            let mac = MacEntry {
                vlan_id: match e[0].trim().parse() {
                    Ok(x) => x,
                    Err(_fail) => {
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Received invalid data"));
                    },
                },
                mac_address: e[1].trim().to_string().parse()?,
                entry_type: e[2].trim().to_string().parse()?,
                ports: e[3].trim().to_string(),
            };

            return Ok(Some(mac));
        }

        return Ok(None);
    }

    pub fn poe_debug(&mut self) -> std::io::Result<()> {
        self.channel.write(b"debug ilpower port status\n")?;

        let raw = self.fetch_data()?;
        let data = self.clean_data(raw);

        for line in data.split("\n") {
            if line.len() < 39 {
                continue;
            }
            let port = line[0..4].trim().to_string();
            let _state = line[5..10].trim().to_string();
            let status = line[11..21].trim().to_string();
            let prio = line[22..30].trim().to_string();
            let class = line[31..38].trim().to_string();
            let reason = line[39..].trim().to_string();

            if port.len() < 1 || port == "Port" || port == "----" {
                continue;
            }

            let info = PoEDebug {
                port: port.parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?,
                status: status.parse()?,
                priority: prio.parse()?,
                class: class.parse()?,
                reason: reason,
            };

            println!("{:?}", info);
        }
        Ok(())
    }

    pub fn poe_info(&mut self) -> std::io::Result<(PoEConfig, std::vec::Vec::<PoESupply>, std::vec::Vec::<PoEPort>)> {
        self.channel.write(b"show power inline consumption\n")?;

        let raw = self.fetch_data()?;
        let data = self.clean_data(raw);
        let mut step: u8 = 0;

        let mut cfg = PoEConfig::default();
        let mut supplies = std::vec::Vec::<PoESupply>::new();
        let mut portdata = std::vec::Vec::<PoEPort>::new();

        for line in data.split("\n") {
            if line.trim() == "" {
                step+=1;
                continue;
            }
            match step {
                0 => {
                    let kv: Vec<&str> = line.split(":").collect();
                    if kv.len() < 2 {
                        continue;
                    }
                    let key = kv[0].trim();
                    let val = kv[1].trim();

                    match key {
                        "Power management mode" => cfg.management_mode = val.parse()?,
                        "Pre-allocation" => cfg.pre_allocation = val == "Enabled",
                        "Power-up sequence" => cfg.power_up_sequence = val.parse()?,
                        _ => { return Err(std::io::Error::new(std::io::ErrorKind::Other, "Received invalid data")); },
                    }
                },
                1 => {
                    //Unit Power Status Nominal  Allocated       Consumed Available
                    //                  Power    Power           Power    Power
                    //---- ----- ------ -------- --------------- -------- ---------
                    if line.len() < 52 {
                        continue;
                    }
                    let unit: u8 = match line[0..4].trim().parse() {
                        Ok(x) => x,
                        Err(_fail) => { continue; },
                    };
                    let power = line[5..10].trim();
                    let status = line[11..17].trim();
                    let nom_pwr = line[18..26].trim().replace("Watts", "");
                    let alo_pwr = line[27..42].trim().split(" ").collect::<Vec<&str>>()[0].replace("Watts", "");
                    let con_pwr = line[43..51].trim().replace("Watts", "");
                    let ava_pwr = line[52..].trim().replace("Watts", "");

                    let supply = PoESupply {
                        unit: unit,
                        power: power.to_string(),
                        status: status.to_string(),
                        nominal_power: nom_pwr.parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?,
                        allocated_power: alo_pwr.parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?,
                        consumed_power: con_pwr.parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?,
                        available_power: ava_pwr.parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?,
                    };
                    supplies.push(supply);
                },
                2 => {
                    //Port Power Limit (Admin) (mW) Power (mW) Voltage (mV) Current (mA)
                    //---- ------------------------ ---------- ------------ ------------
                    if line.len() < 54 {
                        continue;
                    }
                    let port: u8 = match line[0..4].trim().parse() {
                        Ok(x) => x,
                        Err(_fail) => { continue; },
                    };
                    let both_pwr_limit = line[5..29].trim();
                    let pwr_limit_split: Vec<&str> = both_pwr_limit[0..both_pwr_limit.len()-1].split("(").collect();
                    let pwr_limit: i32 = pwr_limit_split[0].trim().parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?;
                    let admin_pwr_limit: i32 = pwr_limit_split[1].trim().parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?;
                    let pwr: i32 = line[30..40].trim().parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?;
                    let volt: i32 = line[41..53].trim().parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?;
                    let current: i32 = line[54..].trim().parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?;

                    let portinfo = PoEPort {
                        port: port,
                        power_limit: pwr_limit,
                        admin_power_limit: admin_pwr_limit,
                        power: pwr,
                        voltage: volt,
                        current: current,
                    };
                    portdata.push(portinfo);
                },
                _ => {},
            }
        }

        return Ok((cfg, supplies, portdata));
    }

    pub fn cable_info(&mut self) -> std::io::Result<std::vec::Vec::<CableDiagnosis>> {
        return self.cable_info_int("all");
    }

    pub fn cable_info_port(&mut self, port: u8) -> std::io::Result<std::option::Option<CableDiagnosis>> {
        let res = self.cable_info_int(format!("{}", port).as_str());
        return match res {
            Ok(x) => {
                if x.len() <= 0 {
                    return Ok(None);
                }
                let e = x[0];
                return Ok(Some(e));
            },
            Err(e) => Err(e),
        };
    }

    fn cable_info_int(&mut self, interfaces: &str) -> std::io::Result<std::vec::Vec::<CableDiagnosis>> {
        self.channel.write(format!("show cable-diag interfaces {}\n", interfaces).as_bytes())?;
        let mut result = std::vec::Vec::<CableDiagnosis>::new();

        let raw = self.fetch_data()?;
        let data = self.clean_data(raw);

        let mut diag = CableDiagnosis::default();

        for line in data.split("\n") {
            let fields: Vec<&str> = line.split("|").collect();
            if fields.len() == 5 && fields[0].trim() != "Port" {
                let port: u8 = fields[0].trim().parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?;
                let speed: String = fields[1].trim().to_string();
                let pair: String = fields[2].trim().replace("Pair ", "").to_string();
                let pairc: char = pair.chars().next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?;
                let length: u32 = fields[3].trim().replace(".", "").parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?;
                let status: String = fields[4].trim().to_string();
                diag.port = port;
                diag.speed = speed.parse()?;
                diag.pair_info[0].pair = pairc;
                diag.pair_info[0].length = length;
                diag.pair_info[0].status =status.parse::<CablePairState>()?;
            } else if fields.len() == 3 {
                let pair: String = fields[0].trim().replace("Pair ", "").to_string();
                let length: u32 = fields[1].trim().replace(".", "").parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?;
                let status: String = fields[2].trim().to_string();
                let pairc: char = pair.chars().next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?;
                let offset = match pairc { 'A' => 0, 'B' => 1, 'C' => 2, 'D' => 3, _ => 4 };
                if offset > 3 { continue }
                diag.pair_info[offset].pair = pairc;
                diag.pair_info[offset].length = length;
                diag.pair_info[offset].status = status.parse::<CablePairState>()?;
            } else if line.trim() == "" {
                if diag.port > 0 {
                    result.push(diag);
                }
                diag = CableDiagnosis::default();
            }
        }

        return Ok(result);
    }

    pub fn interface_info(&mut self) -> std::io::Result<std::vec::Vec::<InterfaceTrafficStatus>> {
        return self.interface_info_int("all");
    }

    pub fn interface_info_port(&mut self, port: u8) -> std::io::Result<InterfaceTrafficStatus> {
        let ret = self.interface_info_int(format!("{}", port).as_str());
        return match ret {
            Err(x) => Err(x),
            Ok(x) => {
                if x.len() <= 0 {
                    Err(std::io::Error::new(std::io::ErrorKind::Other, "Port not found"))
                } else {
                    Ok(x[0])
                }
            },
        }
    }

    fn interface_info_int(&mut self, interfaces: &str) -> std::io::Result<std::vec::Vec::<InterfaceTrafficStatus>> {
        self.channel.write(format!("show interfaces {}\n", interfaces).as_bytes())?;
        let mut result = std::vec::Vec::<InterfaceTrafficStatus>::new();

        let raw = self.fetch_data()?;
        let data = self.clean_data(raw);

        let mut status = InterfaceTrafficStatus::default();

        for line in data.split("\n") {
            if line.starts_with("     ") {
                lazy_static! {
                    static ref RE1: Regex = Regex::new(r"(\d+) packets input, (\d+) bytes, (\d+) throttles").unwrap();
                    static ref RE2: Regex = Regex::new(r"Received (\d+) broadcasts \((\d+) multicasts\)").unwrap();
                    static ref RE3: Regex = Regex::new(r"(\d+) runts, (\d+) giants, (\d+) throttles").unwrap();
                    static ref RE4: Regex = Regex::new(r"(\d+) input errors, (\d+) CRC, (\d+) frame, (\d+) overrun, (\d+) ignored").unwrap();
                    static ref RE5: Regex = Regex::new(r"(\d+) multicast, (\d+) pause input").unwrap();
                    static ref RE6: Regex = Regex::new(r"(\d+) input packets with dribble condition detected").unwrap();
                    static ref RE7: Regex = Regex::new(r"(\d+) packets output, (\d+) bytes, (\d+) underrun").unwrap();
                    static ref RE8: Regex = Regex::new(r"(\d+) output errors, (\d+) collisions, (\d+) interface resets").unwrap();
                    static ref RE9: Regex = Regex::new(r"(\d+) babbles, (\d+) late collision, (\d+) deferred").unwrap();
                    static ref RE10: Regex = Regex::new(r"(\d+) PAUSE output").unwrap();
                }
                for cap in RE1.captures_iter(line) {
                    status.input_packets = cap[1].parse().unwrap();
                    status.input_bytes = cap[2].parse().unwrap();
                    status.input_throttles = cap[3].parse().unwrap();
                }
                for cap in RE2.captures_iter(line) {
                    status.input_broadcasts = cap[1].parse().unwrap();
                    status.input_multicasts = cap[2].parse().unwrap();
                }
                for cap in RE3.captures_iter(line) {
                    status.input_runts = cap[1].parse().unwrap();
                    status.input_giants = cap[2].parse().unwrap();
                }
                for cap in RE4.captures_iter(line) {
                    status.input_errors = cap[1].parse().unwrap();
                    status.input_crc = cap[2].parse().unwrap();
                    status.input_frame = cap[3].parse().unwrap();
                    status.input_overrun = cap[4].parse().unwrap();
                    status.input_ignored = cap[5].parse().unwrap();
                }
                for cap in RE5.captures_iter(line) {
                    status.input_pause = cap[2].parse().unwrap();
                }
                for cap in RE6.captures_iter(line) {
                    status.input_dribble = cap[1].parse().unwrap();
                }
                for cap in RE7.captures_iter(line) {
                    status.output_packets = cap[1].parse().unwrap();
                    status.output_bytes = cap[2].parse().unwrap();
                    status.output_underrun = cap[3].parse().unwrap();
                }
                for cap in RE8.captures_iter(line) {
                    status.output_errors = cap[1].parse().unwrap();
                    status.output_collisions = cap[2].parse().unwrap();
                    status.output_interface_resets = cap[3].parse().unwrap();
                }
                for cap in RE9.captures_iter(line) {
                    status.output_babbles = cap[1].parse().unwrap();
                    status.output_late_collisions = cap[2].parse().unwrap();
                    status.output_deferred = cap[3].parse().unwrap();
                }
                for cap in RE10.captures_iter(line) {
                    status.output_paused =  cap[1].parse().unwrap();
                    if status.port > 0 {
                        result.push(status);
                        status = InterfaceTrafficStatus::default();
                    }
                }
            } else if line.starts_with("  ") {
                if line.contains("media type is") {
                    let splitted: Vec<&str> = line.split(", ").collect();
                    status.duplex = splitted[0].trim().replace("-duplex", "").to_string().parse()?;
                    status.speed = splitted[1].trim().replace("-speed", "").to_string().parse()?;
                    status.media_type = splitted[2][14..].parse()?;
                } else if line.contains("flow-control is") {
                    status.flow_control = line[16..].contains("on");
                }
            } else if line.starts_with("GigabitEthernet") {
                let splitted: Vec<&str> = line[15..].split(" ").collect();
                status.port = splitted[0].parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?;
                status.up = splitted[2] == "up";
            }
        }

        return Ok(result);
    }

    pub fn interface_status_info(&mut self) -> std::io::Result<std::vec::Vec::<InterfaceStatus>> {
        self.channel.write(b"show interfaces all status\n")?;
        let mut result = std::vec::Vec::<InterfaceStatus>::new();

        lazy_static! {
            static ref RE: Regex = Regex::new(r"^(\d+)[ ]+(.*?)[ ]+(notconnect|connected)[ ]+(\d+)[ ]+([^ ]+)[ ]+([^ ]+)[ ]+(Copper|Fiber)$").unwrap();
        }

        let raw = self.fetch_data()?;
        let data = self.clean_data(raw);

        for line in data.split("\n") {
            for cap in RE.captures_iter(line) {
                let interface = InterfaceStatus {
                    port: cap[1].parse().unwrap(),
                    name: cap[2].to_string(),
                    connected: &cap[3] == "connected",
                    vlan: cap[4].parse().unwrap(),
                    duplex: cap[5].parse()?,
                    speed: cap[6].parse()?,
                    mediatype: cap[7].parse()?,
                };
                result.push(interface);
            }
        }
        Ok(result)
    }

    pub fn vlan_info(&mut self) -> std::io::Result<std::vec::Vec::<VLANInfo>> {
        self.channel.write(b"show vlan\n")?;
        let mut result = std::vec::Vec::<VLANInfo>::new();

        let raw = self.fetch_data()?;
        let data = self.clean_data(raw);

        for line in data.split("\n") {
            let elements: std::vec::Vec<&str> = line.split("|").collect();
            if elements.len() < 5 || elements[0].trim() == "VID" {
                continue;
            }

            let vlan = VLANInfo {
                id: elements[0].trim().parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse data"))?,
                name: elements[1].trim().to_string(),
                ports_untagged: elements[2].trim().to_string(),
                ports_tagged: elements[3].trim().to_string(),
                vlan_type: elements[4].trim().parse()?,
            };

            result.push(vlan);
        }

        Ok(result)
    }

    pub fn nop(&mut self) -> std::io::Result<()> {
        self.channel.write(b"\n")?;
        self.fetch_data()?;
        Ok(())
    }

    #[cfg(feature = "web")]
    fn zyxel_password(&self) -> String {
        let alphabetstr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let alphabet:Vec<char> = alphabetstr.chars().collect();
        let pwchars:Vec<char> = self.password.chars().collect();
        let mut result = String::new();
        let mut i: i32 = self.password.len() as i32;
        i -= 1;

        for x in 0..320 {
            if x % 7 == 6 && i >= 0 {
                result += format!("{}", pwchars[i as usize]).as_str();
                i-=1;
            } else if x == 122 {
                if self.password.len() < 10 {
                    result += "0"
                } else {
                    let c = format!("{}", self.password.len()/10).chars().next().unwrap();
                    result += format!("{}", c).as_str()
                }
            } else if x == 288 {
                result += format!("{}", self.password.len()%10).as_str()
            } else {
                let rnd = random_integer::random_u8(0, (alphabet.len() as u8)-1);
                result += format!("{}", alphabet[rnd as usize]).as_str()
            }
        }

        result
    }

    #[cfg(feature = "web")]
    fn http_login(&mut self) -> std::io::Result<(reqwest::blocking::Client, String)> {
        let client = reqwest::blocking::Client::new();
        let user = &self.username;
        let pass = &self.zyxel_password();
        let dummy = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(n) => format!("{}000", n.as_secs()),
            Err(_) => "1000000000000".to_string(),
        };
        let url = format!("http://{}/cgi-bin/dispatcher.cgi", self.address);

        let authparams = [("login", "1"), ("username", user.as_str()), ("password", pass.as_str()), ("dummy", dummy.as_str())];
        client.get(url.as_str()).query(&authparams).send().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to login: {}", e)))?;

        /* Yes, GS1900 series is very crappy */
        let t = std::time::Duration::from_millis(500);
        std::thread::sleep(t);

        let checkparams = [("login_chk", "1"), ("dummy", dummy.as_str())];
        let response = client.get(url.as_str()).query(&checkparams).send().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to check login: {}", e)))?;
        let data = response.text().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to decode check login data: {}", e)))?;

        if data != "\nOK\n" {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "HTTP Login failed!"));
        }

        let ssidparams = [("cmd", "1")];
        let response = client.get(url.as_str()).query(&ssidparams).send().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to get session: {}", e)))?;
        let data = response.text().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to decode get session data: {}", e)))?;

        lazy_static! {
            static ref RE: Regex = Regex::new(r"setCookie\(.XSSID., .(.*?).\);").unwrap();
        }

        for cap in RE.captures_iter(data.as_str()) {
            return Ok((client, cap[1].to_string()));
        }

        Err(std::io::Error::new(std::io::ErrorKind::Other, "Session not found!"))
    }

    #[cfg(feature = "web")]
    fn construct_headers(&self, session: String) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::USER_AGENT, reqwest::header::HeaderValue::from_static("reqwest"));
        headers.insert(reqwest::header::COOKIE, reqwest::header::HeaderValue::from_str(format!("XSSID={}", session).as_str()).unwrap());
        headers
    }

    #[cfg(feature = "web")]
    fn http_command(&mut self, client: reqwest::blocking::Client, session: String, params: std::collections::HashMap<&str, &str>) -> std::io::Result<()> {
        let url = format!("http://{}/cgi-bin/dispatcher.cgi", self.address);
        let headers = self.construct_headers(session.clone());

        let request = client.post(url.as_str()).form(&params).headers(headers);

        let _response = request.send();

        /*
         * GS1900 response does not contain an empty line after headers,
         * which results in an error in the hyper crate (library used by
         * reqwest to parse the server response). Fortunately we do not
         * really need the response, so let's just ignore the result.
         * If hyper crate gets a workaround for the issue, we should check
         * the HTTP response for success.
         */
        //let data = _response.unwrap().text().unwrap();

        Ok(())
    }

    #[cfg(feature = "web")]
    pub fn control_poe(&mut self, port: u8, state: bool, priority: PoEPriority, power_mode: PoEPowerMode, range_detection: bool, power_limit_mode: PoELimitMode, power_limit: i32) -> std::io::Result<()> {
        let (client, session) = self.http_login()?;

        let stateparam = match state {
            true => "1",
            false => "0",
        };
        let prioparam = match priority {
            PoEPriority::Critical => "0",
            PoEPriority::High => "1",
            PoEPriority::Medium => "2",
            PoEPriority::Low => "3",
        };
        let rangeparam = match range_detection {
            true => "1",
            false => "0",
        };
        let portparam = format!("{}", port);

        let modeparam = match power_limit_mode {
            PoELimitMode::Classification => "0",
            PoELimitMode::User => "0",
        };
        if power_limit < 1000 || power_limit > 33000 { /* mW */
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Invalid power limit!"));
        }
        let pwrlimitparam = format!("{}", power_limit);

        let pwrmodeparam = match power_mode {
            PoEPowerMode::IEEE_802_3af => "0",
            PoEPowerMode::Legacy => "1",
            PoEPowerMode::Pre_802_3at => "2",
            PoEPowerMode::IEEE_802_3at => "3",
        };

        let mut params = std::collections::HashMap::new();
        params.insert("cmd", "775");
        params.insert("portlist", portparam.as_str());
        params.insert("state", stateparam);
        params.insert("portPriority", prioparam);
        params.insert("portPowerMode", pwrmodeparam);
        params.insert("portRangeDetection", rangeparam);
        params.insert("portLimitMode", modeparam);
        params.insert("portPowerLimit", pwrlimitparam.as_str());
        params.insert("poeTimeRange", "20");
        params.insert("sysSubmit", "Apply");
        params.insert("XSSID", session.as_str());

        self.http_command(client, session.clone(), params)
    }

    #[cfg(feature = "web")]
    pub fn control_port(&mut self, port: u8, label: String, enabled: bool, speed: PortSpeed, duplex: PortDuplex, flow_control: bool) -> std::io::Result<()> {
        let (client, session) = self.http_login()?;

        let portparam = format!("{}", port);

        let stateparam = match enabled {
            true => "1",
            false => "0",
        };

        let speedparam: &str;
        if speed.auto {
            speedparam = "0";
        } else if speed.speed >= 1000 {
            speedparam = "3";
        } else if speed.speed >= 100 {
            speedparam = "2";
        } else if speed.speed >= 10 {
            speedparam = "1";
        } else {
            speedparam = "0";
        }

        let duplexparam = match duplex {
            PortDuplex::Auto => "0",
            PortDuplex::Full => "1",
            PortDuplex::Half => "2",
        };

        let fcparam = match flow_control {
            true => "1",
            false => "0",
        };

        let mut params = std::collections::HashMap::new();
        params.insert("cmd", "770");
        params.insert("portlist", portparam.as_str());
        params.insert("descp", label.as_str());
        params.insert("state", stateparam);
        params.insert("speed", speedparam);
        params.insert("duplex", duplexparam);
        params.insert("fc", fcparam);
        params.insert("sysSubmit", "Apply");
        params.insert("XSSID", session.as_str());

        println!("{:?}", params);

        self.http_command(client, session.clone(), params)
    }
}
