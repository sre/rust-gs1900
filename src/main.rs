// © 2020 Sebastian Reichel
// SPDX-License-Identifier: ISC

extern crate gs1900;
use std::str::FromStr;

fn help(name: &str) {
        eprintln!("{} <address> <user> <pass> <cmd>", name);
        eprintln!("");
        eprintln!("Commands:");
        eprintln!(" basic-info");
        eprintln!(" lldp-info");
        eprintln!(" fiber-info");
        eprintln!(" poe-info");
        eprintln!(" poe-debug");
        eprintln!(" cable-info");
        eprintln!(" interface-info");
        eprintln!(" vlan-info");
        eprintln!(" mac-table");
        eprintln!(" mac-table-port <port>");
        eprintln!(" cable-info-port <port>");
        eprintln!(" interface-info-port <port>");
        eprintln!(" lookup-mac-address <MAC>");
        eprintln!(" interface-status-info");
        #[cfg(feature = "web")]
        eprintln!("");
        #[cfg(feature = "web")]
        eprintln!("HTTP commands: (WARNING: commands reset poe/port settings as side-effect)");
        #[cfg(feature = "web")]
        eprintln!(" poe-enable");
        #[cfg(feature = "web")]
        eprintln!(" poe-disable");
        #[cfg(feature = "web")]
        eprintln!(" port-enable");
        #[cfg(feature = "web")]
        eprintln!(" port-disable");

}

fn main_err() -> std::io::Result<()> {
    println!("Zyxel GS1900 Tool");
    println!();

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 1 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Not enough parameters"));
    }

    if args.len() < 5 {
        help(args[0].as_str());
        eprintln!("");
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "Not enough parameters"));
    }

    let addr = args[1].to_string();
    let user = args[2].to_string();
    let pw = args[3].to_string();
    let cmd = args[4].as_str();
    let arg : String;
    if args.len() > 5 {
        arg = args[5].to_string();
    } else {
        arg = "".to_string();
    }

    println!("Connect to {}...", addr);
    let mut sw = gs1900::GS1900::new(addr, user, pw)?;

    match cmd {
        "basic-info" => {
            println!("Requesting basic info...");
            let data = sw.basic_info()?;
            println!("{:?}", data);
        },
        "lldp-info" => {
            println!("Requesting LLDP info...");
            let data = sw.lldp_info()?;
            for entry in data {
                println!("{:?}", entry);
            }
        },
        "fiber-info" => {
            println!("Requesting fiber info...");
            let data = sw.fiber_info()?;
            println!("{:?}", data);
        },
        "poe-info" => {
            println!("Requesting PoE info...");
            let data = sw.poe_info()?;
            println!("{:?}", data);
        },
        "poe-debug" => {
            println!("Requesting PoE debug info...");
            let data = sw.poe_debug()?;
            println!("{:?}", data);
        },
        "cable-info" => {
            println!("Requesting cable info...");
            let data = sw.cable_info()?;
            for x in data {
                println!("{:?}", x);
            }
        },
        "cable-info-port" => {
            println!("Requesting cable info...");
            let data = sw.cable_info_port(arg.parse().unwrap())?;
            for x in data {
                println!("{:?}", x);
            }
        },
        "interface-info" => {
            println!("Requesting interface info...");
            let data = sw.interface_info()?;
            for x in data {
                println!("{:?}", x);
            }
        },
        "interface-info-port" => {
            println!("Requesting interface port info...");
            let data = sw.interface_info_port(arg.parse().unwrap())?;
            println!("{:?}", data);
        },
        "interface-status-info" => {
            println!("Requesting interface status info...");
            let data = sw.interface_status_info()?;
            for x in data {
                println!("{:?}", x);
            }
        },
        "vlan-info" => {
            println!("Requesting VLAN info...");
            let data = sw.vlan_info()?;
            println!("{:?}", data);
        },
        "mac-table" => {
            println!("Requesting MAC table...");
            let data = sw.mac_table()?;
            for x in data {
                println!("{:?}", x);
            }
        },
        "mac-table-port" => {
            println!("Requesting MAC table...");
            let data = sw.mac_table_port(arg.parse().unwrap())?;
            for x in data {
                println!("{:?}", x);
            }
        },
        "lookup-mac-address" => {
            println!("Requesting MAC table...");
            let data = sw.lookup_mac_address(gs1900::MacAddress::from_str(arg.as_str()).unwrap())?;
            println!("{:?}", data);
        },
        #[cfg(feature = "web")]
        "poe-enable" => {
            println!("HTTP request...");
            sw.control_poe(arg.parse().unwrap(), true, gs1900::PoEPriority::Low, gs1900::PoEPowerMode::IEEE_802_3af, false, gs1900::PoELimitMode::Classification, 1000)?;
        },
        #[cfg(feature = "web")]
        "poe-disable" => {
            println!("HTTP request...");
            sw.control_poe(arg.parse().unwrap(), false, gs1900::PoEPriority::Low, gs1900::PoEPowerMode::IEEE_802_3af, false, gs1900::PoELimitMode::Classification, 1000)?;
        },
        #[cfg(feature = "web")]
        "port-enable" => {
            println!("HTTP request...");
            sw.control_port(arg.parse().unwrap(), "".to_string(), true, gs1900::PortSpeed { auto: true, speed: 0 }, gs1900::PortDuplex::Auto, false)?;
        },
        #[cfg(feature = "web")]
        "port-disable" => {
            println!("HTTP request...");
            sw.control_port(arg.parse().unwrap(), "".to_string(), false, gs1900::PortSpeed { auto: true, speed: 0 }, gs1900::PortDuplex::Auto, false)?;
        },
        _ => {
            help(args[0].as_str());
            eprintln!("");
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "unknown command"));
        }
    }

    return Ok(());
}

fn main() {
    match main_err() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
