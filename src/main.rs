use clap::{App, Arg};
use std::env::var as get_env;
// use std::{result, time::Duration, thread::sleep};
use serde_json;
use regex::Regex;
use colored::*;
use reqwest;
use termion::{cursor, clear};


fn get_state(host: &str, port: u16, id: u32, zap_key: &str) -> serde_json::Value {
    let client = reqwest::blocking::Client::builder().build().unwrap();
    client
        .get(
            format!(
                "http://{}:{}/JSON/ascan/view/scanProgress/?apikey={}&scanId={}",
                host,
                port,
                zap_key,
                id
            )
        )
        .header(
            "Accept",
            "application/json"
        )
        .send().unwrap()
        .json::<serde_json::Value>().unwrap()
}

fn run_monitor_mode(host: &str, port: u16, id: u32, zap_key: String) -> Result<(), i32> {
    print!("{}", clear::All);
    loop {
        let progress_regex = Regex::new(r"^\d{1,3}%$").unwrap();
        let state = get_state(host, port, id, zap_key.as_str());

        if state.get("code").is_some() {
            eprintln!("{}: Unable to retrieve state: {}", "Error".red(), state);
            return Err(3);
        }

        let tests = &state["scanProgress"];
        let mut screen = String::new();
        let mut current_host = String::new();
        let mut found_in_progress = false;
        for i in 0..tests.as_array().unwrap().len() {
            if i % 2 == 0 {
                current_host = tests[i].to_string();
                continue
            }

            let plugins = &tests[i]["HostProcess"];
            let plugins_num = plugins.as_array().unwrap().len();
            for j in 0..plugins_num {
                let name = plugins[j]["Plugin"][0].as_str().unwrap();
                let progress = plugins[j]["Plugin"][3].as_str().unwrap();

                let duration = plugins[j]["Plugin"][4].as_str().unwrap();
                let duration = (duration.parse::<f64>().unwrap() / 1000.0).to_string();

                if progress_regex.is_match(progress) {
                    found_in_progress = true;
                    let progress_bar = progress[0..progress.len() - 1].parse::<usize>().unwrap() / 5;
                    screen += format!("{}{}", current_host, clear::UntilNewline).as_str();
                    screen += format!("\n\t{} -- ", name.yellow()).as_str();
                    screen += format!("{} ", progress).as_str();
                    screen += format!("[{:■<1$}", "", progress_bar).as_str();
                    screen += format!("{:.<1$}] ", "", 20usize - progress_bar).as_str();
                    screen += format! {"{}s{}\n", duration.as_str().bold(), clear::UntilNewline}.as_str();
                }
            }
            screen += "\n"
        }

        if found_in_progress {
            println!("{}{}{}{}", cursor::Hide, cursor::Goto(1, 1), screen, clear::UntilNewline);
        }
        else {
            println!("No ongoing operations found for ascan {}.", id);
            println!("You can see summary running {} without flag {}", "zam".bold(), "-m".bold());
            break;
        }
    }

    Ok(())
}

fn show_state(host: &str, port: u16, id: u32, zap_key: String) -> Result<(), i32> {
    let progress_regex = Regex::new(r"^\d{1,3}%$").unwrap();
    let state = get_state(host, port, id, zap_key.as_str());

    if state.get("code").is_some() {
        eprintln!("{}: Unable to retrieve state: {}", "Error".red(), state);
        return Err(3);
    }

    let tests = &state["scanProgress"];
    let mut screen = String::new();
    for i in 0..tests.as_array().unwrap().len() {
        if i % 2 == 0 {
            screen += format!("{}\n", tests[i].as_str().unwrap()).as_str();
            continue
        }

        let plugins = &tests[i]["HostProcess"];
        let plugins_num = plugins.as_array().unwrap().len();
        for j in 0..plugins_num {
            let name = &plugins[j]["Plugin"][0];
            let progress = plugins[j]["Plugin"][3].as_str().unwrap();
            let mut progress_bar = 0;
            let mut color = Color::White;

            let duration = plugins[j]["Plugin"][4].as_str().unwrap();
            let duration = (duration.parse::<f64>().unwrap() / 1000.0).to_string();

            if progress_regex.is_match(progress) {
                progress_bar = progress[0..progress.len() - 1].parse::<usize>().unwrap() / 10;
                color = Color::Yellow;
            }
            else if progress == "Complete" {
                progress_bar = 10;
                color = Color::Green;
            }
            else if progress.starts_with("Skipped") {
                color = Color::Red;
            }
            else if progress == "Pending" {
                color = Color::Blue;
            }

            screen += format!("\t[{:■<1$}", "", progress_bar).as_str();
            screen += format!("{:.<1$}] ", "", 10usize - progress_bar).as_str();
            screen += format!("{}\t({}s)\t{}\n", progress.color(color), duration.bold(), name).as_str();
        }
        screen += "\n"
    }

    print!("{}{}", screen, clear::AfterCursor);
    Ok(())
}

fn main() -> Result<(), i32> {
    let matches = App::new("ZAP Ascan Monitor")
        .version("1.0.0")
        .author("Sin Kettu <avangard.jazz@gmail.com>")
        .arg(Arg::with_name("address")
            .short("a")
            .long("address")
            .value_name("ADDRESS")
            .takes_value(true)
            .required(true)
            .help("Address and port of ZAP API: <address:port>"))
        .arg(Arg::with_name("scan_id")
            .short("i")
            .long("scan-id")
            .value_name("SCAN-ID")
            .takes_value(true)
            .required(true)
            .help("IF of active scanner to monitor"))
        .arg(Arg::with_name("monitor")
            .short("m")
            .long("monitor")
            .takes_value(false)
            .help("Monitor mode, zam will show ongoing processes"))
        .get_matches();

    // Retrieving zam parameters
    let address = matches.value_of("address").unwrap();
    let id = matches.value_of("scan_id").unwrap().parse::<u32>().unwrap();
    let monitor = matches.is_present("monitor");
    let zap_key = match get_env("ZAP_KEY") {
        Ok(val) => val.to_string(),
        Err(err) => {
            eprintln!("{}: Cannot retrieve ZAP API key from ENV: {}", "Error".red(), err);
            return Err(1);
        }
    };

    // Convert passed address to more convenient shape
    let split_address = address.split(":").collect::<Vec<&str>>();
    if split_address.len() != 2 {
        eprintln!("Given address is not valid and must be in the following format: IP:PORT. Current: {}", address.bold());
        return Err(2);
    }

    let host = split_address[0];
    let port = split_address[1].parse::<u16>().unwrap();

    if monitor {
        run_monitor_mode(host, port, id, zap_key)
    }
    else {
        show_state(host, port, id, zap_key)
    }
}
