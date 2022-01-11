use clap::{App, Arg};
use std::env::var as get_env;
use serde_json;
use regex::Regex;
use reqwest::{
    self,
    header::{
        HeaderMap,
        HeaderName,
        HeaderValue
    },
    redirect::Policy,
    blocking::Response
};

fn get_state(host: &str, port: u16, id: u32, zap_key: &str) -> serde_json::Value {
    let client = reqwest::blocking::Client::builder().build().unwrap();
    client
        .post(
            format!(
                "http://{}:{}/JSON/ascan/view/scanProgress/?apikey={}&Id={}",
                host,
                port,
                zap_key,
                id
            )
        )
        .send().unwrap()
        .json::<serde_json::Value>().unwrap()
}

fn main() {
    let matches = App::new("ZAP Ascan Monitor")
                                .version("0.1")
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
                                .get_matches();

    let address = matches.value_of("address").unwrap();
    let id = matches.value_of("scan_id").unwrap().parse::<u32>().unwrap();
    let zap_key = match get_env("ZAP_KEY") {
        Ok(val) => val.to_string(),
        Err(err) => panic!("Error occurred when getting ZAP KEY: {}", err.to_string())
    };

    let host_regex = Regex::new(
        r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})$"
    ).unwrap();

    let groups = host_regex.captures(address);
    let host;
    let port;
    match groups {
        Some(val) => {
            host = val.get(1)
                .expect("Cannot get host (address) from hostname")
                .as_str();
            port = val.get(2)
                .expect("Cannot get port from hostname")
                .as_str()
                .parse::<u16>().unwrap();
        },
        None => panic!("Cannot parse passed address")
    };

    let state = get_state(host, port, id, zap_key.as_str());
    println!("{:#?}", state.as_object().unwrap());
    println!();
    for (key, value) in state.as_object().unwrap() {
        println!("{}", key);
    }
}
