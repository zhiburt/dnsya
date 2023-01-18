use std::{io, str::FromStr};

use clap::{arg, command, Parser};

#[derive(Debug, Clone)]
pub struct Config {
    pub device: Option<String>,
    pub filter: Option<PacketType>,
    pub options: FormatOptions,
    pub format: OutputFormat,
}

impl Config {
    pub fn parse() -> Self {
        let config = CLIConfig::parse();
        Self {
            device: config.device,
            filter: config.filter,
            options: config.options.unwrap_or_default(),
            format: config.format.unwrap_or(OutputFormat::Text),
        }
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct CLIConfig {
    /// A device we will explore.
    #[arg(value_name = "DEVICE")]
    device: Option<String>,
    /// DNS packet filtering (q - query, r - response)
    #[arg(short, long, value_name = "FILTER")]
    filter: Option<PacketType>,
    /// Optional data display (options: 'p', 's', 't')
    #[arg(short, long, value_name = "OPTIONS")]
    options: Option<FormatOptions>,
    /// Output format (text | csv | table)
    #[arg(long, value_name = "FORMAT")]
    format: Option<OutputFormat>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Query,
    Response,
}

impl FromStr for PacketType {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "q" => Ok(Self::Query),
            "r" => Ok(Self::Response),
            _ => Err(io::Error::new(
                io::ErrorKind::Other,
                "unexpected packet filter (expected: 'r', 'q')",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputOptions {
    Name,
}

impl FromStr for OutputOptions {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "name" => Ok(Self::Name),
            _ => Err(io::Error::new(
                io::ErrorKind::Other,
                "unexpected output option",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Table,
    Csv,
}

impl FromStr for OutputFormat {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "text" => Ok(Self::Text),
            "table" => Ok(Self::Table),
            "csv" => Ok(Self::Csv),
            _ => Err(io::Error::new(
                io::ErrorKind::Other,
                "unexpected output format",
            )),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct FormatOptions {
    pub port: bool,
    pub service_name: bool,
    pub packet_type: bool,
}

impl FromStr for FormatOptions {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut options = FormatOptions::default();
        for c in s.chars() {
            match c {
                'p' => options.port = true,
                's' => options.service_name = true,
                't' => options.packet_type = true,
                c => return Err(format!("unexpected option {:?}", c)),
            }
        }

        Ok(options)
    }
}
