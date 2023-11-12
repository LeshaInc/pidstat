mod pidstat;

use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};
use comfy_table::{ContentArrangement, Table};
use human_bytes::human_bytes;
use libc::pid_t;

use crate::pidstat::ProcessInfo;

#[derive(Debug, clap::Parser)]
#[command(version)]
struct Args {
    /// Process ID
    pid: pid_t,
    #[arg(short, long, default_value_t = FormatValues::Pretty, value_enum)]
    format: FormatValues,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FormatValues {
    Pretty,
    Json,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let Some(info) = ProcessInfo::from_pid(args.pid)? else {
        bail!("No such process");
    };

    match args.format {
        FormatValues::Pretty => {
            let mut main_table = Table::new();
            main_table.load_preset(comfy_table::presets::UTF8_FULL_CONDENSED);
            main_table.set_content_arrangement(ContentArrangement::Dynamic);
            main_table.set_header(vec!["PID", "PPID", "SID", "VSS", "RSS", "Num Threads"]);
            main_table.add_row(vec![
                format!("{}", info.pid),
                format!("{}", info.ppid),
                format!("{}", info.sid),
                human_bytes(info.vss as f64),
                human_bytes(info.rss as f64),
                format!("{}", info.tasks.len()),
            ]);

            let mut table = Table::new();
            table.load_preset(comfy_table::presets::UTF8_FULL_CONDENSED);
            table.set_content_arrangement(ContentArrangement::Dynamic);
            table.set_header(vec![
                "TID",
                "State",
                "Command",
                "UTime",
                "STime",
                "StartTime",
                "MinFlt",
                "MajFlt",
                "Prio",
                "Nice",
                "CPU",
            ]);

            for task in &info.tasks {
                table.add_row(vec![
                    format!("{}", task.tid),
                    format!("{:?}", task.state),
                    format!("{}", task.command),
                    format!("{:?}", task.utime),
                    format!("{:?}", task.stime),
                    format!("{:?}", task.start_time),
                    format!("{}", task.min_flt),
                    format!("{}", task.maj_flt),
                    format!("{}", task.prio),
                    format!("{}", task.nice),
                    format!("{}", task.cpu),
                ]);
            }

            println!("{main_table}");
            println!("{table}");
        }
        FormatValues::Json => {
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
    }

    Ok(())
}
