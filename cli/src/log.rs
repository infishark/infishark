//! Session marks for status only. Tables, JSON, and captured rows stay plain
//! so they can be piped. Marks go to stderr.
//!
//!   ·  progress
//!   +  finished
//!   !  failure or warning

use std::fmt::Display;

use console::style;

fn line(mark: &str, msg: impl Display) {
    eprintln!("{} {}", mark, msg);
}

pub fn info(msg: impl Display) {
    line(&style("·").dim().to_string(), msg);
}

pub fn ok(msg: impl Display) {
    line(&style("+").dim().to_string(), msg);
}

pub fn warn(msg: impl Display) {
    line(&style("!").yellow().to_string(), msg);
}

pub fn err(msg: impl Display) {
    line(&style("!").red().to_string(), msg);
}
