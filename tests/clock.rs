//! Standalone host harness for clock failure-path tests (no privileged code runs).
#![allow(dead_code)]

#[path = "../src/platform.rs"]
mod platform;
#[path = "../src/time.rs"]
mod time;
