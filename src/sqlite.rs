use std::io;

use anyhow::Context;
use rusqlite::{Row, types::Type};

pub fn integer(value: u64, field: &'static str) -> anyhow::Result<i64> {
    i64::try_from(value).with_context(|| format!("{field} exceeds SQLite INTEGER range"))
}

pub fn unsigned(row: &Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| negative_integer(index, value))
}

pub fn optional_unsigned(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<u64>> {
    let value: Option<i64> = row.get(index)?;
    value
        .map(|value| u64::try_from(value).map_err(|_| negative_integer(index, value)))
        .transpose()
}

fn negative_integer(index: usize, value: i64) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        Type::Integer,
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("negative value {value} for unsigned field"),
        )
        .into(),
    )
}
