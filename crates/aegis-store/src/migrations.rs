use crate::error::{Result, StoreError};
use rusqlite::Connection;
use rusqlite_migration::{Migrations, M};

pub fn run_migrations(conn: &mut Connection) -> Result<()> {
    let migrations = Migrations::new(vec![M::up(include_str!("../migrations/001_initial.sql"))]);
    migrations
        .to_latest(conn)
        .map_err(|e| StoreError::Migration(e.to_string()))
}
