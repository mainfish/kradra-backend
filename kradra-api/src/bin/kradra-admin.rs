use std::error::Error;

use sqlx::Row;
use sqlx::postgres::PgPoolOptions;

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  kradra-admin promote <username>");
    eprintln!("  kradra-admin demote <username>");
    eprintln!("  kradra-admin set-role <username> <admin|user>");
    eprintln!("  kradra-admin list");
    eprintln!("");
    eprintln!("Environment:");
    eprintln!("  DATABASE_URL=postgres://...");
}

fn normalize_role(role: &str) -> Option<&'static str> {
    match role {
        "admin" | "ADMIN" => Some("admin"),
        "user" | "USER" => Some("user"),
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    dotenvy::dotenv().ok();

    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        print_usage();
        std::process::exit(2);
    };

    let database_url = std::env::var("DATABASE_URL").map_err(
        |_| "DATABASE_URL is not set (expected in env or .env file next to the workspace)",
    )?;

    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    match cmd.as_str() {
        "promote" => {
            let Some(username) = args.next() else {
                print_usage();
                std::process::exit(2);
            };

            set_role(&db, &username, "admin").await?;
            println!("OK: {username} promoted to admin");
        }
        "demote" => {
            let Some(username) = args.next() else {
                print_usage();
                std::process::exit(2);
            };

            set_role(&db, &username, "user").await?;
            println!("OK: {username} demoted to user");
        }
        "set-role" => {
            let Some(username) = args.next() else {
                print_usage();
                std::process::exit(2);
            };
            let Some(role_raw) = args.next() else {
                print_usage();
                std::process::exit(2);
            };

            let Some(role) = normalize_role(&role_raw) else {
                eprintln!("Invalid role: {role_raw} (expected: admin|user)");
                std::process::exit(2);
            };

            set_role(&db, &username, role).await?;
            println!("OK: {username} role set to {role}");
        }
        "list" => {
            list_users(&db).await?;
        }
        _ => {
            print_usage();
            std::process::exit(2);
        }
    }

    Ok(())
}

async fn set_role(
    db: &sqlx::PgPool,
    username: &str,
    role: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let result = sqlx::query(
        r#"
        UPDATE users
        SET role = $2
        WHERE username = $1
        "#,
    )
    .bind(username)
    .bind(role)
    .execute(db)
    .await?;

    if result.rows_affected() == 0 {
        eprintln!("User not found: {username}");
        std::process::exit(1);
    }

    Ok(())
}

async fn list_users(db: &sqlx::PgPool) -> Result<(), Box<dyn Error + Send + Sync>> {
    let rows = sqlx::query(
        r#"
        SELECT id::text as id, username, role, is_active,
               to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') as created_at
        FROM users
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(db)
    .await?;

    if rows.is_empty() {
        println!("No users found.");
        return Ok(());
    }

    println!(
        "{:<36}  {:<20}  {:<8}  {:<8}  {}",
        "id", "username", "role", "active", "created_at"
    );

    for row in rows {
        let id: String = row.try_get("id")?;
        let username: String = row.try_get("username")?;
        let role: String = row.try_get("role")?;
        let is_active: bool = row.try_get("is_active")?;
        let created_at: String = row.try_get("created_at")?;

        println!(
            "{:<36}  {:<20}  {:<8}  {:<8}  {}",
            id,
            username,
            role,
            if is_active { "true" } else { "false" },
            created_at
        );
    }

    Ok(())
}
