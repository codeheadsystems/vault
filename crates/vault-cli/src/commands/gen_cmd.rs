//! `vault gen`, and the generator options `vault add --generate` shares.

use crate::error::{CliError, Result};
use crate::output::JsonResult;
use crate::session::{Ctx, OsRng};
use crate::sys::clip;
use clap::Args;
use vault_core::generate::{self, Classes};
use vault_core::json::{self, Value};
use vault_core::secret::SecretString;
use zeroize::Zeroizing;

/// The generator options.
#[derive(Debug, Args)]
pub struct GenArgs {
    /// Password length
    #[arg(long, value_name = "N", default_value_t = generate::DEFAULT_LENGTH)]
    pub length: usize,
    /// No upper-case letters
    #[arg(long)]
    pub no_upper: bool,
    /// No digits
    #[arg(long)]
    pub no_digits: bool,
    /// No symbols
    #[arg(long)]
    pub no_symbols: bool,
    /// Allows the ambiguous characters 0O1lI
    #[arg(long)]
    pub ambiguous: bool,
    /// A passphrase of N words instead [default: 7]
    #[arg(
        long,
        value_name = "N",
        num_args = 0..=1,
        default_missing_value = "7",
        conflicts_with_all = ["length", "no_upper", "no_digits", "no_symbols", "ambiguous"]
    )]
    pub words: Option<usize>,
    /// The passphrase word separator
    #[arg(long, default_value = "-", requires = "words")]
    pub separator: String,
}

impl GenArgs {
    /// Generates the value and its entropy in bits.
    pub fn generate(&self) -> Result<(SecretString, f64)> {
        let bad = |_| CliError::usage("the generator options are out of range");
        match self.words {
            Some(n) => Ok((
                generate::passphrase(&mut OsRng, n, &self.separator).map_err(bad)?,
                generate::passphrase_bits(n),
            )),
            None => {
                let classes = Classes {
                    upper: !self.no_upper,
                    lower: true,
                    digits: !self.no_digits,
                    symbols: !self.no_symbols,
                    avoid_ambiguous: !self.ambiguous,
                };
                Ok((
                    generate::password(&mut OsRng, self.length, &classes).map_err(bad)?,
                    generate::password_bits(self.length, &classes).map_err(bad)?,
                ))
            }
        }
    }
}

/// `vault gen`: prints the value, or copies it with `-c`; the entropy goes to standard error.
pub fn gen_cmd(ctx: &Ctx, args: &GenArgs, copy: bool) -> Result<JsonResult> {
    let (value, bits) = args.generate()?;
    if copy {
        clip::copy(&value, ctx.settings.clear_after)?;
    } else {
        ctx.out.line(&value);
    }
    if !ctx.out.json {
        ctx.out.err(&format!("{bits:.1} bits of entropy"));
    }
    let mut raw = Zeroizing::new(Vec::new());
    raw.extend_from_slice(format!("{{\"bits\":{bits:.1},\"value\":").as_bytes());
    raw.extend_from_slice(&json::to_vec(&Value::String(value.to_string())));
    raw.push(b'}');
    Ok(JsonResult::Raw(raw))
}
