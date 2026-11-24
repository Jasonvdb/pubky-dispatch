//! Values the host programs check the redaction with: a record and an error that aren't on
//! the redaction script's public list, each carrying a known text. Built only with the
//! `test-fixtures` feature, which no production build enables.

/// The text the fixtures carry, which no generated description may show.
pub const FIXTURE_TEXT: &str = "fixture-text-not-to-show";

/// A record the generated bindings would describe field by field.
#[derive(Debug, uniffi::Record)]
pub struct RedactionFixture {
    /// The text not to show.
    pub hidden: String,
}

/// An error the generated bindings would describe field by field, named without the
/// `Error` suffix the generator turns into `Exception`.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FixtureFailure {
    /// Carries the text not to show.
    #[error("fixture failure: {hidden}")]
    Hidden {
        /// The text not to show.
        hidden: String,
    },
}

/// A record carrying [`FIXTURE_TEXT`].
#[uniffi::export]
pub fn redaction_fixture() -> RedactionFixture {
    RedactionFixture {
        hidden: FIXTURE_TEXT.to_owned(),
    }
}

/// A failure carrying [`FIXTURE_TEXT`].
///
/// # Errors
///
/// Always [`FixtureFailure::Hidden`].
#[uniffi::export]
pub fn redaction_fixture_failure() -> Result<(), FixtureFailure> {
    Err(FixtureFailure::Hidden {
        hidden: FIXTURE_TEXT.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixtures_carry_their_text() {
        assert_eq!(redaction_fixture().hidden, FIXTURE_TEXT);
        assert!(
            redaction_fixture_failure()
                .unwrap_err()
                .to_string()
                .contains(FIXTURE_TEXT)
        );
    }
}
