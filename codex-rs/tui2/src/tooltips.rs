use lazy_static::lazy_static;
use rand::Rng;

const RAW_CODEX_TOOLTIPS: &str = include_str!("../tooltips.txt");
const RAW_XCODEX_TOOLTIPS: &str = include_str!("../tooltips_xcodex.txt");

fn parse_tooltips(raw: &'static str) -> Vec<&'static str> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

lazy_static! {
    static ref CODEX_TOOLTIPS: Vec<&'static str> = parse_tooltips(RAW_CODEX_TOOLTIPS);
    static ref XCODEX_TOOLTIPS: Vec<&'static str> = parse_tooltips(RAW_XCODEX_TOOLTIPS);
}

pub(crate) fn random_tooltip() -> Option<&'static str> {
    let mut rng = rand::rng();
    pick_tooltip(&mut rng, CODEX_TOOLTIPS.as_slice())
}

pub(crate) fn random_xcodex_tooltip() -> Option<&'static str> {
    let mut rng = rand::rng();
    pick_tooltip(&mut rng, XCODEX_TOOLTIPS.as_slice())
}

fn pick_tooltip<R: Rng + ?Sized>(rng: &mut R, tooltips: &[&'static str]) -> Option<&'static str> {
    if tooltips.is_empty() {
        None
    } else {
        tooltips.get(rng.random_range(0..tooltips.len())).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn random_tooltip_returns_some_tip_when_available() {
        let mut rng = StdRng::seed_from_u64(42);
        assert!(pick_tooltip(&mut rng, CODEX_TOOLTIPS.as_slice()).is_some());
    }

    #[test]
    fn random_tooltip_is_reproducible_with_seed() {
        let expected = {
            let mut rng = StdRng::seed_from_u64(7);
            pick_tooltip(&mut rng, CODEX_TOOLTIPS.as_slice())
        };

        let mut rng = StdRng::seed_from_u64(7);
        assert_eq!(expected, pick_tooltip(&mut rng, CODEX_TOOLTIPS.as_slice()));
    }

    #[test]
    fn random_xcodex_tooltip_returns_some_tip_when_available() {
        let mut rng = StdRng::seed_from_u64(42);
        assert!(pick_tooltip(&mut rng, XCODEX_TOOLTIPS.as_slice()).is_some());
    }
}
