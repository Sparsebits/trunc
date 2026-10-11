//! Resuming from a safe point (picked by the input), with the input before it zeroed and the
//! window read back from the output so far, gives the rest of the output and meets the same
//! later safe points. The first pass and the resumed one may use different thread counts.

#![no_main]
use libfuzzer_sys::fuzz_target;
use trunc_legacy::stream::NoHistory;

#[path = "common/units.rs"]
mod units;

fuzz_target!(|data: &[u8]| {
    let Some(case) = units::build(data) else {
        return;
    };
    let codec = case.codec;
    let every = case.every.max(1);
    let threads = |bit: u8| if case.extra & bit != 0 { 4 } else { 1 };
    let first = units::decode(codec, &case.input, None, &mut NoHistory, threads(1), every);
    units::check_points(codec, &first.points, case.input.len(), first.out.len());
    // Only points whose cursor the run kept can be resumed from (all of them unless there are
    // very many; see `units::Point`).
    let kept: Vec<usize> = (0..first.points.len())
        .filter(|&i| first.points[i].cursor.is_some())
        .collect();
    if kept.is_empty() {
        return;
    }
    let pick = kept[usize::from(case.extra >> 2) % kept.len()];
    let point = &first.points[pick];
    let at = usize::try_from(point.out).unwrap();
    let mut punched = case.input.clone();
    punched[..usize::try_from(point.free_below).unwrap()].fill(0);
    let rest = units::decode(
        codec,
        &punched,
        point.cursor.as_deref(),
        &mut units::VecHistory(&first.out[..at]),
        threads(2),
        every,
    );
    let later = &first.points[pick + 1..];
    match (&first.end, &rest.end) {
        (Ok(a), Ok(b)) => {
            assert!(
                rest.out == first.out[at..],
                "{codec:?}: resume at {at} differs"
            );
            assert_eq!(
                a.out_len, b.out_len,
                "{codec:?}: resume at {at} ends elsewhere"
            );
            assert!(
                rest.points[..] == *later,
                "{codec:?}: resume at {at} meets other safe points"
            );
        }
        (Err(_), Err(_)) => {
            assert!(
                units::prefix_consistent(&rest.out, &first.out[at..]),
                "{codec:?}: resume at {at} gives other output before the error"
            );
            assert!(
                units::prefix_consistent(&rest.points, later),
                "{codec:?}: resume at {at} meets other safe points before the error"
            );
        }
        (Ok(_), Err(e)) => panic!("{codec:?}: resume at {at} failed: {e}"),
        (Err(e), Ok(_)) => {
            panic!("{codec:?}: resume at {at} succeeded where the full decode failed: {e}")
        }
    }
});
