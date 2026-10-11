//! Decoding with threads gives the same result as without: the same output, safe points and
//! end when it succeeds, and a failure (with the same output and safe points before it) when it
//! does not.

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
    let one = units::decode(codec, &case.input, None, &mut NoHistory, 1, case.every);
    let four = units::decode(codec, &case.input, None, &mut NoHistory, 4, case.every);
    units::check_points(codec, &one.points, case.input.len(), one.out.len());
    match (&one.end, &four.end) {
        (Ok(a), Ok(b)) => {
            assert!(
                one.out == four.out,
                "{codec:?}: output differs with threads"
            );
            assert!(
                one.points == four.points,
                "{codec:?}: safe points differ with threads"
            );
            assert_eq!(a, b, "{codec:?}: end differs with threads");
        }
        (Err(_), Err(_)) => {
            // Each may stop at a different spot, but what came before is the same.
            assert!(
                units::prefix_consistent(&one.out, &four.out),
                "{codec:?}: output before the error differs with threads"
            );
            assert!(
                units::prefix_consistent(&one.points, &four.points),
                "{codec:?}: safe points before the error differ with threads"
            );
        }
        (a, b) => panic!("{codec:?}: 1 thread gives {a:?}, 4 threads give {b:?}"),
    }
});
