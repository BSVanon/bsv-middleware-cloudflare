//! Release size witness: the verifier retains elements and an index, not the BEEF.
use bsv_middleware_core::{verify_brc29_payment_stream, LookupFn, MerkleRoot, SliceSource};
use bsv_sdk::primitives::{sha256d, Writer};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        ptr
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            let live = if new_size >= layout.size() {
                LIVE.fetch_add(new_size - layout.size(), Ordering::Relaxed) + new_size
                    - layout.size()
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed)
                    - (layout.size() - new_size)
            };
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        new_ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout);
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn transaction(parent: [u8; 32], unlock: &[u8], lock: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_i32_le(2)
        .write_var_int(1)
        .write_bytes(&parent)
        .write_u32_le(0)
        .write_var_bytes(unlock)
        .write_u32_le(u32::MAX)
        .write_var_int(1)
        .write_u64_le(1000)
        .write_var_bytes(lock)
        .write_u32_le(0);
    w.into_bytes()
}

#[tokio::test]
#[ignore = "run in release for the 64 MB allocation witness"]
async fn sixty_four_megabytes_in_64k_chunks_peak_below_four_megabytes() {
    let doc: serde_json::Value =
        serde_json::from_str(include_str!("../conformance/brc29-payment-vectors.json")).unwrap();
    let case = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "exact-amount")
        .unwrap();
    let get = |key: &str| case[key].as_str().unwrap();
    let derived = hex::decode(
        bsv_middleware_core::expected_locking_script(
            get("server_private_key"),
            get("sender_identity_key"),
            get("derivation_prefix"),
            get("derivation_suffix"),
        )
        .unwrap(),
    )
    .unwrap();
    let parent = transaction([0xaa; 32], &[], &[0x75, 0x51]);
    let root = sha256d(&parent);
    let mut previous = root;
    let mut w = Writer::new();
    w.write_u32_le(0xefbe_0002)
        .write_var_int(1)
        .write_var_int(800_000)
        .write_bytes(&[1, 1, 0, 2])
        .write_bytes(&root)
        .write_var_int(65)
        .write_bytes(&[1, 0])
        .write_bytes(&parent);
    let mut unlock = vec![0x4e];
    unlock.extend((1_000_000u32).to_le_bytes());
    unlock.resize(1_000_005, 7);
    for i in 0..64 {
        let lock = if i == 63 {
            derived.as_slice()
        } else {
            &[0x75, 0x51]
        };
        let raw = transaction(previous, &unlock, lock);
        previous = sha256d(&raw);
        w.write_u8(0).write_bytes(&raw);
    }
    let bytes = w.into_bytes();
    drop(unlock);
    let mut shown = root;
    shown.reverse();
    let root_hex = hex::encode(shown);
    let service = LookupFn(|_| std::future::ready(Ok(Some(MerkleRoot::new(root_hex.clone())))));
    let baseline_sdk = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline_sdk, Ordering::Relaxed);
    let sdk = bsv_sdk::transaction::verify_stream(
        bytes.as_slice(),
        bsv_sdk::transaction::beef_stream::HeadersFn(|_: u64, _: &[u8; 32]| true),
        None,
    )
    .unwrap();
    assert!(sdk.is_valid());
    let sdk_peak = PEAK.load(Ordering::Relaxed) - baseline_sdk;
    println!("SDK_STREAM_MEMORY incremental_peak_bytes={sdk_peak}");
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let result = verify_brc29_payment_stream(
        get("server_private_key"),
        get("sender_identity_key"),
        get("derivation_prefix"),
        get("derivation_suffix"),
        &mut SliceSource::new(&bytes),
        0,
        1000,
        Some(&service),
        None,
    )
    .await
    .unwrap();
    let peak = PEAK.load(Ordering::Relaxed) - baseline;
    assert!(result.is_ok(), "{result:?}");
    println!(
        "STREAM_MEMORY body_bytes={} incremental_peak_bytes={peak}",
        bytes.len()
    );
    assert!(peak < 4 * 1024 * 1024, "peak {peak}");
}
