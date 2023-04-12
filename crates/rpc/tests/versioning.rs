//! This test was separated because the `metrics` crate uses a singleton recorder, so keeping a test
//! that relies on metric values in a separate binary makes more sense than using an inter-test
//! locking mechanism which can cause weird test failures without any obvious clue to what might
//! have caused those failures in the first place.

#[tokio::test]
async fn api_versions_are_routed_correctly_for_all_methods() {
    use pathfinder_common::test_utils::metrics::{FakeRecorder, RecorderGuard};
    use pathfinder_rpc::test_client::TestClientBuilder;
    use pathfinder_rpc::versioning::test_utils::{method_names, paths};
    use pathfinder_rpc::{context::RpcContext, metrics::logger::RpcMetricsLogger, RpcServer};
    use serde_json::json;

    let context = RpcContext::for_tests();
    let (_server_handle, address) = RpcServer::new("127.0.0.1:0".parse().unwrap(), context)
        .with_logger(RpcMetricsLogger)
        .run()
        .await
        .unwrap();

    let v02_methods = method_names::COMMON_FOR_V02_V03
        .into_iter()
        .chain(method_names::COMMON_FOR_ALL.into_iter())
        .collect::<Vec<_>>();
    let v03_methods = v02_methods
        .clone()
        .into_iter()
        .chain(method_names::V03_ONLY.into_iter())
        .collect::<Vec<_>>();
    let pathfinder_methods = method_names::COMMON_FOR_ALL
        .into_iter()
        .chain(method_names::PATHFINDER_ONLY.into_iter())
        .collect();

    for (paths, version, methods) in vec![
        (paths::V02, "v0.2", v02_methods),
        (paths::V03, "v0.3", v03_methods),
        (paths::PATHFINDER, "v0.1", pathfinder_methods),
    ]
    .into_iter()
    {
        let recorder = FakeRecorder::default();
        let handle = recorder.handle();
        // Other concurrent tests could be setting their own recorders
        let guard = RecorderGuard::lock(recorder);

        let paths_len = paths.len();
        let paths_iter = paths.iter();

        // Perform all the calls but don't assert the results just yet
        for path in paths_iter.clone().map(ToOwned::to_owned) {
            let client = TestClientBuilder::default()
                .address(address)
                .endpoint(path.into())
                .build()
                .unwrap();

            for method in methods.iter() {
                let res = client.request::<serde_json::Value>(method, json!([])).await;

                match res {
                    Err(jsonrpsee::core::Error::Call(
                        jsonrpsee::types::error::CallError::Custom(e),
                    )) if e.code() == jsonrpsee::types::error::METHOD_NOT_FOUND_CODE => {
                        // Don't poison the internal lock
                        drop(guard);
                        panic!("Unregistered method called, path: {path}, method: {method}")
                    }
                    Ok(_) | Err(_) => {}
                }
            }
        }

        // Drop the global recorder guard to avoid poisoning its internal lock if
        // the following asserts fail which would fail other tests using the `RecorderGuard`
        // at the same time.
        //
        // The recorder itself still exists since dropping the guard only unregisters the recorder
        // and leaks it making the handle still valid past this point.
        drop(guard);

        // Now we can safely assert all results
        for path in paths_iter.clone() {
            for method in methods.iter() {
                let expected_counter = paths_len as u64;
                let actual_counter = handle.get_counter_value_by_label(
                    "rpc_method_calls_total",
                    [("method", method), ("version", version)],
                );
                assert_eq!(
                    actual_counter, expected_counter,
                    "path: {path}, method: {method}"
                );
            }
        }
    }
}
