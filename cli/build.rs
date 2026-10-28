use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let root = manifest.parent().expect("repository root");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let target = env::var("TARGET").expect("TARGET");
    let apple_ios = target == "aarch64-apple-ios";
    let target_key = target.replace('-', "_");
    let cc = env::var_os(format!("CC_{target_key}"))
        .or_else(|| env::var_os("CC"))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            if apple_ios {
                let output = Command::new("xcrun")
                    .args(["--sdk", "iphoneos", "--find", "clang"])
                    .output()
                    .expect("xcrun is required to build the iOS planner");
                assert!(
                    output.status.success(),
                    "xcrun could not find the iPhoneOS compiler"
                );
                PathBuf::from(
                    String::from_utf8(output.stdout)
                        .expect("xcrun path is UTF-8")
                        .trim(),
                )
            } else {
                PathBuf::from("cc")
            }
        });
    let ar = env::var_os(format!("AR_{target_key}"))
        .or_else(|| env::var_os("AR"))
        .unwrap_or_else(|| "ar".into());
    let sources = [
        "native/src/iu_execution_planner.c",
        "native/src/iu_artifact_provenance.c",
        "native/src/iu_launch_binding.c",
        "native/src/iu_policy_store.c",
        "native/src/iu_amethyst_adapter.c",
        "native/src/iu_amethyst_capabilities.c",
        "native/src/iu_policy.c",
        "native/src/iu_preflight.c",
    ];
    for header in [
        "native/include/iu_execution_planner.h",
        "native/include/iu_artifact_provenance.h",
        "native/include/iu_launch_binding.h",
        "native/include/iu_policy_store.h",
        "native/include/iu_amethyst_adapter.h",
        "native/include/iu_amethyst_capabilities.h",
        "native/include/iu_policy.h",
        "native/include/iu_preflight.h",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(header).display());
    }
    let mut objects = Vec::new();
    for (index, source) in sources.iter().enumerate() {
        println!("cargo:rerun-if-changed={}", root.join(source).display());
        let object = out.join(format!("planner-{index}.o"));
        let mut command = Command::new(&cc);
        command
            .current_dir(root)
            .arg("-std=c17")
            .arg("-O2")
            .arg("-fPIC")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Wpedantic")
            .arg("-Werror")
            .arg("-Inative/include")
            .arg("-c")
            .arg(source)
            .arg("-o")
            .arg(&object);
        if apple_ios {
            command.arg("-target").arg("arm64-apple-ios12.0");
            if let Some(sdk) = env::var_os("SDKROOT") {
                command.arg("-isysroot").arg(sdk);
            }
        }
        let status = command.status().expect("start native planner compiler");
        assert!(status.success(), "failed to compile {source}");
        objects.push(object);
    }
    let archive = out.join("libiu_planner.a");
    let status = Command::new(ar)
        .arg("crus")
        .arg(&archive)
        .args(&objects)
        .status()
        .expect("start archive tool");
    assert!(status.success(), "failed to create planner archive");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=iu_planner");
}
