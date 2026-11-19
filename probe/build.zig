const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    var query = target.query;
    if (target.result.cpu.arch == .x86_64) {
        // Use core2 CPU model for SSE2 without AVX (max compatibility)
        query.cpu_model = .{ .explicit = &std.Target.x86.cpu.core2 };
        query.cpu_features_add = std.Target.Cpu.Feature.Set.empty;
        query.cpu_features_sub = std.Target.Cpu.Feature.Set.empty;
    }
    const modified_target = b.resolveTargetQuery(query);

    // Generate an embedded version module from the root VERSION file.
    // Use a Run step so that changes to ../VERSION invalidate the build cache.
    const gen_version = b.addSystemCommand(&.{"../scripts/gen_version.sh"});
    gen_version.addFileArg(b.path("../VERSION"));
    const version_path = gen_version.addOutputFileArg("version_embed.zig");
    const version_module = b.createModule(.{
        .root_source_file = version_path,
    });

    // Install the third-party license notice next to the binary.
    const install_license = b.addInstallFile(b.path("LICENSE-THIRD-PARTY.txt"), "bin/LICENSE-THIRD-PARTY.txt");
    b.getInstallStep().dependOn(&install_license.step);

    // iperf3's own upstream LICENSE, verbatim and standalone (not just
    // summarized/embedded in LICENSE-THIRD-PARTY.txt above) -- see
    // probe/iperf3_license.txt and probe/LICENSE-THIRD-PARTY.txt's iperf3
    // entry, which points here for the full text.
    const install_iperf3_license = b.addInstallFile(b.path("iperf3_license.txt"), "bin/iperf3_license.txt");
    b.getInstallStep().dependOn(&install_iperf3_license.step);

    // Rooted at probe/ (not probe/src/) so its @embedFile calls can reach
    // the sibling iperf3-linux-static/, iperf3-win-patch/, and
    // iperf3_license.txt -- see embedded_assets.zig's own comment and
    // src/iperf3_embedded.zig, which imports this module.
    const embedded_assets_module = b.createModule(.{
        .root_source_file = b.path("embedded_assets.zig"),
    });

    const root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = modified_target,
        .optimize = optimize,
    });
    root_module.addImport("version_embed", version_module);
    root_module.addImport("embedded_assets", embedded_assets_module);

    const exe = b.addExecutable(.{
        .name = "linknesis-probe",
        .root_module = root_module,
        .win32_manifest = b.path("src/linknesis.manifest"),
    });

    exe.linkLibC();

    if (target.result.os.tag == .windows) {
        exe.subsystem = .Windows;
        exe.linkSystemLibrary("iphlpapi");
        exe.linkSystemLibrary("ws2_32");
        exe.linkSystemLibrary("gdi32");

        // Install the tray/window icon next to the Windows executable.
        const install_icon = b.addInstallFile(b.path("src/linknesis.ico"), "bin/linknesis.ico");
        b.getInstallStep().dependOn(&install_icon.step);
    } else {
        exe.linkSystemLibrary("ssl");
        exe.linkSystemLibrary("crypto");
    }

    b.installArtifact(exe);

    // Unit tests. Rooted at a single file each (like core/build.zig's
    // auth_tests/thresholds_tests), but wss_client.zig and iperf3_runner.zig
    // import each other plus most of the rest of the probe (config,
    // ip_discovery, dns, mtr, platform, license_error, version, updater) via
    // plain relative @imports, so each test binary still pulls in nearly the
    // same dependency graph as the real probe executable and needs the same
    // libs/target-specific imports as `exe` above.
    const wss_client_test_module = b.createModule(.{
        .root_source_file = b.path("src/wss_client.zig"),
        .target = modified_target,
        .optimize = optimize,
    });
    wss_client_test_module.addImport("version_embed", version_module);
    const wss_client_tests = b.addTest(.{ .root_module = wss_client_test_module });
    wss_client_tests.linkLibC();
    if (target.result.os.tag == .windows) {
        wss_client_tests.linkSystemLibrary("iphlpapi");
        wss_client_tests.linkSystemLibrary("ws2_32");
        wss_client_tests.linkSystemLibrary("gdi32");
    } else {
        wss_client_tests.linkSystemLibrary("ssl");
        wss_client_tests.linkSystemLibrary("crypto");
    }
    const run_wss_client_tests = b.addRunArtifact(wss_client_tests);

    const iperf3_runner_test_module = b.createModule(.{
        .root_source_file = b.path("src/iperf3_runner.zig"),
        .target = modified_target,
        .optimize = optimize,
    });
    iperf3_runner_test_module.addImport("version_embed", version_module);
    const iperf3_runner_tests = b.addTest(.{ .root_module = iperf3_runner_test_module });
    iperf3_runner_tests.linkLibC();
    if (target.result.os.tag == .windows) {
        iperf3_runner_tests.linkSystemLibrary("iphlpapi");
        iperf3_runner_tests.linkSystemLibrary("ws2_32");
        iperf3_runner_tests.linkSystemLibrary("gdi32");
    } else {
        iperf3_runner_tests.linkSystemLibrary("ssl");
        iperf3_runner_tests.linkSystemLibrary("crypto");
    }
    const run_iperf3_runner_tests = b.addRunArtifact(iperf3_runner_tests);

    // config.zig has no external @imports of its own (no c.zig, no
    // version_embed), so its test module needs no extra libs.
    const config_test_module = b.createModule(.{
        .root_source_file = b.path("src/config.zig"),
        .target = modified_target,
        .optimize = optimize,
    });
    const config_tests = b.addTest(.{ .root_module = config_test_module });
    const run_config_tests = b.addRunArtifact(config_tests);

    // mtr.zig imports wss_client.zig (circular, like iperf3_runner.zig) and
    // config.zig, so it needs the same libs/version_embed import as exe.
    const mtr_test_module = b.createModule(.{
        .root_source_file = b.path("src/mtr.zig"),
        .target = modified_target,
        .optimize = optimize,
    });
    mtr_test_module.addImport("version_embed", version_module);
    const mtr_tests = b.addTest(.{ .root_module = mtr_test_module });
    mtr_tests.linkLibC();
    if (target.result.os.tag == .windows) {
        mtr_tests.linkSystemLibrary("iphlpapi");
        mtr_tests.linkSystemLibrary("ws2_32");
        mtr_tests.linkSystemLibrary("gdi32");
    } else {
        mtr_tests.linkSystemLibrary("ssl");
        mtr_tests.linkSystemLibrary("crypto");
    }
    const run_mtr_tests = b.addRunArtifact(mtr_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_wss_client_tests.step);
    test_step.dependOn(&run_iperf3_runner_tests.step);
    test_step.dependOn(&run_config_tests.step);
    test_step.dependOn(&run_mtr_tests.step);
}
