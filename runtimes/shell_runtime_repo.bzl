def _json_string(value):
    return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

# Coreutils-style tools that Bazel itself and common rule sets shell out to (for example
# tools/test/test-setup.sh, genrules and rules_python's script bootstrap). Each becomes a
# /usr/bin symlink to the static busybox when the runtime includes busybox.
_BUSYBOX_APPLETS = [
    "awk",
    "basename",
    "cat",
    "chmod",
    "cmp",
    "cp",
    "cut",
    "date",
    "diff",
    "dirname",
    "du",
    "echo",
    "egrep",
    "env",
    "expr",
    "false",
    "fgrep",
    "find",
    "grep",
    "gunzip",
    "gzip",
    "head",
    "id",
    "install",
    "ln",
    "ls",
    "md5sum",
    "mkdir",
    "mktemp",
    "mv",
    "od",
    "printf",
    "pwd",
    "readlink",
    "realpath",
    "rm",
    "rmdir",
    "sed",
    "seq",
    "sha1sum",
    "sha256sum",
    "sleep",
    "sort",
    "stat",
    "tail",
    "tar",
    "tee",
    "test",
    "touch",
    "tr",
    "true",
    "uname",
    "uniq",
    "unzip",
    "wc",
    "which",
    "whoami",
    "xargs",
    "yes",
    "zcat",
]

# Without busybox, /usr/bin/env is a stub that only resolves `env bash` and `env sh`.
_ENV_STUB = """#!/bin/bash
case "$1" in
  bash|sh)
    shift
    exec /bin/bash "$@"
    ;;
  *)
    printf 'actiond /usr/bin/env only supports "bash" or "sh"; got %q\\n' "$1" >&2
    exit 127
    ;;
esac
"""

def _extract_deb(rctx, url, sha256, output):
    rctx.download_and_extract(
        url = url,
        sha256 = sha256,
        output = output,
        type = ".deb",
    )
    for suffix in ["xz", "zst", "gz"]:
        data_archive = "%s/data.tar.%s" % (output, suffix)
        if rctx.path(data_archive).exists:
            rctx.extract(data_archive, output = "root")
            return
    fail("unsupported .deb payload compression for %s" % url)

def _shell_deb_runtime_impl(rctx):
    if len(rctx.attr.urls) != 1 or len(rctx.attr.sha256s) != 1:
        fail("shell_deb_runtime expects exactly one static shell package")
    if bool(rctx.attr.busybox_url) != bool(rctx.attr.busybox_sha256):
        fail("busybox_url and busybox_sha256 must be set together")

    _extract_deb(rctx, rctx.attr.urls[0], rctx.attr.sha256s[0], "deb")

    bash_static = rctx.path("root/bin/bash-static")
    if not bash_static.exists:
        fail("expected static bash payload at root/bin/bash-static")
    rctx.symlink(bash_static, "root/bin/bash")

    # Scripts with a `#!/bin/sh` shebang, such as rules_python's build-data writer, are
    # exec'd directly, so /bin/sh must exist.
    rctx.symlink(bash_static, "root/bin/sh")

    entries = [
        "d\tbin\t",
        "f\tbin/bash-static\t",
        "s\tbin/bash\t/bin/bash-static",
        "s\tbin/sh\t/bin/bash-static",
        "d\tusr\t",
        "d\tusr/bin\t",
    ]
    tree_srcs = ["root/bin/bash", "root/bin/bash-static", "root/bin/sh"]
    debs = [rctx.attr.urls[0]]

    if rctx.attr.busybox_url:
        _extract_deb(rctx, rctx.attr.busybox_url, rctx.attr.busybox_sha256, "busybox_deb")
        if not rctx.path("root/bin/busybox").exists:
            fail("expected static busybox payload at root/bin/busybox")
        entries.append("f\tbin/busybox\t")
        entries.extend(["s\tusr/bin/%s\t/bin/busybox" % applet for applet in _BUSYBOX_APPLETS])
        tree_srcs.append("root/bin/busybox")
        debs.append(rctx.attr.busybox_url)
    else:
        rctx.file("root/usr/bin/env", _ENV_STUB, executable = True)
        entries.append("f\tusr/bin/env\t")
        tree_srcs.append("root/usr/bin/env")

    rctx.file("squashfs_entries.txt", "\n".join(entries + [""]), executable = False)

    manifest = """{
  "name": %s,
  "arch": %s,
  "debs": [%s],
  "mounts": [
    ["root/bin", "/bin"],
    ["root/usr/bin", "/usr/bin"]
  ]
}
""" % (
        _json_string(rctx.attr.shell),
        _json_string(rctx.attr.arch),
        ", ".join([_json_string(url) for url in debs]),
    )
    rctx.file("runtime_manifest.json", manifest)

    rctx.file("BUILD.bazel", """
filegroup(
    name = "tree",
    srcs = %s,
    visibility = ["//visibility:public"],
)

exports_files([
    "runtime_manifest.json",
    "squashfs_entries.txt",
])
""" % repr(tree_srcs))

shell_deb_runtime = repository_rule(
    implementation = _shell_deb_runtime_impl,
    attrs = {
        "arch": attr.string(mandatory = True),
        "busybox_sha256": attr.string(),
        "busybox_url": attr.string(doc = "Optional busybox-static .deb whose applets are linked into /usr/bin."),
        "shell": attr.string(mandatory = True),
        "sha256s": attr.string_list(mandatory = True),
        "urls": attr.string_list(mandatory = True),
    },
)
