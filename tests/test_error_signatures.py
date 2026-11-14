from agentbox.executor import error_signature

NODE_A = (
    "/tmp/a/app.js:10\n    const x = obj.name.first;\n                       ^\n\n"
    "TypeError: Cannot read properties of undefined (reading 'first')\n"
    "    at Object.<anonymous> (/tmp/a/app.js:10:24)\n"
    "    at Module._compile (node:internal/modules/cjs/loader:1256:14)\n\n"
    "Node.js v20.11.0\n"
)
NODE_A_MOVED = (
    "/tmp/b/app.js:42\n    const y = obj.name.first;\n\n"
    "TypeError: Cannot read properties of undefined (reading 'first')\n"
    "    at Object.<anonymous> (/tmp/b/app.js:42:7)\n"
    "    at Module._compile (node:internal/modules/cjs/loader:1500:2)\n\n"
    "Node.js v22.1.0\n"
)
NODE_OTHER = (
    "ReferenceError: foo is not defined\n"
    "    at Object.<anonymous> (/tmp/a/app.js:3:1)\n\nNode.js v20.11.0\n"
)


def test_node_same_error_same_signature_despite_lines_and_paths():
    s1, c1 = error_signature(NODE_A, 1)
    s2, c2 = error_signature(NODE_A_MOVED, 1)
    assert c1 == c2 == "TypeError"
    assert s1 == s2


def test_node_different_errors_differ():
    assert error_signature(NODE_A, 1)[0] != error_signature(NODE_OTHER, 1)[0]


def test_node_error_code_is_part_of_class():
    text = ("Error [ERR_MODULE_NOT_FOUND]: Cannot find module '/tmp/a/foo.js'\n"
            "    at new NodeError (node:internal/errors:405:5)\n")
    assert error_signature(text, 1)[1] == "Error[ERR_MODULE_NOT_FOUND]"


GO_PANIC_1 = ("panic: runtime error: index out of range [5] with length 3\n\n"
              "goroutine 1 [running]:\nmain.main()\n\t/tmp/x/main.go:8 +0x1d\nexit status 2\n")
GO_PANIC_2 = ("panic: runtime error: index out of range [7] with length 4\n\n"
              "goroutine 1 [running]:\nmain.main()\n\t/tmp/y/main.go:21 +0x2f\nexit status 2\n")


def test_go_panic_numbers_normalized():
    s1, c1 = error_signature(GO_PANIC_1, 2)
    s2, c2 = error_signature(GO_PANIC_2, 2)
    assert c1 == c2 == "GoPanic"
    assert s1 == s2


def test_go_compile_error_ignores_line_numbers():
    a = "# command-line-arguments\n./main.go:5:2: undefined: foo\n"
    b = "# command-line-arguments\n./main.go:12:9: undefined: foo\n"
    sa, ca = error_signature(a, 1)
    assert ca == "GoCompileError"
    assert sa == error_signature(b, 1)[0]
    assert sa != error_signature("./main.go:5:2: undefined: bar\n", 1)[0]


def test_go_fatal_error():
    text = "fatal error: all goroutines are asleep - deadlock!\n\ngoroutine 1 [chan receive]:\n"
    assert error_signature(text, 2)[1] == "GoFatalError"


def test_python_still_works():
    text = ('Traceback (most recent call last):\n  File "main.py", line 1, in <module>\n'
            "    print(1/0)\nZeroDivisionError: division by zero\n")
    sig, cls = error_signature(text, 1)
    assert cls == "ZeroDivisionError" and sig.startswith("ZeroDivisionError:")


def test_success_has_no_signature():
    assert error_signature("warning: something", 0) == (None, None)


# --- Rust Tests -----------------------------------------------------------

RUST_PANIC_OLD = (
    "thread 'main' panicked at 'assertion failed: false', src/main.rs:14:5\n"
    "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\n"
)
RUST_PANIC_NEW = (
    "thread 'main' panicked at /workspace/other/lib.rs:99:12:\n"
    "assertion failed: false\n"
    "stack backtrace:\n"
    "   0: rust_begin_unwind\n"
)
RUST_PANIC_DIFF = (
    "thread 'main' panicked at 'index out of bounds: the len is 3 but the index is 5', src/main.rs:14:5\n"
)


def test_rust_panic_same_error_across_versions_paths_and_lines():
    s1, c1 = error_signature(RUST_PANIC_OLD, 101)
    s2, c2 = error_signature(RUST_PANIC_NEW, 101)
    assert c1 == c2 == "RustPanic"
    assert s1 == s2


def test_rust_panic_different_errors_differ():
    s1, _ = error_signature(RUST_PANIC_OLD, 101)
    s2, _ = error_signature(RUST_PANIC_DIFF, 101)
    assert s1 != s2


def test_rust_compile_error_ignores_lines_and_paths():
    c1 = (
        "error[E0308]: mismatched types\n"
        " --> src/main.rs:2:18\n"
        "  |\n"
        "2 |     let x: u32 = \"hello\";\n"
        "  |            ---   ^^^^^^^ expected `u32`, found `&str`\n"
    )
    c2 = (
        "error[E0308]: mismatched types\n"
        " --> /home/user/project/src/lib.rs:45:9\n"
        "  |\n"
        "45 |     let y: u32 = \"world\";\n"
    )
    s1, cls1 = error_signature(c1, 1)
    s2, cls2 = error_signature(c2, 1)
    assert cls1 == cls2 == "RustCompileError[E0308]"
    assert s1 == s2


def test_rust_different_compile_errors_differ():
    e1 = "error[E0308]: mismatched types\n --> src/main.rs:2:18\n"
    e2 = "error[E0425]: cannot find value `foo` in this scope\n --> src/main.rs:5:10\n"
    s1, cls1 = error_signature(e1, 1)
    s2, cls2 = error_signature(e2, 1)
    assert cls1 == "RustCompileError[E0308]"
    assert cls2 == "RustCompileError[E0425]"
    assert s1 != s2


# --- Java Tests -----------------------------------------------------------

JAVA_EX_1 = (
    'Exception in thread "main" java.lang.NullPointerException: Cannot invoke "String.length()" because "s" is null\n'
    "\tat com.example.Main.main(Main.java:5)\n"
)
JAVA_EX_2 = (
    'Exception in thread "main" java.lang.NullPointerException: Cannot invoke "String.length()" because "s" is null\n'
    "\tat org.other.Service.run(Service.java:120)\n"
    "\tat com.example.Main.main(Main.java:42)\n"
)
JAVA_EX_DIFF = (
    'Exception in thread "main" java.lang.IllegalArgumentException: Negative timeout value\n'
    "\tat com.example.Main.main(Main.java:10)\n"
)


def test_java_exception_same_across_lines_and_paths():
    s1, c1 = error_signature(JAVA_EX_1, 1)
    s2, c2 = error_signature(JAVA_EX_2, 1)
    assert c1 == c2 == "java.lang.NullPointerException"
    assert s1 == s2


def test_java_different_exceptions_differ():
    s1, _ = error_signature(JAVA_EX_1, 1)
    s2, _ = error_signature(JAVA_EX_DIFF, 1)
    assert s1 != s2


def test_java_caused_by_extracts_innermost_cause_across_different_lines():
    caused_1 = (
        'Exception in thread "main" java.lang.RuntimeException: Failed to execute\n'
        "\tat com.example.App.main(App.java:10)\n"
        "Caused by: java.io.FileNotFoundException: config.json (No such file or directory)\n"
        "\tat com.example.App.load(App.java:25)\n"
    )
    caused_2 = (
        'Exception in thread "main" java.util.concurrent.ExecutionException: java.lang.RuntimeException\n'
        "\tat java.base/java.util.concurrent.FutureTask.report(FutureTask.java:122)\n"
        "Caused by: java.lang.RuntimeException: Failed to execute\n"
        "\tat com.example.App.main(App.java:88)\n"
        "Caused by: java.io.FileNotFoundException: config.json (No such file or directory)\n"
        "\tat com.example.App.load(App.java:150)\n"
    )
    s1, c1 = error_signature(caused_1, 1)
    s2, c2 = error_signature(caused_2, 1)
    assert c1 == c2 == "java.io.FileNotFoundException"
    assert s1 == s2


def test_java_compile_error_ignores_lines_and_paths():
    j1 = "Main.java:3: error: cannot find symbol\n  System.out.println(foo);\n"
    j2 = "/src/com/App.java:42:10: error: cannot find symbol\n  System.out.println(bar);\n"
    s1, c1 = error_signature(j1, 1)
    s2, c2 = error_signature(j2, 1)
    assert c1 == c2 == "JavaCompileError[cannot find symbol]"
    assert s1 == s2


def test_java_different_compile_errors_differ():
    j1 = "Main.java:3: error: cannot find symbol\n"
    j2 = "Main.java:5: error: incompatible types: int cannot be converted to String\n"
    s1, c1 = error_signature(j1, 1)
    s2, c2 = error_signature(j2, 1)
    assert c1 == "JavaCompileError[cannot find symbol]"
    assert c2 == "JavaCompileError[incompatible types: int cannot be converted to String]"
    assert s1 != s2


# --- Ruby Tests -----------------------------------------------------------

RUBY_1 = (
    "main.rb:2:in 'divide': divided by 0 (ZeroDivisionError)\n"
    "\tfrom main.rb:5:in '<main>'\n"
)
RUBY_MOVED = (
    "/app/lib/calc.rb:45:in 'divide': divided by 0 (ZeroDivisionError)\n"
    "\tfrom /app/lib/calc.rb:100:in '<main>'\n"
)
RUBY_OLD_STYLE = (
    "main.rb:2:in `divide': divided by 0 (ZeroDivisionError)\n"
    "\tfrom main.rb:5:in `<main>'\n"
)
RUBY_DIFF = (
    "main.rb:2:in 'fetch': key not found: :id (KeyError)\n"
    "\tfrom main.rb:5:in '<main>'\n"
)


def test_ruby_same_across_lines_and_paths():
    s1, c1 = error_signature(RUBY_1, 1)
    s2, c2 = error_signature(RUBY_MOVED, 1)
    assert c1 == c2 == "ZeroDivisionError"
    assert s1 == s2


def test_ruby_quote_styles_match():
    s1, c1 = error_signature(RUBY_1, 1)
    s2, c2 = error_signature(RUBY_OLD_STYLE, 1)
    assert c1 == c2 == "ZeroDivisionError"
    assert s1 == s2


def test_ruby_backticks_in_error_message_match_single_quotes():
    ruby_msg_old = (
        "main.rb:3:in `<main>': undefined local variable or method `foo' for main:Object (NameError)\n"
    )
    ruby_msg_new = (
        "main.rb:3:in '<main>': undefined local variable or method 'foo' for main:Object (NameError)\n"
    )
    s1, c1 = error_signature(ruby_msg_old, 1)
    s2, c2 = error_signature(ruby_msg_new, 1)
    assert c1 == c2 == "NameError"
    assert s1 == s2


def test_ruby_different_errors_differ():
    s1, _ = error_signature(RUBY_1, 1)
    s2, _ = error_signature(RUBY_DIFF, 1)
    assert s1 != s2


# --- Generic Fallback & Cross-Language Non-Interference -------------------

def test_generic_fallback_for_unrecognized_output():
    unrelated = "curl: (7) Failed to connect to 127.0.0.1 port 8080: Connection refused\n"
    sig, cls = error_signature(unrelated, 7)
    assert sig is not None
    assert cls is None  # no recognized class, hashed last lines
