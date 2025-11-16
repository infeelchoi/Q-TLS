{
  "targets": [
    {
      "target_name": "qtls_native",
      "sources": [
        "src/qtls_binding.cc",
        "src/qtls_context.cc",
        "src/qtls_connection.cc",
        "src/qtls_crypto.cc"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "/usr/local/include",
        "/usr/include",
        "../../include"
      ],
      "libraries": [
        "-lqtls",
        "-loqs",
        "-lssl",
        "-lcrypto"
      ],
      "library_dirs": [
        "/usr/local/lib",
        "/usr/lib",
        "/usr/lib/x86_64-linux-gnu",
        "../../build"
      ],
      "cflags!": ["-fno-exceptions"],
      "cflags_cc!": ["-fno-exceptions"],
      "cflags": [
        "-Wall",
        "-Wextra",
        "-O3"
      ],
      "cflags_cc": [
        "-Wall",
        "-Wextra",
        "-O3",
        "-std=c++17"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS"
      ],
      "conditions": [
        [
          "OS=='linux'",
          {
            "cflags": [
              "-fPIC"
            ],
            "ldflags": [
              "-Wl,-rpath,'$$ORIGIN'"
            ]
          }
        ],
        [
          "OS=='mac'",
          {
            "xcode_settings": {
              "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
              "CLANG_CXX_LIBRARY": "libc++",
              "MACOSX_DEPLOYMENT_TARGET": "10.15",
              "OTHER_CFLAGS": [
                "-O3"
              ]
            }
          }
        ]
      ]
    }
  ]
}
