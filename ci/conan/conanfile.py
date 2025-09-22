from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout
from conan.tools.build import check_max_cppstd, check_min_cppstd
from conan.tools.files import copy
from conan.tools.scm import Git


class LogfaultConan(ConanFile):
    name = "logfault"
    version = "0.5.2"
    settings = "os", "arch", "compiler", "build_type"
    exports_sources = "include/*", "tests/*", "CMakeLists.txt"
    no_copy_source = True
    generators = "CMakeDeps"

    def package(self):
        # This will also copy the "include" folder
        copy(self, "*.h", self.source_folder, self.package_folder)

    def package_info(self):
        # For header-only packages, libdirs and bindirs are not used
        # so it's necessary to set those as empty.
        self.cpp_info.bindirs = []
        self.cpp_info.libdirs = []

    def requirements(self):
        if not self.conf.get("tools.build:skip_test", default=False):
            self.test_requires("gtest/1.14.0")

    def validate(self):
        check_min_cppstd(self, 14)

    def layout(self):
        cmake_layout(self)

    def generate(self):
        tc = CMakeToolchain(self)
        if not self.conf.get("tools.build:skip_test", default=False):
            tc.variables["LOGFAULT_BUILD_TESTS"] = "ON"
        tc.generate()

    def build(self):
        if not self.conf.get("tools.build:skip_test", default=False):
            cmake = CMake(self)
            cmake.configure()
            cmake.build()
            cmake.test()

    def package(self):
        # This will also copy the "include" folder
        copy(self, "LICENSE", self.source_folder, self.package_folder)
        copy(self, "*.h", self.source_folder, self.package_folder)

    def package_info(self):
        # For header-only packages, libdirs and bindirs are not used
        # so it's necessary to set those as empty.
        self.cpp_info.bindirs = []
        self.cpp_info.libdirs = []

    def package_id(self):
        self.info.clear()
