import ctypes.util as cutil
import distutils.log as distlog
import os
import subprocess
import sys

from setuptools import Command
from setuptools import setup
from setuptools.command.build_py import build_py as BuildPyCommand
from setuptools.command.test import test as TestCommand

PACKAGE = 'ntruencrypt'
LIBNAME = 'libntruencrypt'

if os.name == 'nt':  # Windows
    LIB_SUFFIX = '.dll'
elif os.name == 'posix':  # Linux & Mac
    # os.system("/bin/bash compile_dependencies.sh")
    LIB_SUFFIX = sys.platform == '.dylib' if sys.platform == 'darwin' else '.so'
else:
    raise Exception("Unknown operating system")

LIB_PATH = PACKAGE + '/' + LIBNAME + LIB_SUFFIX


class BuildExternalDependenciesCommand(Command):
    description = 'build external dependencies'
    user_options = [
        ('build-force=', None, 'force external depedency building'),
    ]

    def initialize_options(self):
        """Set default values for options."""
        # Each user option must be listed here with their default value.
        self.build_force = False

    def finalize_options(self):
        pass

    def _check_installed(self):
        self.debug_print("Installation check")
        if cutil.find_library(LIBNAME[3:]) is not None:
            self.debug_print("Found installed library")
            return True
        self.debug_print("Cannot find installed library %s" % LIBNAME[3:])
        if os.path.isfile(LIB_PATH):
            self.debug_print("Found local library")
            return True
        self.debug_print("Cannot find local library at '%s'" % LIB_PATH)
        return False

    def run(self):
        """Run command."""
        if self.build_force:
            self.announce("Forcing compilation")
        elif self._check_installed():
            self.announce("External dependencies already installed", distlog.INFO)
            return

        command = ['/bin/bash', 'compile_dependencies.sh']

        self.announce('Running command: %s' % str(command), distlog.INFO)
        subprocess.check_call(command)


class CustomTestCommand(TestCommand):
    def run(self):
        self.distribution.run_command('build_ext')
        super().run()


class CustomBuildCommand(BuildPyCommand):
    def run(self):
        self.distribution.run_command('build_ext')
        super().run()


setup(
    name='ntruencrypt',
    version='1.0',
    description='A libntruencrypt python wrapper',
    url='https://github.com/SnowyCoder/ntruencryptlib-wrapper',
    author='Rossi Lorenzo',
    author_email='rossilorenzo@mail.com',
    license='MIT',
    keywords='NTRU Encryption python3 lattice asymmetrical',
    packages=[PACKAGE],
    include_package_data=True,
    data_files=[('', [LIB_PATH])],
    test_suite="tests",
    project_urls={
        'Source': 'https://github.com/SnowyCoder/ntruencryptlib-wrapper',
        'Tracker': 'https://github.com/SnowyCoder/ntruencryptlib-wrapper/issues',
    },
    cmdclass={
        'test': CustomTestCommand,
        'build_py': CustomBuildCommand,
        'build_ext': BuildExternalDependenciesCommand
    }
)
