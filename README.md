<!-- OpenWRT Declarative Image Builder
     https://github.com/gucci-on-fleek/openwrt-builder-template
     SPDX-License-Identifier: MPL-2.0+ OR CC-BY-SA-4.0+
     SPDX-FileCopyrightText: 2024 Max Chernoff -->

# OpenWRT Declarative Image Builder

This is a template repository for building OpenWRT images using a
declarative TOML configuration file.

## About

For every image that you want to build, just add a corresponding
`.conf.toml` file to the repository. Then, for every commit, a GitHub
action will automatically build the images and upload them as new
releases.

## Usage

```sh
$ ./build.py --help
usage: build.py [-h] (-e text | -d text | --keygen | filename)

positional arguments:
  filename            The config file to build

options:
  -h, --help          show this help message and exit
  -e, --encrypt text  Encrypt a string
  -d, --decrypt text  Decrypt a string
  --keygen            Generate a new key

environment variables:
  $OPENWRT_KEY          The key to use for encryption
```

See the [`sample.conf.toml`](sample.conf.toml) file for an example
configuration.


## Licence

The contents of this repository are licensed under the [_Mozilla Public
License_, version 2.0](https://www.mozilla.org/en-US/MPL/2.0/) or
greater. The documentation is additionally licensed under [CC-BY-SA,
version 4.0](https://creativecommons.org/licenses/by-sa/4.0/legalcode)
or greater, and the template file is public domain.
