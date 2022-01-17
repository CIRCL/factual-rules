# factual-rules

Factual rules are [YARA](https://yara.readthedocs.io/en/stable/) rules to find legitimate software on raw disk acquisition.
The goal of the software is to be able to use a set of rules against collected or acquired digital forensic evidences and find installed software in a timely fashion.
All the rules are generated using [factual-rules-generator](https://github.com/CIRCL/factual-rules-generator).

## Source and origin of rules 

YARA rules present in this repository were generated using scripts hosted in the [factual-rules-generator repository](https://github.com/CIRCL/factual-rules-generator).
Additional, rules can be automatically created with `factural-rules-generator` and contributed it back to this repository.

## Rules directory format

YARA rules are in the [`/rules`](./rules/) directory and each folder follows the same pattern per software name:

- At the top level:

  - Installer name (such as `chocolatey`, `msiexec`, `exe`)
  - Following the execution of the installer 
    - two files, md5 and sha1 containing the hashes for each files created during the installation;
    - a folder with each hash in [Hashlookup](https://github.com/hashlookup/hashlookup-forensic-analyser) file format.

- At the second level, the installer folder:

  - Two rules extract from raw disk:
    - rule for installation part
    - rule for uninstallation part
  - one rule created with the software's executable
  - Folder containing 2 other rules created with the tree structure of raw disk:
    - tree rule for installation part
    - tree rule for uninstallation part

## Usage

Expect the executables rules, each rules has an external parameter called `ext_var`which needs to be specified.
This parameter represents the limit of strings to match with the entry file:  if a YARA rule contains 100 strings, if `ext_val` is set to 50, then, the entry file will match only the 50 strings with the YARA rule against the evidence. 

~~~bash
dacru@dacru:~/factual-rules$ yara -d ext_var=50 WinRAR_install.yar rawdisk_acquire.img
WinRAR_install rawdisk_acquire.img 
~~~

This result tells you that WinRAR was installed following the strings matches on the raw disk using the `WinRAR_install` rule.

## Benchmarking and testing factual rules search on acquired disk

To test the YARA rules, the software is installed in a virtual machine (as done in the generation), and change the virtual image into a raw format. 

The rules were tested on the disk without any additional action.

### Sample search result

~~~
Virtual machine setup and configuration: 

- Size of virtual machine: 32GB
- PC spec:
  -  i7-10850H CPU @ 2.70GHz
  - 32GB RAM
~~~

Result of the execution:

~~~
real	2m24.378s
user	1m55.829s
sys		0m9.271s
~~~

## Overview of factual rules generator and the YARA rules are generated 

![Overview of factual rules generator](https://github.com/CIRCL/factual-rules/blob/main/img/YaraRule.png?raw=true)

The source code of the [factual-rules-generator](https://github.com/CIRCL/factual-rules-generator) is open sourced.

## License

~~~
Copyright (C) 2021-2022 CIRCL - Computer Incident Response Center Luxembourg
Copyright (C) 2021-2022 David Cruciani

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
~~~










