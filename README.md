# factual-rules
YARA rules to find legitimate software



## Generation

Generation of all YARA rules present in this repository are generated using this code ([factual-rules-generator](https://github.com/CIRCL/factual-rules-generator)) created by CIRCL



## Rules

Each folder follow the same pattern:

- On top level of the folder:

  - installer name (chocolatey, msiexec, exe)

  - Depend on execution: 

    - two file, md5 and sha1, for each files created during this installation

    - a folder of each hash identified by [Hashlookup](https://github.com/hashlookup/hashlookup-forensic-analyser)

      

- On second level in installer folder:

  - 2 rules extract from raw disk:
    - rule for installation part
    - rule for uninstallation part
  - 1 rule created with the software's executable
  - folder containing 2 other rule created with the tree structure of raw disk:
    - tree rule for installation part
    - tree rule for uninstallation part



## Usage

Expect the executables rules, each rules has an external parameter which needs to be specified. This parameters represent the limit of rule to match with the entry file:  if a YARA rule contains 100 rule, if ext_val is set to 50, then, the entry file will match with the YARA rule if 50 rule match with the entry file.

~~~bash
dacru@dacru:~/factual-rules$ yara -d ext_var=50 WinRAR_install.yar winrar.img
WinRAR_install winrar.img
~~~



## Time Execution

To test YARA rules, the software is install in a virtual machine, just like the generation, and change into a raw format. The rule is apply on the disk without any additional action.

For the test, 

- Size of virtual machine: 32GB
- PC spec:
  -  i7-10850H CPU @ 2.70GHz
  - 32GB RAM

Time spent for the execution:

~~~
real	2m24.378s
user	1m55.829s
sys		0m9.271s
~~~















