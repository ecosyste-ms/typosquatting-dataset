# Typosquatting Dataset

A curated dataset of package-name pairs from public typosquatting research and detection tests. Includes reported attacks, research demonstrations, and synthetic examples with ecosystem, classification, and source attribution.

Useful for testing [typosquatting detection tools](https://github.com/andrew/typosquatting) and integration into [packages.ecosyste.ms](https://packages.ecosyste.ms).

## Data Format

The `typosquats.csv` file contains:

| Field | Description |
|-------|-------------|
| malicious_package | The variant name; this existing column name does not imply that every entry contains malware |
| target_package | The legitimate package being squatted |
| ecosystem | Package ecosystem (pypi, npm, crates.io, go, github_actions, rubygems, maven, nuget) |
| registry | Registry URL |
| classification | Typosquatting technique used |
| source | Data source attribution |

## Classification Types

These classifications describe name transformations using the categories in [andrew/typosquatting](https://github.com/andrew/typosquatting#algorithms). They describe the spelling relationship, without attributing a cause or intent. A generator's supported characters and affixes may cover only part of a category.

| Classification | Description | Example |
|----------------|-------------|---------|
| omission | Drop single characters | requests -> reqests |
| repetition | Double characters | requests -> rrequests |
| replacement | Adjacent keyboard characters | requests -> requezts |
| transposition | Swap adjacent characters | requests -> reqeusts |
| addition | Insert characters at start/end | requests -> arequests |
| homoglyph | Lookalike characters (l/1, 0/O, e/3) | requests -> reque5ts |
| vowel_swap | Swap vowels | requests -> raquests |
| delimiter | Change/add/remove - _ . | my-package -> my_package |
| word_order | Reorder words | foo-bar -> bar-foo |
| plural | Singularize/pluralize | request -> requests |
| misspelling | Common typos | library -> libary |
| numeral | Number/word swap | lib2 -> libtwo |
| bitflip | Single-bit errors (bitsquatting) | google -> coogle |
| adjacent_insertion | Insert adjacent keyboard key | google -> googhle |
| double_hit | Replace double chars with adjacent | google -> giigle |
| combosquatting | Add package prefixes or suffixes | lodash -> lodash-js |
| other | Combined edits or transformations outside the categories above | npm-run-all -> npmrunnall |

## Summary

This dataset contains 167 name pairs. Research demonstrations and synthetic examples are included because they exercise the same name comparisons as reported attacks. Inclusion does not establish that a package is malicious or that every version was affected.

**By ecosystem:** PyPI (95), npm (37), RubyGems (15), Go (10), GitHub Actions (8), crates.io (2)

**By classification:** other (62), replacement (16), omission (15), transposition (13), repetition (10), addition (10), combosquatting (8), delimiter (7), vowel_swap (6), plural (5), bitflip (5), homoglyph (4), adjacent_insertion (4), word_order (2)

Apply registry rules when using these pairs to test a detector. For example, PyPI treats `my_package`, `my.package`, and `my-package` as [the same normalized name](https://packaging.python.org/en/latest/specifications/name-normalization/). Those rows exercise delimiter transformations, but do not describe separately registrable packages.

Some inherited pairs need context beyond spelling. [Pillow-SIMD](https://pypi.org/project/pillow-simd/) is a Pillow fork. The `torchtriton` row preserves a prefix comparison with `triton`; the [documented incident](https://pytorch.org/blog/compromised-nightly-dependency/) involved dependency confusion between registries using the same `torchtriton` name. `npm-cli-flag` is a placeholder target for two packages named after command-line options.

The GitHub Actions examples added from [zizmor's typosquat-uses audit](https://github.com/zizmorcore/zizmor/pull/1985) are synthetic test cases. Its fixtures also include `actions/chckout` as a negative case against `actions/checkout`, because the owner is unchanged. That distinction is useful when testing namespace-aware detection alongside raw spelling comparisons.

## Data Sources

### Primary Malicious Package Databases

**[ossf/malicious-packages](https://github.com/ossf/malicious-packages)**
OpenSSF database of malicious packages in OSV format. Covers PyPI, npm, crates.io, Go, Maven, NuGet, RubyGems, and VSCode extensions. Contains thousands of documented malicious packages with detailed incident reports.

**[lxyeternal/pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry)**
~10,000 malicious PyPI packages from the ASE 2023 paper "An Empirical Study of Malicious Code In PyPI Ecosystem." Includes many typosquatting variants of popular packages like BeautifulSoup, PyTorch, Matplotlib, and requests.

**[DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset)**
17,367 human-vetted malicious packages for npm and PyPI. Samples stored as encrypted ZIPs with manifest files for quick lookups. Distinguishes between compromised legitimate packages and purpose-built malicious packages.

**[Backstabber's Knife Collection](https://dasfreak.github.io/Backstabbers-Knife-Collection/)**
Research dataset from Ohm et al. covering npm, PyPI, and RubyGems. Contains samples from actual attacks since 2015. Access restricted to researchers with institutional email.

Reference: Ohm et al. (2020) "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks" ([paper](https://dl.acm.org/doi/10.1007/978-3-030-65745-1_7))

### Detection Tools and Research

**[IQTLabs/pypi-scan](https://github.com/IQTLabs/pypi-scan)**
Typosquatting detection tool for PyPI using Levenshtein distance, name reordering, and homophone detection. Identified real typosquats including "pandar" (pandas), "prompt-tool-kit" (prompt-toolkit), and "requestsaa" (requests). Archived January 2023.

Documentation: [pypi-scan.readthedocs.io](https://pypi-scan.readthedocs.io/en/latest/)

**[rustfoundation/typomania-crates](https://github.com/rustfoundation/typomania-crates)**
Rust Foundation tool for detecting typosquatting in crates.io using the typomania crate. Integrates with spaCy for additional NLP-based false positive reduction.

### Incident Documentation

**[Karneades/PackAttack](https://github.com/Karneades/PackAttack)**
Documentation of package manager attacks (typosquatting, dependency confusion) from 2017-2023 across PyPI, npm, RubyGems, and PowerShell Gallery. Notable incidents include the crossenv npm attack (2017), urllib PyPI typosquat (2017), and torchtriton dependency confusion (2023).

**[RH-ISAC: Typosquatting Campaign March 2024](https://rhisac.org/threat-intelligence/typosquatting-campaign-targets-python-developers-with-hundreds-of-malicious-libraries/)**
Campaign deploying 566 malicious packages targeting popular PyPI libraries including requests (36 variants), colorama (35), tensorflow (29), BeautifulSoup (26), PyTorch (26), and others. Packages contained zgRAT malware.

**[PyPI Warehouse Issue #9527](https://github.com/pypi/warehouse/issues/9527)**
Proposal for "social distancing" rules blocking similar names to top packages. References analysis of 40 historical typosquatting attacks, finding 18 had Levenshtein distance of 2 or less from their targets.

**[Socket: Typosquatted Go Packages](https://socket.dev/blog/typosquatted-go-packages-deliver-malware-loader)**
Seven malicious Go packages impersonating github.com/areknoster/hypert and github.com/loov/layout libraries. Used array-based obfuscation to hide shell commands that download and execute malware loaders targeting Linux and macOS.

**[Orca Security: GitHub Actions Typosquatting](https://orca.security/resources/blog/typosquatting-in-github-actions/)**
Research demonstrating GitHub Actions organization typosquatting. Created proof-of-concept organizations like "actons" (targeting "actions"), "circelci" (targeting "circleci"), and "aws-action" (targeting "aws-actions"). Found 158+ repositories referencing the "action" org.

**[OpenSourceMalware: StubMaker RubyGems Campaign](https://opensourcemalware.com/blog/stubmaker-rubygems-windows-infostealer)**
Documents variants of bundler, activesupport, i18n, and rake. The dataset includes the 14 names with identified targets; the report leaves the targets of `joxn` and `reaker` unclear.

**[ReversingLabs: Mining for Malicious Ruby Gems](https://www.reversinglabs.com/blog/mining-for-malicious-ruby-gems)**
Documents `atlas-client` targeting `atlas_client`, a delimiter substitution in RubyGems.

**[Socket: Go Decimal Library Typosquat](https://socket.dev/blog/popular-go-decimal-library-typosquat-dns-backdoor)**
Documents `github.com/shopsprint/decimal` targeting `github.com/shopspring/decimal` by replacing the last character of the owner name.

**[Socket: Go UUID Library Typosquats](https://socket.dev/blog/malicious-go-packages-impersonate-googles-uuid-library-and-exfiltrate-data)**
Documents `github.com/bpoorman/uuid` targeting `github.com/pborman/uuid`. The owner name combines a transposition with a repeated `o`.

**[Socket: Rust Logger Impersonation](https://socket.dev/blog/two-malicious-rust-crates-impersonate-popular-logger-to-steal-wallet-keys)**
Documents `faster_log` targeting `fast_log`. The dataset includes this name pair from the report.

**[Socket: npm SSH Backdoors](https://socket.dev/blog/malicious-npm-packages-inject-ssh-backdoors-via-typosquatted-libraries)**
Documents six pairs targeting babel-cli, chokidar, streamsearch, ssh2, npm-run-all, and node-pty. The dataset includes all six.

### Academic Research

**IntelliRadar (arxiv:2409.15049)**
[IntelliRadar: A Comprehensive Platform to Pinpoint Malicious Package Information from Cyber Intelligence](https://arxiv.org/abs/2409.15049)

Constructed database of 34,313 malicious npm and PyPI package names by analyzing social media, developer forums, and other unstructured sources. Found 7,542 packages not in OSV and 12,684 not in Snyk.

**Tschacher (2016)**
Early research on package manager typosquatting demonstrating infection of thousands of hosts within days.

**Duan et al. (2020) - MalOSS**
Analytical pipeline identifying 300+ malware instances across RubyGems, npm, and PyPI.

**Taylor et al. (2020) - SpellBound**
[SpellBound: Defending Against Package Typosquatting](https://arxiv.org/abs/2003.03471)

Detects typosquatting by analyzing lexical similarity and popularity metrics. Flags unknown packages with names similar to popular ones before installation. Achieved 0.5% false positive rate and discovered a high-profile npm typosquat that was subsequently removed.

## Tools

**[olsenbudanur/anti-typosquatting](https://github.com/olsenbudanur/anti-typosquatting)** - npm install wrapper that detects potential typosquats using Levenshtein distance against the top 10,000 packages.

**[Karneades/psyposquatter](https://github.com/Karneades/psyposquatter)** - PowerShell tool that generates name permutations and checks PSGallery for existing typosquats.

**[tatianahub/typoschecker](https://github.com/tatianahub/typoschecker)** - Python tool that scans requirements files for packages with names similar to popular PyPI packages.

**[Xapollon430/typosquating](https://github.com/Xapollon430/typosquating)** - npm typosquatting detector using Levenshtein distance against popular packages.

**[rustfoundation/typomania](https://github.com/rustfoundation/typomania)** - Rust library providing typosquatting detection primitives, adaptable to any package registry.

**[mt3443/typogard](https://github.com/mt3443/typogard)** - Client-side npm tool that checks packages and transitive dependencies against known typosquatting transformations.

**[rangertaha/urlinsane](https://github.com/rangertaha/urlinsane)** - Domain typosquatting tool with 24 generation algorithms and DNS/GeoIP/redirect checking. Written in Go.

## Related Projects

- [andrew/typosquatting](https://github.com/andrew/typosquatting) - Generate typosquat variations for package names
- [packages.ecosyste.ms](https://packages.ecosyste.ms) - Open source package metadata service

### packages.ecosyste.ms API

The package_names endpoint can help identify potential typosquats by searching for packages with similar prefixes or postfixes to popular package names.

```
GET /api/v1/registries/{registry}/package_names
```

**Parameters:**
- `prefix` - filter by package names starting with string (case insensitive)
- `postfix` - filter by package names ending with string (case insensitive)
- `page`, `per_page` - pagination
- `sort`, `order` - sorting

**Examples:**
```
# Find RubyGems packages ending in "ails" (potential "rails" typosquats)
https://packages.ecosyste.ms/api/v1/registries/rubygems.org/package_names?postfix=ails

# Find RubyGems packages starting with "rai" (potential "rails" typosquats)
https://packages.ecosyste.ms/api/v1/registries/rubygems.org/package_names?prefix=rai

# Find npm packages starting with "reac" (potential "react" typosquats)
https://packages.ecosyste.ms/api/v1/registries/npmjs.org/package_names?prefix=reac
```

Full API documentation: [packages.ecosyste.ms/docs](https://packages.ecosyste.ms/docs)

## Contributing

Additional name pairs from incidents, research, and detector tests are welcome. Include a source that identifies the target, and state when examples are synthetic. Use `other` when a pair combines edits that cannot be described by a single category.

Run `ruby test/dataset_test.rb` to check CSV structure, duplicate pairs, basic transformation labels, and summary counts. The tests require the `csv` and `test-unit` gems and do not access the network or install any package named in the dataset.

## License

CC0 1.0 Universal. See [LICENSE](LICENSE).
