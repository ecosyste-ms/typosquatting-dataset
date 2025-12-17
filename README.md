# Typosquatting Dataset

A curated dataset of known package typosquats from public security research. Maps malicious packages to their legitimate targets with ecosystem, classification, and source attribution.

Useful for testing [typosquatting detection tools](https://github.com/andrew/typosquatting) and integration into [ecosyste.ms/packages](https://github.com/ecosyste-ms/packages).

## Data Format

The `typosquats.csv` file contains:

| Field | Description |
|-------|-------------|
| malicious_package | The typosquatting package name |
| target_package | The legitimate package being squatted |
| ecosystem | Package ecosystem (pypi, npm, crates.io, go, github_actions, rubygems, maven, nuget) |
| registry | Registry URL |
| classification | Typosquatting technique used |
| source | Data source attribution |

## Classification Types

These classifications match the algorithms in [andrew/typosquatting](https://github.com/andrew/typosquatting#algorithms):

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
| other | Attack types not fitting other categories | -- |

## Summary

This curated dataset contains 143 typosquatting entries drawn from larger malicious package databases. The source repositories collectively document tens of thousands of malicious packages, but many lack clear target package mappings. This dataset focuses on confirmed typosquats where both the malicious package and its intended target are known.

**By ecosystem:** PyPI (95), npm (35), Go (8), GitHub Actions (4), crates.io (1)

**By classification:** replacement (28), omission (27), addition (24), transposition (22), repetition (11), other (9), delimiter (7), plural (6), homoglyph (4), word_order (2), vowel_swap (2), numeral (1)

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
Research demonstrating GitHub Actions organization typosquatting. Created fake organizations like "actons" (targeting "actions"), "circelci" (targeting "circleci"), and "aws-action" (targeting "aws-actions"). Found 158+ repositories referencing the malicious "action" org.

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

## Related Projects

- [andrew/typosquatting](https://github.com/andrew/typosquatting) - Generate typosquat variations for package names
- [ecosyste.ms/packages](https://github.com/ecosyste-ms/packages) - Open source package metadata service

## Contributing

Additional typosquatting examples with confirmed target packages are welcome. Please include source attribution.

## License

CC0 1.0 Universal. See [LICENSE](LICENSE).
